use super::auth::{ClientAuth, ServerAuth};
use super::client::StatefulClient;
use super::kem::StatefulKem;
use super::server::StatefulServer;
use super::stats::{RESPONSES_ONLY_QUERY, STATS_QUERY, StatsBoard, StatsSnapshot};
use super::wire::MAX_DATAGRAM_BYTES;
use crate::sockets::{runs_on_calling_thread, worker_thread};
use crate::traits::EntropyProvider;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const RTO_MIN: Duration = Duration::from_millis(100);
pub const RTO_MAX: Duration = Duration::from_secs(2);
pub const RTO_FALLBACK: Duration = Duration::from_millis(500);
pub const RTT_RTO_MULTIPLIER: u32 = 3;
pub const RTO_BACKOFF: u32 = 2;
pub const MAX_RETRIES: u32 = 6;

const RECV_BUFFER_BYTES: usize = 4096;
const _: () = assert!(MAX_DATAGRAM_BYTES <= RECV_BUFFER_BYTES);
const SERVER_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 64;

#[derive(Debug)]
pub enum SessionError {
    Io(io::Error),
    Protocol(crate::error::Error),
    TimedOut(&'static str),
}

impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SessionError {}

pub struct ServeOptions<'a> {
    pub stats_probe: Option<StatsShard<'a>>,
}

/// The slot on a stats board that one server writes its snapshot to.
#[derive(Clone, Copy)]
pub struct StatsShard<'a> {
    pub board: &'a StatsBoard,
    pub index: usize,
}

struct StatsPublisher<'a> {
    shard: StatsShard<'a>,
    published_ms: Option<u64>,
}

impl StatsPublisher<'_> {
    fn publish(&mut self, snapshot: StatsSnapshot, now_ms: u64) {
        self.shard.board.publish(self.shard.index, snapshot);
        self.published_ms = Some(now_ms);
    }

    fn publish_once_per_ms<K, A, E>(&mut self, server: &StatefulServer<K, A, E>, now_ms: u64)
    where
        K: StatefulKem,
        A: ServerAuth,
        E: EntropyProvider,
    {
        if self.published_ms != Some(now_ms) {
            self.publish(server.snapshot(now_ms), now_ms);
        }
    }
}

pub fn serve<K, A, E>(
    socket: &UdpSocket,
    server: &mut StatefulServer<K, A, E>,
    stop: &AtomicBool,
    options: &ServeOptions<'_>,
    on_shared_secret: &mut dyn FnMut(SocketAddr, &[u8]),
) -> io::Result<()>
where
    K: StatefulKem,
    A: ServerAuth,
    E: EntropyProvider,
{
    socket.set_read_timeout(Some(SERVER_POLL_INTERVAL))?;
    let started = Instant::now();
    let mut buf = [0u8; RECV_BUFFER_BYTES];
    let mut consecutive_errors = 0u32;
    let mut publisher = options.stats_probe.map(|shard| StatsPublisher {
        shard,
        published_ms: None,
    });
    while !stop.load(Ordering::Relaxed) {
        let now_ms = started.elapsed().as_millis() as u64;
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(received) => {
                consecutive_errors = 0;
                received
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                server.tick(now_ms);
                if let Some(publisher) = &mut publisher {
                    publisher.publish_once_per_ms(server, now_ms);
                }
                continue;
            }
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                    return Err(e);
                }
                continue;
            }
        };
        let datagram = &buf[..len];
        if let Some(publisher) = &mut publisher
            && let Some(reply_to) = stats_probe_reply(datagram)
        {
            publisher.publish(server.snapshot(now_ms), now_ms);
            let _ = socket.send_to(&reply_to(&publisher.shard.board.total()), src);
            continue;
        }
        let mut send = |reply: &[u8]| socket.send_to(reply, src).is_ok();
        let completed = server.handle(src, datagram, now_ms, &mut send);
        if let Some(secret) = &completed {
            on_shared_secret(src, secret);
        }
        if let Some(publisher) = &mut publisher {
            match completed {
                Some(_) => publisher.publish(server.snapshot(now_ms), now_ms),
                None => publisher.publish_once_per_ms(server, now_ms),
            }
        }
    }
    Ok(())
}

fn stats_probe_reply(datagram: &[u8]) -> Option<fn(&StatsSnapshot) -> Vec<u8>> {
    if datagram == RESPONSES_ONLY_QUERY {
        Some(|snapshot| snapshot.stats.responses_sent.to_le_bytes().to_vec())
    } else if datagram == STATS_QUERY {
        Some(StatsSnapshot::to_probe_bytes)
    } else {
        None
    }
}

/// Serves each socket on its own thread with its own server. Use sockets
/// from `crate::sockets::bind_udp_workers`, so that all datagrams of one
/// client reach the same server. If one worker fails, all workers stop.
/// One worker without `worker_stack_kib` runs on the calling thread.
pub fn serve_workers<K, A, E>(
    sockets: Vec<UdpSocket>,
    servers: Vec<StatefulServer<K, A, E>>,
    worker_stack_kib: Option<NonZeroUsize>,
    stop: &AtomicBool,
    answer_stats_probe: bool,
    on_shared_secret: &(dyn Fn(SocketAddr, &[u8]) + Sync),
) -> io::Result<()>
where
    K: StatefulKem,
    A: ServerAuth + Send,
    E: EntropyProvider + Send,
{
    assert_eq!(sockets.len(), servers.len(), "one server per socket");
    let board = StatsBoard::new(servers.len());
    let run_worker = |index: usize, socket: UdpSocket, mut server: StatefulServer<K, A, E>| {
        let options = ServeOptions {
            stats_probe: answer_stats_probe.then_some(StatsShard {
                board: &board,
                index,
            }),
        };
        let result = serve(&socket, &mut server, stop, &options, &mut |src, secret| {
            on_shared_secret(src, secret)
        });
        if result.is_err() {
            stop.store(true, Ordering::Relaxed);
        }
        result
    };
    let mut workers = sockets.into_iter().zip(servers).enumerate();
    if runs_on_calling_thread(workers.len(), worker_stack_kib) {
        let (index, (socket, server)) = workers.next().expect("one worker");
        return run_worker(index, socket, server);
    }
    std::thread::scope(|scope| {
        let run_worker = &run_worker;
        let handles = workers
            .map(|(index, (socket, server))| {
                worker_thread(worker_stack_kib)
                    .spawn_scoped(scope, move || run_worker(index, socket, server))
            })
            .collect::<io::Result<Vec<_>>>()?;
        handles
            .into_iter()
            .map(|handle| handle.join().expect("server worker panicked"))
            .collect::<io::Result<Vec<()>>>()
            .map(drop)
    })
}

pub fn run_session<K, A>(
    socket: &UdpSocket,
    client: &mut StatefulClient<K, A>,
    mut on_phase: impl FnMut(&str),
) -> Result<Vec<u8>, SessionError>
where
    K: StatefulKem,
    A: ClientAuth,
{
    let mut recv_buf = [0u8; RECV_BUFFER_BYTES];

    let hello_rtt = exchange_hello(socket, client, &mut recv_buf, &mut on_phase)?;
    on_phase("hello_response_received");

    let base_rto = (hello_rtt * RTT_RTO_MULTIPLIER).clamp(RTO_MIN, RTO_MAX);
    let secret = collect_ciphertext(socket, client, &mut recv_buf, base_rto, &mut on_phase)?;
    on_phase("shared_secret_derived");
    Ok(secret)
}

fn exchange_hello<K: StatefulKem, A: ClientAuth>(
    socket: &UdpSocket,
    client: &mut StatefulClient<K, A>,
    recv_buf: &mut [u8],
    on_phase: &mut impl FnMut(&str),
) -> Result<Duration, SessionError> {
    let mut rto = RTO_FALLBACK;
    let mut reply_failed_to_open = false;
    for attempt in 0..=MAX_RETRIES {
        let sent_at = Instant::now();
        socket.send(client.hello())?;
        if attempt == 0 {
            on_phase("hello_sent");
        }
        let deadline = sent_at + rto;
        while let Some(len) = recv_until(socket, recv_buf, deadline)? {
            match client.on_server_hello(&recv_buf[..len]) {
                Ok(_) => return Ok(sent_at.elapsed()),
                Err(crate::error::Error::ServerAuthenticationFailed) => {
                    reply_failed_to_open = true;
                }
                Err(_) => {}
            }
        }
        rto = (rto * RTO_BACKOFF).min(RTO_MAX);
        eprintln!(
            "[retry] hello attempt={} rto={:.3}",
            attempt + 1,
            rto.as_secs_f64()
        );
    }
    if reply_failed_to_open {
        return Err(SessionError::Protocol(
            crate::error::Error::ServerAuthenticationFailed,
        ));
    }
    Err(SessionError::TimedOut("hello"))
}

fn send_key_fragments<K: StatefulKem, A: ClientAuth>(
    socket: &UdpSocket,
    client: &StatefulClient<K, A>,
) -> io::Result<()> {
    for fragment in client.key_fragments() {
        socket.send(fragment)?;
    }
    Ok(())
}

fn collect_ciphertext<K: StatefulKem, A: ClientAuth>(
    socket: &UdpSocket,
    client: &mut StatefulClient<K, A>,
    recv_buf: &mut [u8],
    base_rto: Duration,
    on_phase: &mut impl FnMut(&str),
) -> Result<Vec<u8>, SessionError> {
    send_key_fragments(socket, client)?;
    on_phase("key_fragments_sent");
    let mut rto = base_rto;
    let mut stalls = 0u32;
    loop {
        let deadline = Instant::now() + rto;
        match recv_until(socket, recv_buf, deadline)? {
            Some(len) => match client.on_ct_fragment(&recv_buf[..len]) {
                Ok(Some(secret)) => return Ok(secret),
                Ok(None) => {
                    rto = base_rto;
                    stalls = 0;
                }
                Err(
                    e @ (crate::error::Error::DecodingFailed
                    | crate::error::Error::ServerAuthenticationFailed),
                ) => return Err(SessionError::Protocol(e)),
                Err(_) => {}
            },
            None => {
                stalls += 1;
                if stalls > MAX_RETRIES {
                    return Err(SessionError::TimedOut("ciphertext"));
                }
                send_key_fragments(socket, client)?;
                rto = (rto * RTO_BACKOFF).min(RTO_MAX);
                eprintln!(
                    "[retry] ciphertext attempt={} rto={:.3}",
                    stalls,
                    rto.as_secs_f64()
                );
            }
        }
    }
}

fn recv_until(socket: &UdpSocket, buf: &mut [u8], deadline: Instant) -> io::Result<Option<usize>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(None);
    }
    socket.set_read_timeout(Some(remaining))?;
    match socket.recv(buf) {
        Ok(len) => Ok(Some(len)),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(None)
        }
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Ok(None),
        Err(e) => Err(e),
    }
}
