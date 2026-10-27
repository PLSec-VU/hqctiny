use HQCLethe::hqc::Hqc1;
use HQCLethe::sockets::bind_udp_workers;
use HQCLethe::stateful::auth::NoAuth;
use HQCLethe::stateful::client::StatefulClient;
use HQCLethe::stateful::config::{ServerConfig, TableConfig};
use HQCLethe::stateful::entropy::OsEntropy;
use HQCLethe::stateful::server::StatefulServer;
use HQCLethe::stateful::stats::{STATS_QUERY, StatsBoard, StatsSnapshot};
use HQCLethe::stateful::transport::{run_session, serve_workers};
use std::net::{SocketAddr, UdpSocket};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const WORKERS: NonZeroUsize = NonZeroUsize::new(4).unwrap();
const SESSIONS: u64 = 8;
const LOCALHOST_ANY_PORT: ([u8; 4], u16) = ([127, 0, 0, 1], 0);

fn probe_field(probe: &[u8], name: &str) -> u64 {
    let index = StatsSnapshot::FIELD_NAMES
        .iter()
        .position(|field| *field == name)
        .unwrap();
    u64::from_le_bytes(probe[index * 8..index * 8 + 8].try_into().unwrap())
}

fn query_stats(server_addr: SocketAddr) -> Vec<u8> {
    let socket = UdpSocket::bind(SocketAddr::from(LOCALHOST_ANY_PORT)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.send_to(STATS_QUERY, server_addr).unwrap();
    let mut buf = [0u8; 4096];
    let len = socket.recv(&mut buf).unwrap();
    buf[..len].to_vec()
}

#[test]
fn worker_sockets_share_one_port() {
    let sockets = bind_udp_workers(LOCALHOST_ANY_PORT.into(), WORKERS).unwrap();
    let ports: Vec<u16> = sockets
        .iter()
        .map(|s| s.local_addr().unwrap().port())
        .collect();
    assert_eq!(ports.len(), WORKERS.get());
    assert!(ports.iter().all(|port| *port == ports[0] && *port != 0));
}

#[test]
fn one_worker_socket_does_not_share_its_port() {
    let socket = bind_udp_workers(LOCALHOST_ANY_PORT.into(), NonZeroUsize::MIN)
        .unwrap()
        .remove(0);
    assert!(UdpSocket::bind(socket.local_addr().unwrap()).is_err());
}

#[test]
fn shard_tables_split_the_budget() {
    let whole = TableConfig::default();
    let shard = whole.shard(4);
    assert_eq!(shard.max_entries, whole.max_entries / 4);
    assert_eq!(shard.max_bytes, whole.max_bytes / 4);
    assert_eq!(shard.max_entries_per_source, whole.max_entries_per_source);
    assert_eq!(whole.shard(whole.max_entries * 2).max_entries, 1);
}

#[test]
fn stats_board_sums_shards() {
    let board = StatsBoard::new(2);
    let mut first = StatsSnapshot::default();
    first.stats.hellos_answered = 3;
    first.oldest_entry_age_ms = 50;
    let mut second = StatsSnapshot::default();
    second.stats.hellos_answered = 4;
    second.oldest_entry_age_ms = 20;
    board.publish(0, first);
    board.publish(1, second);
    let total = board.total();
    assert_eq!(total.stats.hellos_answered, 7);
    assert_eq!(total.oldest_entry_age_ms, 50);
}

#[test]
fn sessions_complete_across_workers_and_probe_reports_totals() {
    let sockets = bind_udp_workers(LOCALHOST_ANY_PORT.into(), WORKERS).unwrap();
    let server_addr = sockets[0].local_addr().unwrap();
    let config = ServerConfig {
        table: TableConfig::default().shard(WORKERS.get()),
        ..ServerConfig::default()
    };
    let servers = (0..WORKERS.get())
        .map(|_| StatefulServer::<Hqc1, _, _>::new(config.clone(), NoAuth, OsEntropy, 0))
        .collect();
    let stop = AtomicBool::new(false);
    let server_secrets = Mutex::new(Vec::new());
    let report =
        |_: SocketAddr, secret: &[u8]| server_secrets.lock().unwrap().push(secret.to_vec());

    std::thread::scope(|scope| {
        let serving = scope.spawn(|| serve_workers(sockets, servers, None, &stop, true, &report));

        let client_secrets: Vec<Vec<u8>> = (0..SESSIONS)
            .map(|_| {
                let socket = UdpSocket::bind(SocketAddr::from(LOCALHOST_ANY_PORT)).unwrap();
                socket.connect(server_addr).unwrap();
                let mut client = StatefulClient::<Hqc1, _>::new(NoAuth, &OsEntropy);
                run_session(&socket, &mut client, |_| {}).unwrap()
            })
            .collect();
        let probe = query_stats(server_addr);

        stop.store(true, Ordering::Relaxed);
        serving.join().unwrap().unwrap();

        let server_secrets = server_secrets.lock().unwrap();
        assert!(client_secrets.iter().all(|s| server_secrets.contains(s)));
        assert_eq!(probe_field(&probe, "hellos_answered"), SESSIONS);
        assert_eq!(probe_field(&probe, "encaps_completed"), SESSIONS);
    });
}
