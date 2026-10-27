use HQCLethe::envelope::SessionKeys;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::stateful::auth::NoAuth;
use HQCLethe::stateful::client::StatefulClient;
use HQCLethe::stateful::config::{ServerConfig, TableConfig};
use HQCLethe::stateful::cookie::{COOKIE_BYTES, Cookie};
use HQCLethe::stateful::entropy::OsEntropy;
use HQCLethe::stateful::kem::StatefulKem;
use HQCLethe::stateful::server::StatefulServer;
use HQCLethe::stateful::table::ENTRY_OVERHEAD_BYTES;
use HQCLethe::stateful::transport::{ServeOptions, run_session, serve};
use HQCLethe::stateful::wire::{self, KEY_FRAGMENT_PAYLOAD_BYTES, MAX_DATAGRAM_BYTES, Message};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

type Server<K> = StatefulServer<K, NoAuth, OsEntropy>;

const IDLE_FOREVER_MS: u64 = 3_600_000;

fn addr(ip_last: u8, port: u16) -> SocketAddr {
    format!("192.0.2.{ip_last}:{port}").parse().unwrap()
}

fn server_with<K: StatefulKem>(table: TableConfig) -> Server<K> {
    let config = ServerConfig {
        table,
        ..ServerConfig::default()
    };
    StatefulServer::new(config, NoAuth, OsEntropy, 0)
}

fn default_server<K: StatefulKem>() -> Server<K> {
    server_with(TableConfig::default())
}

struct Reply {
    datagrams: Vec<Vec<u8>>,
    secret: Option<Vec<u8>>,
}

fn deliver<K: StatefulKem>(
    server: &mut Server<K>,
    src: SocketAddr,
    datagram: &[u8],
    now_ms: u64,
) -> Reply {
    let mut datagrams = Vec::new();
    let secret = server.handle(src, datagram, now_ms, &mut |d: &[u8]| {
        datagrams.push(d.to_vec());
        true
    });
    Reply { datagrams, secret }
}

fn no_auth_keys() -> SessionKeys {
    SessionKeys::derive(&Zeroizing::new([0u8; 32]))
}

fn dummy_public_key<K: StatefulKem>() -> Vec<u8> {
    vec![0x5a; K::PUBLIC_KEY_BYTES]
}

fn dummy_client<K: StatefulKem>() -> StatefulClient<K, NoAuth> {
    StatefulClient::with_keypair(NoAuth, &OsEntropy, dummy_public_key::<K>(), Vec::new())
}

fn cookie_for<K: StatefulKem>(server: &mut Server<K>, src: SocketAddr, now_ms: u64) -> Cookie {
    let client = dummy_client::<K>();
    let reply = deliver(server, src, client.hello(), now_ms);
    let Some(Message::ServerHello {
        nonce,
        sealed_cookie,
    }) = wire::parse(&reply.datagrams[0])
    else {
        panic!("expected ServerHello");
    };
    wire::open_server_hello(
        &no_auth_keys().server_to_client,
        &nonce,
        client.hello(),
        sealed_cookie,
    )
    .unwrap()
}

fn key_fragments_for<K: StatefulKem>(
    server: &mut Server<K>,
    src: SocketAddr,
    now_ms: u64,
) -> Vec<Vec<u8>> {
    let mut client = dummy_client::<K>();
    let reply = deliver(server, src, client.hello(), now_ms);
    client
        .on_server_hello(&reply.datagrams[0])
        .unwrap()
        .to_vec()
}

fn open_partial_entry<K: StatefulKem>(server: &mut Server<K>, src: SocketAddr, now_ms: u64) {
    let fragments = key_fragments_for(server, src, now_ms);
    deliver(server, src, &fragments[0], now_ms);
}

fn sans_io_session<K: StatefulKem>() {
    let mut server = default_server::<K>();
    let mut client = StatefulClient::<K, _>::new(NoAuth, &OsEntropy);
    let src = addr(1, 5000);

    let hello_reply = deliver(&mut server, src, client.hello(), 0);
    assert_eq!(hello_reply.datagrams.len(), 1);
    assert!(server.table().is_empty());

    let fragments = client
        .on_server_hello(&hello_reply.datagrams[0])
        .unwrap()
        .to_vec();
    assert!(fragments.iter().all(|f| f.len() <= MAX_DATAGRAM_BYTES));
    assert!(fragments.len() >= 2);

    let mut server_secret = None;
    let mut ct_datagrams = Vec::new();
    for fragment in &fragments {
        let reply = deliver(&mut server, src, fragment, 1);
        ct_datagrams.extend(reply.datagrams);
        server_secret = server_secret.or(reply.secret);
    }
    assert!(server.table().is_empty());
    assert!(ct_datagrams.iter().all(|d| d.len() <= MAX_DATAGRAM_BYTES));

    let mut client_secret = None;
    for datagram in ct_datagrams.iter().rev() {
        client_secret = client_secret.or(client.on_ct_fragment(datagram).unwrap());
    }
    assert_eq!(client_secret.unwrap(), server_secret.unwrap());
}

#[test]
fn sans_io_agreement_hqc1() {
    sans_io_session::<Hqc1>();
}

#[test]
fn sans_io_agreement_hqc3() {
    sans_io_session::<Hqc3>();
}

#[test]
fn sans_io_agreement_hqc5() {
    sans_io_session::<Hqc5>();
}

fn udp_session<K: StatefulKem + 'static>() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = socket.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let secrets = Arc::new(Mutex::new(Vec::new()));
    let handle = {
        let (stop, secrets) = (stop.clone(), secrets.clone());
        std::thread::spawn(move || {
            let mut server = default_server::<K>();
            let options = ServeOptions { stats_probe: None };
            serve(&socket, &mut server, &stop, &options, &mut |_, secret| {
                secrets.lock().unwrap().push(secret.to_vec());
            })
            .unwrap();
        })
    };

    let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_socket.connect(server_addr).unwrap();
    let mut client = StatefulClient::<K, _>::new(NoAuth, &OsEntropy);
    let client_secret = run_session(&client_socket, &mut client, |_| {}).unwrap();

    stop.store(true, Ordering::Relaxed);
    handle.join().unwrap();
    assert!(secrets.lock().unwrap().contains(&client_secret));
}

#[test]
fn udp_agreement_hqc1() {
    udp_session::<Hqc1>();
}

#[test]
fn udp_agreement_hqc3() {
    udp_session::<Hqc3>();
}

#[test]
fn udp_agreement_hqc5() {
    udp_session::<Hqc5>();
}

#[test]
fn fragment_counts_match_key_and_ciphertext_sizes() {
    assert_eq!(wire::key_fragment_count(Hqc1::PUBLIC_KEY_BYTES), 2);
    assert_eq!(wire::key_fragment_count(Hqc3::PUBLIC_KEY_BYTES), 4);
    assert_eq!(wire::key_fragment_count(Hqc5::PUBLIC_KEY_BYTES), 7);
}

#[test]
fn hello_allocates_nothing() {
    let mut server = default_server::<Hqc1>();
    for port in 0..100 {
        cookie_for(&mut server, addr(1, 1000 + port), 0);
    }
    assert!(server.table().is_empty());
    assert_eq!(server.snapshot(0).stats.hellos_answered, 100);
}

#[test]
fn forged_cookie_allocates_nothing() {
    let mut server = default_server::<Hqc1>();
    let mut fragments = key_fragments_for(&mut server, addr(1, 1), 0);
    fragments[0][5] ^= 0xff;
    deliver(&mut server, addr(1, 1), &fragments[0], 0);
    assert!(server.table().is_empty());
    assert_eq!(server.snapshot(0).stats.rejected_cookie, 1);
}

#[test]
fn cookie_is_bound_to_source_address() {
    let mut server = default_server::<Hqc1>();
    let fragments = key_fragments_for(&mut server, addr(1, 1), 0);
    deliver(&mut server, addr(1, 2), &fragments[0], 0);
    deliver(&mut server, addr(2, 1), &fragments[0], 0);
    assert!(server.table().is_empty());
    assert_eq!(server.snapshot(0).stats.rejected_cookie, 2);
}

#[test]
fn expired_cookie_allocates_nothing() {
    let mut server = default_server::<Hqc1>();
    let fragments = key_fragments_for(&mut server, addr(1, 1), 0);
    let lifetime = ServerConfig::default().cookie_lifetime_ms;
    deliver(&mut server, addr(1, 1), &fragments[0], lifetime + 2_000);
    assert!(server.table().is_empty());
}

#[test]
fn cookie_survives_one_key_rotation_but_not_two() {
    let rotation = ServerConfig::default().key_rotation_ms;
    let long_lived = || ServerConfig {
        cookie_lifetime_ms: 10 * rotation,
        ..ServerConfig::default()
    };

    let mut one = Server::<Hqc1>::new(long_lived(), NoAuth, OsEntropy, 0);
    let fragments = key_fragments_for(&mut one, addr(1, 1), 0);
    deliver(&mut one, addr(1, 1), &fragments[0], rotation);
    assert_eq!(one.table().len(), 1);

    let mut two = Server::<Hqc1>::new(long_lived(), NoAuth, OsEntropy, 0);
    let fragments = key_fragments_for(&mut two, addr(1, 1), 0);
    deliver(&mut two, addr(1, 1), &fragments[0], 2 * rotation);
    assert!(two.table().is_empty());
}

#[test]
fn malformed_fragments_allocate_nothing() {
    let mut server = default_server::<Hqc1>();
    let cookie = cookie_for(&mut server, addr(1, 1), 0);
    let session = no_auth_keys().client_to_server;
    let key = dummy_public_key::<Hqc1>();
    let good = wire::encode_key_fragment(&session, Hqc1::LEVEL_ID, &cookie, 0, &key);
    let wrong_level = wire::encode_key_fragment(
        &session,
        Hqc3::LEVEL_ID,
        &cookie,
        0,
        &dummy_public_key::<Hqc3>(),
    );
    let mut wrong_index = good.clone();
    wrong_index[2 + COOKIE_BYTES] = 9;
    let mut wrong_count = good.clone();
    wrong_count[4 + COOKIE_BYTES] = 99;
    let truncated = good[..good.len() - 1].to_vec();
    for bad in [
        wrong_level,
        wrong_index,
        wrong_count,
        truncated,
        vec![0x03],
        vec![],
    ] {
        deliver(&mut server, addr(1, 1), &bad, 0);
    }
    assert!(server.table().is_empty());
    assert_eq!(server.snapshot(0).stats.rejected_malformed, 6);
}

#[test]
fn partial_upload_holds_one_buffer_until_idle_timeout() {
    let table = TableConfig::default();
    let idle = table.idle_timeout_ms;
    let mut server = server_with::<Hqc1>(table);
    open_partial_entry(&mut server, addr(1, 1), 0);
    assert_eq!(server.table().len(), 1);
    assert!(server.table().accounted_bytes() >= Hqc1::PUBLIC_KEY_BYTES);

    server.tick(idle + 500);
    assert!(server.table().is_empty());
    assert_eq!(server.snapshot(0).timeouts, 1);
}

#[test]
fn duplicate_fragments_do_not_extend_idle_timer() {
    let table = TableConfig::default();
    let idle = table.idle_timeout_ms;
    let mut server = server_with::<Hqc1>(table);
    let fragments = key_fragments_for(&mut server, addr(1, 1), 0);
    deliver(&mut server, addr(1, 1), &fragments[0], 0);
    for now in (500..=idle).step_by(500) {
        deliver(&mut server, addr(1, 1), &fragments[0], now);
    }
    assert!(server.snapshot(0).stats.fragments_duplicate > 0);
    server.tick(idle + 1_000);
    assert!(server.table().is_empty());
}

#[test]
fn a_new_fragment_extends_idle_timer_until_the_absolute_lifetime() {
    let table = TableConfig {
        idle_timeout_ms: 3_000,
        max_lifetime_ms: 8_000,
        sweep_interval_ms: 1,
        ..TableConfig::default()
    };
    let mut server = server_with::<Hqc5>(table);
    let fragments = key_fragments_for(&mut server, addr(1, 1), 0);
    deliver(&mut server, addr(1, 1), &fragments[0], 0);
    deliver(&mut server, addr(1, 1), &fragments[1], 2_500);
    deliver(&mut server, addr(1, 1), &fragments[2], 5_000);
    server.tick(7_000);
    assert_eq!(server.table().len(), 1);
    server.tick(8_500);
    assert!(server.table().is_empty());
}

#[test]
fn per_source_limit_caps_entries_for_one_address() {
    let table = TableConfig {
        max_entries_per_source: 3,
        ..TableConfig::default()
    };
    let mut server = server_with::<Hqc1>(table);
    for port in 0..10 {
        open_partial_entry(&mut server, addr(1, 2000 + port), 0);
    }
    assert_eq!(server.table().len(), 3);
    assert_eq!(server.snapshot(0).stats.dropped_source_limit, 7);
    open_partial_entry(&mut server, addr(2, 1), 0);
    assert_eq!(server.table().len(), 4);
}

#[test]
fn entry_cap_drops_new_entries_when_all_are_young() {
    let table = TableConfig {
        max_entries: 5,
        max_entries_per_source: 100,
        ..TableConfig::default()
    };
    let mut server = server_with::<Hqc1>(table);
    for host in 0..20u8 {
        open_partial_entry(&mut server, addr(host, 1), 0);
    }
    assert_eq!(server.table().len(), 5);
    assert_eq!(server.snapshot(0).stats.dropped_table_full, 15);
    assert_eq!(server.snapshot(0).evictions, 0);
}

#[test]
fn byte_cap_bounds_accounted_memory() {
    let per_entry = Hqc1::PUBLIC_KEY_BYTES + ENTRY_OVERHEAD_BYTES;
    let cap = 3 * per_entry + 10;
    let table = TableConfig {
        max_bytes: cap,
        max_entries_per_source: 100,
        ..TableConfig::default()
    };
    let mut server = server_with::<Hqc1>(table);
    for host in 0..10u8 {
        open_partial_entry(&mut server, addr(host, 1), 0);
    }
    assert_eq!(server.table().len(), 3);
    assert!(server.table().accounted_bytes() <= cap);
}

#[test]
fn eviction_replaces_oldest_entry_once_it_is_old_enough() {
    let table = TableConfig {
        max_entries: 2,
        max_entries_per_source: 100,
        evict_min_age_ms: 1_000,
        idle_timeout_ms: IDLE_FOREVER_MS,
        max_lifetime_ms: IDLE_FOREVER_MS,
        ..TableConfig::default()
    };
    let mut server = server_with::<Hqc1>(table);
    let frags: Vec<_> = (1..=3u8)
        .map(|host| key_fragments_for(&mut server, addr(host, 1), 0))
        .collect();
    deliver(&mut server, addr(1, 1), &frags[0][0], 0);
    deliver(&mut server, addr(2, 1), &frags[1][0], 500);

    deliver(&mut server, addr(3, 1), &frags[2][0], 900);
    assert_eq!(server.snapshot(0).stats.dropped_table_full, 1);
    assert_eq!(server.snapshot(0).evictions, 0);

    deliver(&mut server, addr(3, 1), &frags[2][0], 1_100);
    assert_eq!(server.snapshot(0).evictions, 1);
    assert_eq!(server.table().len(), 2);
    assert_eq!(server.table().entries_for_source(&addr(1, 1)), 0);
    assert_eq!(server.table().entries_for_source(&addr(3, 1)), 1);
}

#[test]
fn evicted_client_finishes_by_resending_its_key() {
    let table = TableConfig {
        max_entries: 1,
        evict_min_age_ms: 100,
        ..TableConfig::default()
    };
    let mut server = server_with::<Hqc1>(table);
    let mut victim = StatefulClient::<Hqc1, _>::new(NoAuth, &OsEntropy);
    let victim_addr = addr(1, 1);
    let hello = deliver(&mut server, victim_addr, victim.hello(), 0);
    let victim_fragments = victim
        .on_server_hello(&hello.datagrams[0])
        .unwrap()
        .to_vec();
    deliver(&mut server, victim_addr, &victim_fragments[0], 0);

    open_partial_entry(&mut server, addr(2, 1), 200);
    assert_eq!(server.snapshot(0).evictions, 1);
    assert_eq!(server.table().entries_for_source(&victim_addr), 0);

    let mut secret = None;
    for fragment in &victim_fragments {
        secret = secret.or(deliver(&mut server, victim_addr, fragment, 1_000).secret);
    }
    assert!(secret.is_some());
}

#[test]
fn ipv6_sources_share_a_slash_64_limit() {
    let table = TableConfig {
        max_entries_per_source: 2,
        ..TableConfig::default()
    };
    let mut server = server_with::<Hqc1>(table);
    for host in 0..5u16 {
        let src: SocketAddr = format!("[2001:db8:0:1::{:x}]:4000", host + 1)
            .parse()
            .unwrap();
        let fragments = key_fragments_for(&mut server, src, 0);
        deliver(&mut server, src, &fragments[0], 0);
    }
    assert_eq!(server.table().len(), 2);
}

#[test]
fn replayed_first_fragment_after_completion_opens_a_new_entry_that_times_out() {
    let mut server = default_server::<Hqc1>();
    let fragments = key_fragments_for(&mut server, addr(1, 1), 0);
    for fragment in &fragments {
        deliver(&mut server, addr(1, 1), fragment, 1);
    }
    assert!(server.table().is_empty());
    let replay = deliver(&mut server, addr(1, 1), &fragments[0], 2);
    assert!(replay.secret.is_none());
    assert_eq!(server.table().len(), 1);
    server.tick(IDLE_FOREVER_MS);
    assert!(server.table().is_empty());
}

#[test]
fn client_rejects_foreign_hello_nonce_and_recovers_from_ciphertext_loss() {
    let mut server = default_server::<Hqc1>();
    let mut client = StatefulClient::<Hqc1, _>::new(NoAuth, &OsEntropy);
    let other = StatefulClient::<Hqc1, _>::new(NoAuth, &OsEntropy);
    let src = addr(1, 1);
    let foreign = deliver(&mut server, src, other.hello(), 0);
    assert!(client.on_server_hello(&foreign.datagrams[0]).is_err());

    let hello = deliver(&mut server, src, client.hello(), 0);
    let fragments = client
        .on_server_hello(&hello.datagrams[0])
        .unwrap()
        .to_vec();
    let mut first_round = Vec::new();
    for fragment in &fragments {
        first_round.extend(deliver(&mut server, src, fragment, 1).datagrams);
    }
    for datagram in first_round.iter().skip(1) {
        assert!(client.on_ct_fragment(datagram).unwrap().is_none());
    }

    let mut second_round = Vec::new();
    for fragment in &fragments {
        second_round.extend(deliver(&mut server, src, fragment, 2).datagrams);
    }
    let mut secret = None;
    for datagram in &second_round {
        secret = secret.or(client.on_ct_fragment(datagram).unwrap());
    }
    assert!(secret.is_some());
}

#[test]
fn stats_probe_bytes_start_with_responses_sent() {
    let mut server = default_server::<Hqc1>();
    cookie_for(&mut server, addr(1, 1), 0);
    let bytes = server.snapshot(0).to_probe_bytes();
    assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()), 1);
}

#[test]
fn fragments_fill_the_datagram_limit_exactly() {
    let cookie = [0u8; COOKIE_BYTES];
    let session = no_auth_keys().client_to_server;
    let full = wire::encode_key_fragment(
        &session,
        Hqc5::LEVEL_ID,
        &cookie,
        0,
        &dummy_public_key::<Hqc5>(),
    );
    assert_eq!(full.len(), MAX_DATAGRAM_BYTES);
    assert_eq!(
        full.len(),
        KEY_FRAGMENT_PAYLOAD_BYTES + wire::KEY_FRAGMENT_OVERHEAD_BYTES
    );
}

#[test]
fn a_flipped_fragment_bit_is_rejected_and_allocates_nothing() {
    let mut server = default_server::<Hqc1>();
    let fragment = key_fragments_for(&mut server, addr(1, 1), 0).remove(0);
    for bit in 0..fragment.len() * 8 {
        let mut corrupted = fragment.clone();
        corrupted[bit / 8] ^= 1 << (bit % 8);
        let reply = deliver(&mut server, addr(1, 1), &corrupted, 0);
        assert!(reply.secret.is_none());
        assert!(server.table().is_empty(), "bit {bit} reached the table");
    }
    let stats = server.snapshot(0).stats;
    assert!(stats.rejected_ae > 0);
    assert_eq!(stats.fragments_accepted, 0);
}
