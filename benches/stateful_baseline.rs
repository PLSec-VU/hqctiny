use HQCLethe::auth::{AuthLevel, ServerPublicKey, shared_keypair};
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5};
use HQCLethe::stateful::auth::{MlKemClientAuth, MlKemServerAuth};
use HQCLethe::stateful::client::StatefulClient;
use HQCLethe::stateful::config::ServerConfig;
use HQCLethe::stateful::entropy::OsEntropy;
use HQCLethe::stateful::kem::{ENTROPY_BYTES, StatefulKem};
use HQCLethe::stateful::server::StatefulServer;
use HQCLethe::stateful::wire::{self, Message};
use HQCLethe::traits::EntropyProvider;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::net::SocketAddr;
use std::sync::Arc;

type Server<K> = StatefulServer<K, MlKemServerAuth<K>, OsEntropy>;
type Client<K> = StatefulClient<K, MlKemClientAuth<K>>;

const BENCH_ADDR: &str = "192.0.2.1:40000";

fn addr() -> SocketAddr {
    BENCH_ADDR.parse().unwrap()
}

fn new_server<K: StatefulKem + AuthLevel>() -> Server<K> {
    let auth = MlKemServerAuth::new(shared_keypair::<K>().secret.clone());
    StatefulServer::new(ServerConfig::default(), auth, OsEntropy, 0)
}

fn pinned_auth<K: AuthLevel>() -> MlKemClientAuth<K> {
    let key = ServerPublicKey::from_bytes(shared_keypair::<K>().public.as_bytes().to_vec());
    MlKemClientAuth::new(Arc::new(key.unwrap()))
}

fn issue_key_fragments<K: StatefulKem + AuthLevel>(
    server: &mut Server<K>,
    client: &mut Client<K>,
) -> Vec<Vec<u8>> {
    let mut reply = Vec::new();
    server.handle(addr(), client.hello(), 0, &mut |d: &[u8]| {
        reply = d.to_vec();
        true
    });
    client.on_server_hello(&reply).unwrap().to_vec()
}

fn bench_variant<K: StatefulKem + AuthLevel>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(format!("stateful/{name}"));
    let mut client = StatefulClient::<K, _>::new(pinned_auth::<K>(), &OsEntropy);
    let hello = client.hello().to_vec();

    group.bench_function("hello_to_cookie", |b| {
        let mut server = new_server::<K>();
        b.iter(|| server.handle(addr(), &hello, 0, &mut |_: &[u8]| true));
    });

    group.bench_function("first_fragment_allocates_entry", |b| {
        b.iter_batched(
            || {
                let mut server = new_server::<K>();
                let fragments = issue_key_fragments(&mut server, &mut client);
                (server, fragments)
            },
            |(mut server, fragments)| server.handle(addr(), &fragments[0], 0, &mut |_: &[u8]| true),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("duplicate_fragment", |b| {
        let mut server = new_server::<K>();
        let fragments = issue_key_fragments(&mut server, &mut client);
        server.handle(addr(), &fragments[0], 0, &mut |_: &[u8]| true);
        b.iter(|| server.handle(addr(), &fragments[0], 0, &mut |_: &[u8]| true));
    });

    group.bench_function("bad_cookie_fragment", |b| {
        let mut server = new_server::<K>();
        let mut forged = issue_key_fragments(&mut server, &mut client)[0].clone();
        forged[3] ^= 0xff;
        b.iter(|| server.handle(addr(), &forged, 0, &mut |_: &[u8]| true));
    });

    group.bench_function("full_key_upload_with_encaps", |b| {
        b.iter_batched(
            || {
                let mut server = new_server::<K>();
                let fragments = issue_key_fragments(&mut server, &mut client);
                (server, fragments)
            },
            |(mut server, fragments)| {
                for fragment in &fragments {
                    server.handle(addr(), fragment, 0, &mut |_: &[u8]| true);
                }
            },
            BatchSize::SmallInput,
        );
    });

    let mut seed = [0u8; ENTROPY_BYTES];
    OsEntropy.random_bytes(&mut seed);
    group.bench_function("hqc_encaps", |b| {
        b.iter(|| K::encaps(&seed, client.public_key()))
    });

    let secret_key = shared_keypair::<K>().secret.clone();
    let auth_request = vec![0x42u8; HQCLethe::auth::auth_ciphertext_bytes::<K>()];
    group.bench_function("mlkem_decaps", |b| {
        b.iter(|| secret_key.decapsulate(&auth_request))
    });

    group.bench_function("hqc_keygen", |b| b.iter(|| K::generate_keypair(&seed)));

    group.bench_function("in_process_session", |b| {
        b.iter_batched(
            || {
                StatefulClient::<K, _>::with_keypair(
                    pinned_auth::<K>(),
                    &OsEntropy,
                    client.public_key().to_vec(),
                    Vec::new(),
                )
            },
            |mut fresh| {
                let mut server = new_server::<K>();
                let fragments = issue_key_fragments(&mut server, &mut fresh);
                let mut replies = Vec::new();
                for fragment in &fragments {
                    server.handle(addr(), fragment, 0, &mut |d: &[u8]| {
                        replies.push(d.to_vec());
                        true
                    });
                }
                replies
                    .iter()
                    .filter(|d| matches!(wire::parse(d), Some(Message::CtFragment { .. })))
                    .count()
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn benches(c: &mut Criterion) {
    bench_variant::<Hqc1>(c, "hqc1");
    bench_variant::<Hqc3>(c, "hqc3");
    bench_variant::<Hqc5>(c, "hqc5");
}

criterion_group!(stateful, benches);
criterion_main!(stateful);
