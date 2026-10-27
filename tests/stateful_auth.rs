use HQCLethe::auth::{
    AuthLevel, AuthSecret, ServerKeypair, ServerPublicKey, ServerSecretKey, shared_keypair,
};
use HQCLethe::error::Error;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5};
use HQCLethe::stateful::auth::{MlKemClientAuth, MlKemServerAuth, ServerAuth, ServerProof};
use HQCLethe::stateful::client::StatefulClient;
use HQCLethe::stateful::config::ServerConfig;
use HQCLethe::stateful::entropy::OsEntropy;
use HQCLethe::stateful::kem::StatefulKem;
use HQCLethe::stateful::server::StatefulServer;
use HQCLethe::stateful::wire::MAX_DATAGRAM_BYTES;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAuth<A> {
    inner: A,
    proofs: Arc<AtomicUsize>,
}

impl<A: ServerAuth> ServerAuth for CountingAuth<A> {
    fn request_bytes(&self) -> usize {
        self.inner.request_bytes()
    }

    fn tag_bytes(&self) -> usize {
        self.inner.tag_bytes()
    }

    fn accept(&self, request: &[u8]) -> Option<AuthSecret> {
        self.proofs.fetch_add(1, Ordering::SeqCst);
        self.inner.accept(request)
    }

    fn prove(&self, k_auth: &AuthSecret, transcript: &[u8], hqc_secret: &[u8]) -> ServerProof {
        self.inner.prove(k_auth, transcript, hqc_secret)
    }
}

type Server<K> = StatefulServer<K, CountingAuth<MlKemServerAuth<K>>, OsEntropy>;
type Client<K> = StatefulClient<K, MlKemClientAuth<K>>;

const NOW_MS: u64 = 0;
const HELLO_BURST: usize = 20;

fn src(ip_last: u8) -> SocketAddr {
    format!("192.0.2.{ip_last}:5000").parse().unwrap()
}

fn secret_key<K: AuthLevel>() -> ServerSecretKey<K> {
    shared_keypair::<K>().secret.clone()
}

fn pinned<K: AuthLevel>(keys: &ServerKeypair<K>) -> Arc<ServerPublicKey<K>> {
    Arc::new(ServerPublicKey::from_bytes(keys.public.as_bytes().to_vec()).unwrap())
}

fn server<K: StatefulKem + AuthLevel>() -> (Server<K>, Arc<AtomicUsize>) {
    let proofs = Arc::new(AtomicUsize::new(0));
    let auth = CountingAuth {
        inner: MlKemServerAuth::new(secret_key::<K>()),
        proofs: proofs.clone(),
    };
    (
        StatefulServer::new(ServerConfig::default(), auth, OsEntropy, NOW_MS),
        proofs,
    )
}

fn client_pinned_to<K: StatefulKem + AuthLevel>(keys: &ServerKeypair<K>) -> Client<K> {
    StatefulClient::new(MlKemClientAuth::new(pinned(keys)), &OsEntropy)
}

fn honest_client<K: StatefulKem + AuthLevel>() -> Client<K> {
    client_pinned_to(shared_keypair::<K>())
}

fn deliver<K: StatefulKem + AuthLevel>(
    server: &mut Server<K>,
    from: SocketAddr,
    datagram: &[u8],
) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
    let mut sent = Vec::new();
    let secret = server.handle(from, datagram, NOW_MS, &mut |d: &[u8]| {
        sent.push(d.to_vec());
        true
    });
    (sent, secret)
}

fn upload_fragments<K: StatefulKem + AuthLevel>(
    server: &mut Server<K>,
    client: &mut Client<K>,
    from: SocketAddr,
) -> Vec<Vec<u8>> {
    let (reply, _) = deliver(server, from, client.hello());
    client.on_server_hello(&reply[0]).unwrap().to_vec()
}

struct Exchange {
    ciphertext_datagrams: Vec<Vec<u8>>,
    server_secret: Option<Vec<u8>>,
}

fn run_upload<K: StatefulKem + AuthLevel>(
    server: &mut Server<K>,
    fragments: &[Vec<u8>],
    from: SocketAddr,
) -> Exchange {
    let mut exchange = Exchange {
        ciphertext_datagrams: Vec::new(),
        server_secret: None,
    };
    for fragment in fragments {
        let (sent, secret) = deliver(server, from, fragment);
        exchange.ciphertext_datagrams.extend(sent);
        exchange.server_secret = exchange.server_secret.take().or(secret);
    }
    exchange
}

fn feed<K: StatefulKem>(
    client: &mut StatefulClient<K, MlKemClientAuth<K>>,
    datagrams: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, Error> {
    let mut secret = None;
    for datagram in datagrams {
        secret = secret.or(client.on_ct_fragment(datagram)?);
    }
    Ok(secret)
}

fn agreement<K: StatefulKem + AuthLevel>() {
    let (mut server, proofs) = server::<K>();
    let mut client = honest_client::<K>();
    let fragments = upload_fragments(&mut server, &mut client, src(1));
    assert!(fragments.iter().all(|f| f.len() <= MAX_DATAGRAM_BYTES));
    let exchange = run_upload(&mut server, &fragments, src(1));
    assert!(
        exchange
            .ciphertext_datagrams
            .iter()
            .all(|d| d.len() <= MAX_DATAGRAM_BYTES)
    );
    let client_secret = feed(&mut client, &exchange.ciphertext_datagrams)
        .unwrap()
        .unwrap();
    assert_eq!(client_secret, exchange.server_secret.unwrap());
    assert_eq!(proofs.load(Ordering::SeqCst), 1);
    assert!(server.table().is_empty());
}

#[test]
fn mlkem_agreement_hqc1() {
    agreement::<Hqc1>();
}

#[test]
fn mlkem_agreement_hqc3() {
    agreement::<Hqc3>();
}

#[test]
fn mlkem_agreement_hqc5() {
    agreement::<Hqc5>();
}

#[test]
fn client_rejects_a_server_that_holds_a_different_key() {
    let imposter = ServerKeypair::<Hqc1>::generate();
    let (mut server, _) = server::<Hqc1>();
    let mut client = client_pinned_to(&imposter);
    let (reply, _) = deliver(&mut server, src(1), client.hello());
    assert_eq!(
        client.on_server_hello(&reply[0]).err(),
        Some(Error::ServerAuthenticationFailed)
    );
}

#[test]
fn client_rejects_every_flipped_bit_of_every_reply_datagram() {
    let (mut server, _) = server::<Hqc1>();
    let mut client = honest_client::<Hqc1>();
    let fragments = upload_fragments(&mut server, &mut client, src(1));
    let datagrams = run_upload(&mut server, &fragments, src(1)).ciphertext_datagrams;
    for datagram in &datagrams {
        for bit in 0..datagram.len() * 8 {
            let mut corrupted = datagram.clone();
            corrupted[bit / 8] ^= 1 << (bit % 8);
            assert!(
                !matches!(client.on_ct_fragment(&corrupted), Ok(Some(_))),
                "bit {bit} accepted"
            );
        }
    }
    assert!(feed(&mut client, &datagrams).unwrap().is_some());
}

#[test]
fn client_rejects_a_server_hello_for_another_hello() {
    let (mut server, _) = server::<Hqc1>();
    let mut client = honest_client::<Hqc1>();
    let other = honest_client::<Hqc1>();
    let (reply, _) = deliver(&mut server, src(1), other.hello());
    assert!(client.on_server_hello(&reply[0]).is_err());
}

#[test]
fn server_rejects_every_flipped_bit_of_a_key_fragment() {
    let (mut server, _) = server::<Hqc1>();
    let mut client = honest_client::<Hqc1>();
    let fragment = upload_fragments(&mut server, &mut client, src(1)).remove(0);
    for bit in 0..fragment.len() * 8 {
        let mut corrupted = fragment.clone();
        corrupted[bit / 8] ^= 1 << (bit % 8);
        deliver(&mut server, src(1), &corrupted);
        assert!(server.table().is_empty(), "bit {bit} reached the table");
    }
}

#[test]
fn a_reply_recorded_for_one_client_fails_for_another() {
    let (mut server, _) = server::<Hqc1>();
    let mut victim = honest_client::<Hqc1>();
    let mut other = honest_client::<Hqc1>();
    let fragments = upload_fragments(&mut server, &mut victim, src(1));
    let recorded = run_upload(&mut server, &fragments, src(1)).ciphertext_datagrams;
    assert!(feed(&mut other, &recorded).is_err());
}

#[test]
fn each_hello_costs_one_decapsulation_and_fragments_cost_none() {
    let (mut server, proofs) = server::<Hqc1>();
    let hello = honest_client::<Hqc1>().hello().to_vec();
    for _ in 0..HELLO_BURST {
        deliver(&mut server, src(1), &hello);
    }
    assert_eq!(proofs.load(Ordering::SeqCst), HELLO_BURST);

    let mut client = honest_client::<Hqc1>();
    let fragments = upload_fragments(&mut server, &mut client, src(1));
    let after_hello = proofs.load(Ordering::SeqCst);

    let mut forged = fragments.clone();
    for fragment in &mut forged {
        fragment[5] ^= 0xff;
    }
    run_upload(&mut server, &forged, src(1));
    run_upload(&mut server, &fragments, src(2));
    assert_eq!(proofs.load(Ordering::SeqCst), after_hello);
    assert!(server.table().is_empty());
}

#[test]
fn encapsulation_waits_for_the_complete_upload() {
    let (mut server, _) = server::<Hqc1>();
    let mut client = honest_client::<Hqc1>();
    let fragments = upload_fragments(&mut server, &mut client, src(1));
    let (all_but_last, last) = fragments.split_at(fragments.len() - 1);

    run_upload(&mut server, all_but_last, src(1));
    assert_eq!(server.snapshot(NOW_MS).stats.encaps_completed, 0);
    assert_eq!(server.table().len(), 1);

    run_upload(&mut server, last, src(1));
    assert_eq!(server.snapshot(NOW_MS).stats.encaps_completed, 1);
    assert!(server.table().is_empty());
}

#[test]
fn a_random_auth_request_costs_one_decapsulation_and_yields_no_session() {
    use HQCLethe::stateful::auth::RandomRequestAuth;
    let (mut server, proofs) = server::<Hqc1>();
    let auth_bytes = HQCLethe::auth::auth_ciphertext_bytes::<Hqc1>();
    let mut forger =
        StatefulClient::<Hqc1, _>::new(RandomRequestAuth::new(auth_bytes, OsEntropy), &OsEntropy);
    let (reply, _) = deliver(&mut server, src(1), forger.hello());
    assert_eq!(proofs.load(Ordering::SeqCst), 1);
    assert_eq!(reply.len(), 1);
    assert!(forger.on_server_hello(&reply[0]).is_err());
    assert!(server.table().is_empty());
}

#[test]
fn a_hello_with_the_wrong_request_length_costs_nothing() {
    let (mut server, proofs) = server::<Hqc1>();
    let mut hello = honest_client::<Hqc1>().hello().to_vec();
    hello.pop();
    let (reply, _) = deliver(&mut server, src(1), &hello);
    assert!(reply.is_empty());
    assert_eq!(proofs.load(Ordering::SeqCst), 0);
}

#[test]
fn upload_and_reply_sizes_per_level() {
    fn sizes<K: StatefulKem + AuthLevel>() -> (usize, usize) {
        let (mut server, _) = server::<K>();
        let mut client = honest_client::<K>();
        let fragments = upload_fragments(&mut server, &mut client, src(1));
        let exchange = run_upload(&mut server, &fragments, src(1));
        (fragments.len(), exchange.ciphertext_datagrams.len())
    }
    assert_eq!(sizes::<Hqc1>(), (2, 4));
    assert_eq!(sizes::<Hqc3>(), (4, 8));
    assert_eq!(sizes::<Hqc5>(), (7, 13));
}
