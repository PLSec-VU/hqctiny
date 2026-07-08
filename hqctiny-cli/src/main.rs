use HQCTiny::client::{Client, PointResult};
use HQCTiny::encoding::{Packet, decode_packet, encode_packet};
use HQCTiny::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCTiny::server::Server;
use HQCTiny::traits::*;
use clap::{Parser, Subcommand, ValueEnum};
use rand::RngCore;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::interval;

#[derive(Clone)]
struct OsEntropy;
impl EntropyProvider for OsEntropy {
    fn random_bytes(&self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}

#[derive(Clone)]
struct InMemorySessionStore {
    sessions: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl InMemorySessionStore {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl SessionStore for InMemorySessionStore {
    fn save_session(&self, k_session: [u8; 32]) {
        self.sessions.lock().unwrap().push(k_session);
    }
}

struct RotatingKeyProviderInner {
    current_idx: RwLock<u8>,
    keys: [RwLock<Option<[u8; 32]>>; 2],
}

#[derive(Clone)]
struct RotatingKeyProvider {
    inner: Arc<RotatingKeyProviderInner>,
}

impl RotatingKeyProvider {
    fn new(entropy: &impl EntropyProvider) -> Self {
        let mut k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        entropy.random_bytes(&mut k0);
        entropy.random_bytes(&mut k1);
        Self {
            inner: Arc::new(RotatingKeyProviderInner {
                current_idx: RwLock::new(0),
                keys: [RwLock::new(Some(k0)), RwLock::new(Some(k1))],
            }),
        }
    }

    fn rotate(&self, entropy: &impl EntropyProvider) {
        let mut idx_guard = self.inner.current_idx.write().unwrap();
        let next_idx = (*idx_guard + 1) % 2;
        let mut new_key = [0u8; 32];
        entropy.random_bytes(&mut new_key);
        *self.inner.keys[next_idx as usize].write().unwrap() = Some(new_key);
        *idx_guard = next_idx;
        println!("Rotated cookie key. New active index: {}", next_idx);
    }
}

impl CookieKeyProvider for RotatingKeyProvider {
    fn current_key_index(&self) -> u8 {
        *self.inner.current_idx.read().unwrap()
    }
    fn get_key(&self, index: u8) -> Option<[u8; 32]> {
        if index > 1 {
            return None;
        }
        *self.inner.keys[index as usize].read().unwrap()
    }
}

async fn spawn_rotation_task(provider: RotatingKeyProvider) {
    let mut interval = interval(Duration::from_secs(90));
    interval.tick().await;
    loop {
        interval.tick().await;
        provider.rotate(&OsEntropy);
    }
}

async fn run_server<SCHEME: HqcScheme>(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
    println!("Server listening on 0.0.0.0:{}", port);

    let entropy = OsEntropy;
    let key_provider = RotatingKeyProvider::new(&entropy);
    let store = InMemorySessionStore::new();
    let server = Server::<SCHEME, _, _, _>::new(store, OsEntropy, key_provider.clone());

    tokio::spawn(spawn_rotation_task(key_provider));

    let mut buf = [0u8; 4096];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let packet = match decode_packet::<SCHEME>(&buf[..len]) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to decode packet from {}: {:?}", addr, e);
                continue;
            }
        };

        match packet {
            Packet::HandshakeRequest(req) => match server.handle_handshake(req) {
                Ok(res) => {
                    let mut resp_buf = [0u8; 2048];
                    let encoded =
                        encode_packet::<SCHEME>(&Packet::HandshakeResponse(res), &mut resp_buf)?;
                    socket.send_to(encoded, addr).await?;
                }
                Err(e) => eprintln!("Handshake error for {}: {:?}", addr, e),
            },
            Packet::PointRequest(req) => match server.handle_point_request(req) {
                Ok(res) => {
                    let mut resp_buf = [0u8; 2048];
                    let encoded =
                        encode_packet::<SCHEME>(&Packet::PointResponse(res), &mut resp_buf)?;
                    socket.send_to(encoded, addr).await?;
                }
                Err(e) => eprintln!("Point request error for {}: {:?}", addr, e),
            },
            _ => eprintln!("Unexpected packet type from {}", addr),
        }
    }
}

async fn run_client<SCHEME: HqcScheme>(
    server_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(server_addr).await?;

    let store = InMemorySessionStore::new();
    let client = Client::<SCHEME, _, _, _>::new(store, OsEntropy);

    let (client, handshake_req) = client.initialize();
    let mut buf = [0u8; 2048];
    let encoded = encode_packet::<SCHEME>(&Packet::HandshakeRequest(handshake_req), &mut buf)?;
    socket.send(encoded).await?;

    let mut recv_buf = [0u8; 4096];
    let len = socket.recv(&mut recv_buf).await?;
    let packet = decode_packet::<SCHEME>(&recv_buf[..len])?;

    let handshake_res = match packet {
        Packet::HandshakeResponse(res) => res,
        _ => return Err("Expected HandshakeResponse".into()),
    };

    let (client, point_reqs) = client.handle_handshake_response(handshake_res)?;
    let mut client = client;

    // Send all point requests
    for req in point_reqs {
        let mut buf = [0u8; 2048];
        let encoded = encode_packet::<SCHEME>(&Packet::PointRequest(req), &mut buf)?;
        socket.send(encoded).await?;
    }

    // Collect responses
    loop {
        let len = socket.recv(&mut recv_buf).await?;
        let packet = decode_packet::<SCHEME>(&recv_buf[..len])?;
        let point_res = match packet {
            Packet::PointResponse(res) => res,
            _ => continue,
        };

        match client.handle_point_response(point_res)? {
            PointResult::Collecting(c) => client = *c,
            PointResult::Completed(_, key) => {
                use base64::{Engine as _, engine::general_purpose};
                println!(
                    "Shared Secret (Base64): {}",
                    general_purpose::STANDARD.encode(key)
                );
                return Ok(());
            }
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a UDP server
    Server {
        #[arg(short, long, default_value_t = 12345)]
        port: u16,
        #[arg(short, long, value_enum, default_value_t = Variant::Hqc1)]
        variant: Variant,
    },
    /// Run as a UDP client
    Client {
        #[arg(short, long, default_value = "127.0.0.1:12345")]
        addr: String,
        #[arg(short, long, value_enum, default_value_t = Variant::Hqc1)]
        variant: Variant,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Variant {
    Hqc1,
    Hqc3,
    Hqc5,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Commands::Server { port, variant } => match variant {
            Variant::Hqc1 => run_server::<Hqc1>(port).await?,
            Variant::Hqc3 => run_server::<Hqc3>(port).await?,
            Variant::Hqc5 => run_server::<Hqc5>(port).await?,
        },
        Commands::Client { addr, variant } => match variant {
            Variant::Hqc1 => run_client::<Hqc1>(&addr).await?,
            Variant::Hqc3 => run_client::<Hqc3>(&addr).await?,
            Variant::Hqc5 => run_client::<Hqc5>(&addr).await?,
        },
    }

    Ok(())
}
