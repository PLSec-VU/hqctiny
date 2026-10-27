use HQCLethe::auth::{AuthLevel, ServerSecretKey};
use HQCLethe::sockets::bind_udp_workers;
use HQCLethe::stateful::auth::MlKemServerAuth;
use HQCLethe::stateful::config::{ServerConfig, TableConfig};
use HQCLethe::stateful::entropy::OsEntropy;
use HQCLethe::stateful::kem::StatefulKem;
use HQCLethe::stateful::server::StatefulServer;
use HQCLethe::stateful::transport::serve_workers;
use clap::Parser;
use hqclethe_stateful::{Variant, dispatch_variant};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

#[derive(Parser)]
#[command(about = "Cookie-gated stateful HQC encapsulation server (baseline)")]
struct Args {
    #[arg(long, default_value_t = 12346)]
    port: u16,
    /// Server threads. Each has its own socket on the port and its own
    /// table with 1/N of the entry and byte budget.
    #[arg(long, default_value = "1")]
    workers: NonZeroUsize,
    /// Stack size of each worker thread in KiB. By default a single worker
    /// runs on the main thread, where `ulimit -s` sets the stack, and several
    /// workers get the platform default thread stack.
    #[arg(long)]
    worker_stack_kib: Option<NonZeroUsize>,
    #[arg(long, value_enum, default_value_t = Variant::Hqc1)]
    variant: Variant,
    /// ML-KEM secret key file (default: server-<variant>.sk)
    #[arg(long)]
    key: Option<PathBuf>,
    #[arg(long, default_value_t = TableConfig::default().max_entries)]
    max_entries: usize,
    #[arg(long, default_value_t = TableConfig::default().max_bytes)]
    max_table_bytes: usize,
    #[arg(long, default_value_t = TableConfig::default().max_entries_per_source)]
    max_entries_per_source: usize,
    #[arg(long, default_value_t = TableConfig::default().idle_timeout_ms)]
    idle_timeout_ms: u64,
    #[arg(long, default_value_t = TableConfig::default().max_lifetime_ms)]
    max_lifetime_ms: u64,
    #[arg(long, default_value_t = TableConfig::default().evict_min_age_ms)]
    evict_min_age_ms: u64,
    #[arg(long, default_value_t = ServerConfig::default().cookie_lifetime_ms)]
    cookie_lifetime_ms: u64,
    #[arg(long, default_value_t = ServerConfig::default().key_rotation_ms)]
    key_rotation_ms: u64,
    /// Count table creations, evictions and timeouts of entries from this source IP
    #[arg(long)]
    watch_source: Option<std::net::IpAddr>,
}

impl Args {
    fn worker_config(&self) -> ServerConfig {
        let table = TableConfig {
            max_entries: self.max_entries,
            max_bytes: self.max_table_bytes,
            max_entries_per_source: self.max_entries_per_source,
            idle_timeout_ms: self.idle_timeout_ms,
            max_lifetime_ms: self.max_lifetime_ms,
            evict_min_age_ms: self.evict_min_age_ms,
            ..TableConfig::default()
        };
        ServerConfig {
            cookie_lifetime_ms: self.cookie_lifetime_ms,
            key_rotation_ms: self.key_rotation_ms,
            table: table.shard(self.workers.get()),
        }
    }
}

#[cfg(not(feature = "quiet"))]
fn report_shared_secret(_src: SocketAddr, secret: &[u8]) {
    eprintln!("session key: {}", hqclethe_stateful::hex(secret));
}

#[cfg(feature = "quiet")]
fn report_shared_secret(_src: SocketAddr, _secret: &[u8]) {}

fn load_auth<K: AuthLevel>(args: &Args) -> std::io::Result<MlKemServerAuth<K>> {
    let path = args
        .key
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("server-{}.sk", args.variant.name())));
    let secret_key = ServerSecretKey::<K>::from_bytes(std::fs::read(&path)?).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not a secret key for this variant", path.display()),
        )
    })?;
    Ok(MlKemServerAuth::new(secret_key))
}

fn run<K: StatefulKem + AuthLevel>(args: &Args) -> std::io::Result<()> {
    let auth = load_auth::<K>(args)?;
    let sockets = bind_udp_workers(SocketAddr::from(([0, 0, 0, 0], args.port)), args.workers)?;
    eprintln!(
        "hqclethe-server-stateful listening on 0.0.0.0:{} with {} workers",
        args.port, args.workers
    );
    let servers = (0..args.workers.get())
        .map(|_| {
            let mut server =
                StatefulServer::<K, _, _>::new(args.worker_config(), auth.clone(), OsEntropy, 0);
            if let Some(ip) = args.watch_source {
                server.watch_source(ip);
            }
            server
        })
        .collect();
    serve_workers(
        sockets,
        servers,
        args.worker_stack_kib,
        &AtomicBool::new(false),
        cfg!(feature = "flood-stats"),
        &report_shared_secret,
    )
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    dispatch_variant!(args.variant, Scheme => run::<Scheme>(&args))
}
