use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::num::NonZeroUsize;

/// Binds `count` UDP sockets to the same address. With more than one socket,
/// each has SO_REUSEPORT set, and Linux sends all datagrams from one source
/// address and port to the same socket. If the port of `addr` is 0, all
/// sockets share the port that the kernel gives to the first one.
pub fn bind_udp_workers(addr: SocketAddr, count: NonZeroUsize) -> io::Result<Vec<UdpSocket>> {
    if count.get() == 1 {
        return Ok(vec![UdpSocket::bind(addr)?]);
    }
    let first = bind_reuse_port(addr)?;
    let shared_addr = first.local_addr()?;
    let mut sockets = vec![first];
    for _ in 1..count.get() {
        sockets.push(bind_reuse_port(shared_addr)?);
    }
    Ok(sockets)
}

fn bind_reuse_port(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// A thread builder for one server worker. Without `stack_kib` the thread gets
/// the platform default stack size. With it, the thread gets exactly that many
/// KiB, so a test can find the smallest stack that works.
pub fn worker_thread(stack_kib: Option<NonZeroUsize>) -> std::thread::Builder {
    let builder = std::thread::Builder::new();
    match stack_kib {
        Some(kib) => builder.stack_size(kib.get() * 1024),
        None => builder,
    }
}

/// A single worker without an explicit stack size runs on the calling thread,
/// so `ulimit -s` limits its stack.
pub fn runs_on_calling_thread(workers: usize, stack_kib: Option<NonZeroUsize>) -> bool {
    workers == 1 && stack_kib.is_none()
}
