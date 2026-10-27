//! In-process protocol run, used by tests, benchmarks and the bandwidth report.

use crate::auth::ServerPublicKey;
use crate::client::{Client, DEFAULT_MAX_PUZZLE_DIFFICULTY, Initial, Progress};
use crate::encoding::{Header, Kind, MAX_UDP_PAYLOAD};
use crate::error::{Error, Result};
use crate::hqc::HqcScheme;
use crate::server::Server;
use crate::traits::*;
use std::net::{IpAddr, Ipv4Addr};
use zeroize::Zeroizing;

/// Sizes of one request and the reply it triggered.
#[derive(Debug, Clone, Copy)]
pub struct PacketRecord {
    pub kind: Kind,
    pub index: u8,
    pub request_bytes: usize,
    pub response_bytes: usize,
}

pub struct SessionOutcome {
    pub session_key: Zeroizing<Vec<u8>>,
    pub ciphertext: Vec<u8>,
    pub packets: Vec<PacketRecord>,
}

const IN_PROCESS_PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

pub fn run_in_process<SCHEME, SS, SE, CS, CE>(
    server: &Server<SCHEME, SS, SE>,
    client: Client<SCHEME, CS, CE, Initial>,
    server_pk: &ServerPublicKey<SCHEME>,
) -> Result<SessionOutcome>
where
    SCHEME: HqcScheme,
    SS: SessionStore,
    SE: EntropyProvider,
    CS: SessionStore,
    CE: EntropyProvider,
{
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let (client, request) = client.initialize(server_pk);
    let mut response_len = server.handle_packet(IN_PROCESS_PEER, &request, &mut out)?;
    let mut packets = vec![PacketRecord {
        kind: Kind::Handshake,
        index: 0,
        request_bytes: request.len(),
        response_bytes: response_len,
    }];
    if Header::decode(&out[..response_len])?.kind == Kind::Challenge {
        let solved = client.solve_challenge(&out[..response_len], DEFAULT_MAX_PUZZLE_DIFFICULTY)?;
        response_len = server.handle_packet(IN_PROCESS_PEER, &solved, &mut out)?;
        packets.push(PacketRecord {
            kind: Kind::SolvedHandshake,
            index: 0,
            request_bytes: solved.len(),
            response_bytes: response_len,
        });
    }

    let mut client = client.handle_handshake_response(&out[..response_len])?;
    let requests = client.requests().to_vec();
    for request in requests {
        let response_len = server.handle_packet(IN_PROCESS_PEER, &request.bytes, &mut out)?;
        packets.push(PacketRecord {
            kind: request.kind,
            index: request.index,
            request_bytes: request.bytes.len(),
            response_bytes: response_len,
        });
        if let Progress::Complete(session_key) = client.handle_response(&out[..response_len])? {
            let ciphertext = client.ciphertext().ok_or(Error::DecodingFailed)?.to_vec();
            return Ok(SessionOutcome {
                session_key,
                ciphertext,
                packets,
            });
        }
    }
    Err(Error::Other("session ended without completing"))
}
