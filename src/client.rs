use crate::auth::{self, AuthSecret, ServerPublicKey};
use crate::encoding::{
    self, GAMMA_BYTES, Header, Kind, MAX_UDP_PAYLOAD, SALT_BYTES, SEED_BYTES, UCHUNK_MAX_BYTES,
    uchunk_count,
};
use crate::envelope::SessionKeys;
use crate::error::{Error, Result};
use crate::hqc::{HqcPublicKeyParameters, HqcScheme};
use crate::puzzle;
use crate::traits::*;
use zeroize::{Zeroize, Zeroizing};

/// The hardest puzzle a client solves unless the caller says otherwise. An
/// attacker who can forge a challenge can make the client spend this much work.
pub const DEFAULT_MAX_PUZZLE_DIFFICULTY: u8 = 24;

pub struct Initial;

pub struct AwaitingHandshake {
    pub request: Vec<u8>,
    pub request_digest: [u8; 32],
    pub auth_secret: AuthSecret,
    pub keys: SessionKeys,
    pub sk: Zeroizing<Vec<u8>>,
    pub s_residues: Vec<Vec<u8>>,
}

/// A request ready to send. Resending the same bytes is safe: the server
/// answers every copy the same way.
#[derive(Debug, Clone)]
pub struct OutgoingRequest {
    pub kind: Kind,
    pub index: u8,
    pub bytes: Vec<u8>,
}

pub struct HandshakeReply {
    pub cookie: Vec<u8>,
    pub salt: [u8; SALT_BYTES],
    pub gamma: [u8; GAMMA_BYTES],
    pub key_index: u8,
}

pub struct Collecting {
    pub auth_secret: AuthSecret,
    pub keys: SessionKeys,
    pub request_digest: [u8; 32],
    pub salt: [u8; SALT_BYTES],
    pub gamma: [u8; GAMMA_BYTES],
    pub key_index: u8,
    pub sk: Zeroizing<Vec<u8>>,
    pub cookie: Vec<u8>,
    pub s_residues: Vec<Vec<u8>>,
    pub requests: Vec<OutgoingRequest>,
    pub answered: Vec<bool>,
    pub u_bytes: Vec<u8>,
    pub v_residues: Vec<Vec<u8>>,
    pub session_key: Option<Zeroizing<Vec<u8>>>,
    pub ciphertext: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum Progress {
    /// The response was new and valid. Other responses are still missing.
    Pending,
    /// The response was valid but the client already had its content.
    Duplicate,
    /// The last response arrived and the session key is confirmed.
    Complete(Zeroizing<Vec<u8>>),
}

pub struct Client<SCHEME, SStore, E, State>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
{
    pub session_store: SStore,
    pub entropy_provider: E,
    pub state: State,
    _phantom: std::marker::PhantomData<SCHEME>,
}

fn build_request<SCHEME: HqcScheme>(
    keys: &SessionKeys,
    key_index: u8,
    cookie: &[u8],
    kind: Kind,
    index: u8,
    residue: &[u8],
) -> Result<OutgoingRequest> {
    let mut payload = vec![0u8; encoding::request_payload_len::<SCHEME>(kind)];
    payload[..residue.len()].copy_from_slice(residue);
    let mut buf = [0u8; MAX_UDP_PAYLOAD];
    let len = encoding::write_request::<SCHEME>(
        &mut buf,
        Header::request(kind, key_index, index),
        cookie,
        &payload,
        &keys.client_to_server,
    )?;
    Ok(OutgoingRequest {
        kind,
        index,
        bytes: buf[..len].to_vec(),
    })
}

fn words_from_bytes(bytes: &[u8], words: &mut [u64]) {
    words.fill(0);
    for (word, chunk) in words.iter_mut().zip(bytes.chunks(8)) {
        let mut le = [0u8; 8];
        le[..chunk.len()].copy_from_slice(chunk);
        *word = u64::from_le_bytes(le);
    }
}

impl<SCHEME, SStore, E> Client<SCHEME, SStore, E, Initial>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
{
    pub fn new(session_store: SStore, entropy_provider: E) -> Self {
        Self {
            session_store,
            entropy_provider,
            state: Initial,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Generates an ephemeral HQC keypair and the Phase-0 request,
    /// encapsulating to the server's pinned long-term ML-KEM key. Returns
    /// the client and the request bytes.
    pub fn initialize(
        self,
        server_pk: &ServerPublicKey<SCHEME>,
    ) -> (Client<SCHEME, SStore, E, AwaitingHandshake>, Vec<u8>) {
        let mut entropy = [0u8; 48];
        self.entropy_provider.random_bytes(&mut entropy);

        let mut pk = vec![0u8; SCHEME::PUBLIC_KEY_BYTES];
        let mut sk = Zeroizing::new(vec![0u8; SCHEME::SECRET_KEY_BYTES]);
        unsafe {
            SCHEME::keypair(&entropy, &mut pk, &mut sk);
        }
        entropy.zeroize();

        let pk_params = SCHEME::partial_public_key_encaps(&pk);
        let hash_ek_kem = *pk_params.hash_ek_kem();
        let mut h_seed = [0u8; SEED_BYTES];
        h_seed.copy_from_slice(&pk[..SEED_BYTES]);

        let s_residues = crate::crt::client::residues_of::<SCHEME>(pk_params.s());

        let (auth_ct, auth_secret) = server_pk.encapsulate();
        let mut request = vec![0u8; encoding::request_len::<SCHEME>(Kind::Handshake)];
        encoding::write_handshake_request::<SCHEME>(&mut request, &hash_ek_kem, &h_seed, &auth_ct)
            .expect("request buffer has the exact request length");
        let body_start = encoding::HEADER_BYTES;
        let body_end = body_start + encoding::handshake_request_body_len::<SCHEME>();
        let request_digest = crate::kdf::request_digest(&request[body_start..body_end]);
        let keys = SessionKeys::derive(&auth_secret);

        let next_state = Client {
            session_store: self.session_store,
            entropy_provider: self.entropy_provider,
            state: AwaitingHandshake {
                request: request.clone(),
                request_digest,
                auth_secret,
                keys,
                sk,
                s_residues,
            },
            _phantom: std::marker::PhantomData,
        };

        (next_state, request)
    }
}

impl<SCHEME, SStore, E> Client<SCHEME, SStore, E, AwaitingHandshake>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
{
    /// Checks and opens the Phase-0 response without consuming the client, so
    /// a forged packet from a third party does not end the session.
    pub fn verify_handshake_response(&self, packet: &[u8]) -> Result<HandshakeReply> {
        let view = encoding::parse_response::<SCHEME>(packet)
            .map_err(|_| Error::ServerAuthenticationFailed)?;
        if view.header.kind != Kind::Handshake {
            return Err(Error::ServerAuthenticationFailed);
        }
        let mut payload = [0u8; MAX_UDP_PAYLOAD];
        let len = encoding::open_response(
            &view,
            &self.state.request_digest,
            &self.state.keys.server_to_client,
            &mut payload,
        )
        .map_err(|_| Error::ServerAuthenticationFailed)?;
        let payload = &payload[..len];

        let cookie_bytes = encoding::cookie_len::<SCHEME>();
        let (cookie, rest) = payload.split_at(cookie_bytes);
        let (salt, gamma) = rest.split_at(SALT_BYTES);
        Ok(HandshakeReply {
            cookie: cookie.to_vec(),
            salt: salt.try_into().map_err(|_| Error::SerializationError)?,
            gamma: gamma.try_into().map_err(|_| Error::SerializationError)?,
            key_index: view.header.key_index,
        })
    }

    /// Answers a server challenge with a solved Phase-0 request. The client
    /// cannot check the challenge MAC, so it refuses puzzles harder than
    /// `max_difficulty`. Solving takes about `2^difficulty` hash calls.
    pub fn solve_challenge(&self, packet: &[u8], max_difficulty: u8) -> Result<Vec<u8>> {
        let (key_index, challenge, peer) = encoding::parse_challenge_response(packet)?;
        if challenge.difficulty > max_difficulty {
            return Err(Error::PuzzleTooHard);
        }
        let counter = puzzle::solve(&challenge, &peer, &self.state.request_digest);
        let mut solved = vec![0u8; encoding::request_len::<SCHEME>(Kind::SolvedHandshake)];
        encoding::write_solved_handshake_request::<SCHEME>(
            &mut solved,
            &self.state.request,
            key_index,
            &challenge,
            counter,
        )?;
        Ok(solved)
    }

    /// Builds every Phase-1 request from a verified reply.
    pub fn start_collecting(
        self,
        reply: HandshakeReply,
    ) -> Result<Client<SCHEME, SStore, E, Collecting>> {
        let mut requests = Vec::new();
        for index in 0..uchunk_count::<SCHEME>() as u8 {
            requests.push(build_request::<SCHEME>(
                &self.state.keys,
                reply.key_index,
                &reply.cookie,
                Kind::UChunk,
                index,
                &[],
            )?);
        }
        for (index, residue) in self.state.s_residues.iter().enumerate() {
            requests.push(build_request::<SCHEME>(
                &self.state.keys,
                reply.key_index,
                &reply.cookie,
                Kind::VResidue,
                index as u8,
                residue,
            )?);
        }

        let residue_count = self.state.s_residues.len();
        let answered = vec![false; requests.len()];
        Ok(Client {
            session_store: self.session_store,
            entropy_provider: self.entropy_provider,
            state: Collecting {
                auth_secret: self.state.auth_secret,
                keys: self.state.keys,
                request_digest: self.state.request_digest,
                salt: reply.salt,
                gamma: reply.gamma,
                key_index: reply.key_index,
                sk: self.state.sk,
                cookie: reply.cookie,
                s_residues: self.state.s_residues,
                requests,
                answered,
                u_bytes: vec![0u8; SCHEME::VEC_N_SIZE_BYTES],
                v_residues: vec![Vec::new(); residue_count],
                session_key: None,
                ciphertext: None,
            },
            _phantom: std::marker::PhantomData,
        })
    }

    pub fn handle_handshake_response(
        self,
        packet: &[u8],
    ) -> Result<Client<SCHEME, SStore, E, Collecting>> {
        let reply = self.verify_handshake_response(packet)?;
        self.start_collecting(reply)
    }
}

impl<SCHEME, SStore, E> Client<SCHEME, SStore, E, Collecting>
where
    SCHEME: HqcScheme,
    SStore: SessionStore,
    E: EntropyProvider,
{
    pub fn requests(&self) -> &[OutgoingRequest] {
        &self.state.requests
    }

    /// The requests whose responses have not arrived yet.
    pub fn outstanding_requests(&self) -> impl Iterator<Item = &OutgoingRequest> {
        self.state
            .requests
            .iter()
            .zip(&self.state.answered)
            .filter(|(_, answered)| !**answered)
            .map(|(request, _)| request)
    }

    /// The assembled KEM ciphertext, once the session is complete.
    pub fn ciphertext(&self) -> Option<&[u8]> {
        self.state.ciphertext.as_deref()
    }

    fn slot(kind: Kind, index: u8) -> usize {
        match kind {
            Kind::UChunk => index as usize,
            _ => uchunk_count::<SCHEME>() + index as usize,
        }
    }

    /// Opens one response packet. A packet that fails authentication changes
    /// nothing, so a forged packet cannot end the session. Responses may
    /// arrive in any order and more than once.
    pub fn handle_response(&mut self, packet: &[u8]) -> Result<Progress> {
        let view = encoding::parse_response::<SCHEME>(packet)?;
        let header = view.header;
        if header.kind == Kind::Handshake {
            return Err(Error::SerializationError);
        }
        let mut payload = [0u8; MAX_UDP_PAYLOAD];
        let len =
            encoding::open_response(&view, &[], &self.state.keys.server_to_client, &mut payload)?;
        let payload = &payload[..len];

        let slot = Self::slot(header.kind, header.index);
        if self.state.answered[slot] {
            return Ok(Progress::Duplicate);
        }
        match header.kind {
            Kind::UChunk => {
                let start = header.index as usize * UCHUNK_MAX_BYTES;
                self.state.u_bytes[start..start + len].copy_from_slice(payload);
            }
            Kind::VResidue => {
                self.state.v_residues[header.index as usize] = payload.to_vec();
            }
            _ => return Err(Error::SerializationError),
        }
        self.state.answered[slot] = true;

        if self.state.answered.iter().all(|answered| *answered) {
            Ok(Progress::Complete(self.finish()?))
        } else {
            Ok(Progress::Pending)
        }
    }

    fn finish(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let v_words = crate::crt::client::reconstruct_v::<SCHEME>(&self.state.v_residues);
        let mut u_words = vec![0u64; SCHEME::VEC_N_SIZE_64];
        words_from_bytes(&self.state.u_bytes, &mut u_words);

        let mut ct = vec![0u8; SCHEME::CIPHERTEXT_BYTES];
        SCHEME::serialize_ciphertext(&mut ct, &u_words, &v_words, &self.state.salt);

        let mut ss = Zeroizing::new(vec![0u8; SCHEME::SHARED_SECRET_BYTES]);
        if SCHEME::dec(&mut ss, &ct, &self.state.sk) != 0 {
            return Err(Error::DecodingFailed);
        }

        let k_joint = auth::bind_secret(&ss, &self.state.auth_secret);
        let mut k_session = crate::kdf::derive_session_key(&*k_joint);
        let mut k_transcript = crate::kdf::derive_transcript_key(&*k_joint);

        let transcript = crate::kdf::compute_transcript(
            &self.state.request_digest,
            &self.state.salt,
            self.state.key_index,
        );
        let confirmed =
            crate::kdf::verify_confirmation_tag(&k_transcript, &transcript, &self.state.gamma);
        k_transcript.zeroize();
        if !confirmed {
            k_session.zeroize();
            return Err(Error::KeyConfirmationFailed);
        }

        let session_key = Zeroizing::new(k_session.to_vec());
        k_session.zeroize();
        self.state.session_key = Some(session_key.clone());
        self.state.ciphertext = Some(ct);
        Ok(session_key)
    }
}
