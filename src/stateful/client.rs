use super::auth::ClientAuth;
use super::kem::{ENTROPY_BYTES, StatefulKem};
use super::transcript::transcript;
use super::wire::{self, CT_ID_BYTES, HELLO_NONCE_BYTES, Message};
use crate::envelope::{SessionKeys, TAG_BYTES};
use crate::error::{Error, Result};
use crate::traits::EntropyProvider;
use std::marker::PhantomData;

struct CiphertextAssembly {
    ct_id: [u8; CT_ID_BYTES],
    buffer: Vec<u8>,
    received: Vec<bool>,
}

impl CiphertextAssembly {
    fn new(ct_id: [u8; CT_ID_BYTES], total_bytes: usize) -> Self {
        Self {
            ct_id,
            buffer: vec![0u8; total_bytes],
            received: vec![false; wire::ct_fragment_count(total_bytes)],
        }
    }

    fn is_complete(&self) -> bool {
        self.received.iter().all(|&r| r)
    }
}

pub struct StatefulClient<K, A> {
    auth: A,
    hello: Vec<u8>,
    session: SessionKeys,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    key_fragments: Vec<Vec<u8>>,
    assembly: Option<CiphertextAssembly>,
    _kem: PhantomData<fn() -> K>,
}

impl<K: StatefulKem, A: ClientAuth> StatefulClient<K, A> {
    pub fn new<E: EntropyProvider>(auth: A, entropy: &E) -> Self {
        let mut seed = [0u8; ENTROPY_BYTES];
        entropy.random_bytes(&mut seed);
        let (public_key, secret_key) = K::generate_keypair(&seed);
        Self::with_keypair(auth, entropy, public_key, secret_key)
    }

    pub fn with_keypair<E: EntropyProvider>(
        mut auth: A,
        entropy: &E,
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Self {
        let mut nonce = [0u8; HELLO_NONCE_BYTES];
        entropy.random_bytes(&mut nonce);
        let auth_request = auth.begin();
        Self {
            hello: wire::encode_hello(K::LEVEL_ID, &nonce, &auth_request),
            session: SessionKeys::derive(&auth.k_auth()),
            auth,
            public_key,
            secret_key,
            key_fragments: Vec::new(),
            assembly: None,
            _kem: PhantomData,
        }
    }

    pub fn hello(&self) -> &[u8] {
        &self.hello
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn key_fragments(&self) -> &[Vec<u8>] {
        &self.key_fragments
    }

    pub fn on_server_hello(&mut self, datagram: &[u8]) -> Result<&[Vec<u8>]> {
        let Some(Message::ServerHello {
            nonce,
            sealed_cookie,
        }) = wire::parse(datagram)
        else {
            return Err(Error::SerializationError);
        };
        let cookie = wire::open_server_hello(
            &self.session.server_to_client,
            &nonce,
            &self.hello,
            sealed_cookie,
        )
        .map_err(|_| Error::ServerAuthenticationFailed)?;
        self.key_fragments = wire::key_fragments(
            &self.session.client_to_server,
            K::LEVEL_ID,
            &cookie,
            &self.public_key,
        );
        Ok(&self.key_fragments)
    }

    pub fn on_ct_fragment(&mut self, datagram: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(Message::CtFragment {
            level,
            ct_id,
            index,
            count,
            header,
            nonce,
            sealed,
        }) = wire::parse(datagram)
        else {
            return Err(Error::SerializationError);
        };
        let (index, count) = (index as usize, count as usize);
        let total = K::CIPHERTEXT_BYTES + self.auth.tag_bytes();
        let well_formed = level == K::LEVEL_ID
            && count == wire::ct_fragment_count(total)
            && index < count
            && sealed.len() == wire::ct_fragment_range(index, total).len() + TAG_BYTES;
        if !well_formed {
            return Err(Error::SerializationError);
        }
        let payload =
            wire::open_ct_fragment(&self.session.server_to_client, header, &nonce, sealed)?;
        if self.assembly.as_ref().is_none_or(|a| a.ct_id != ct_id) {
            self.assembly = Some(CiphertextAssembly::new(ct_id, total));
        }
        let assembly = self.assembly.as_mut().unwrap();
        assembly.buffer[wire::ct_fragment_range(index, total)].copy_from_slice(&payload);
        assembly.received[index] = true;
        if !assembly.is_complete() {
            return Ok(None);
        }
        let response = self.assembly.take().unwrap().buffer;
        let (ciphertext, tag) = response.split_at(K::CIPHERTEXT_BYTES);
        let hqc_secret = K::decaps(ciphertext, &self.secret_key).ok_or(Error::DecodingFailed)?;
        let digest = transcript(K::LEVEL_ID, &self.public_key, ciphertext);
        self.auth.verify(&digest, tag, &hqc_secret).map(Some)
    }
}
