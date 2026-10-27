use super::auth::ServerAuth;
use super::config::ServerConfig;
use super::cookie::{Cookie, CookieKeys};
use super::kem::{ENTROPY_BYTES, StatefulKem};
use super::stats::{Stats, StatsSnapshot};
use super::table::{Accepted, DropReason, EntryKey, Fragment, ReassemblyTable};
use super::transcript::transcript;
use super::wire::{self, CT_ID_BYTES, Message};
use crate::auth::AuthSecret;
use crate::envelope::{NONCE_BYTES, Nonce, SessionKeys, TAG_BYTES};
use crate::traits::EntropyProvider;
use std::marker::PhantomData;
use std::net::SocketAddr;

const COOKIE_KEY_BYTES: usize = 32;

pub type Sender<'a> = dyn FnMut(&[u8]) -> bool + 'a;

pub struct StatefulServer<K, A, E> {
    config: ServerConfig,
    auth: A,
    entropy: E,
    keys: CookieKeys,
    table: ReassemblyTable,
    stats: Stats,
    _kem: PhantomData<fn() -> K>,
}

impl<K, A, E> StatefulServer<K, A, E>
where
    K: StatefulKem,
    A: ServerAuth,
    E: EntropyProvider,
{
    pub fn new(config: ServerConfig, auth: A, entropy: E, now_ms: u64) -> Self {
        let mut current = [0u8; COOKIE_KEY_BYTES];
        let mut previous = [0u8; COOKIE_KEY_BYTES];
        entropy.random_bytes(&mut current);
        entropy.random_bytes(&mut previous);
        Self {
            table: ReassemblyTable::new(config.table.clone()),
            keys: CookieKeys::new(current, previous, now_ms),
            config,
            auth,
            entropy,
            stats: Stats::default(),
            _kem: PhantomData,
        }
    }

    pub fn table(&self) -> &ReassemblyTable {
        &self.table
    }

    pub fn watch_source(&mut self, ip: std::net::IpAddr) {
        self.table.watch_source(ip);
    }

    pub fn snapshot(&self, now_ms: u64) -> StatsSnapshot {
        let counters = self.table.counters();
        StatsSnapshot {
            stats: self.stats,
            table_entries: self.table.len() as u64,
            table_bytes: self.table.accounted_bytes() as u64,
            evictions: counters.evictions,
            timeouts: counters.timeouts,
            peak_entries: counters.peak_entries,
            peak_bytes: counters.peak_bytes,
            entries_created: counters.created,
            watched_created: counters.watched_created,
            watched_evictions: counters.watched_evictions,
            watched_timeouts: counters.watched_timeouts,
            oldest_entry_age_ms: self.table.oldest_entry_age_ms(now_ms),
        }
    }

    pub fn tick(&mut self, now_ms: u64) {
        for _ in 0..self.keys.rotations_due(now_ms, self.config.key_rotation_ms) {
            let mut fresh = [0u8; COOKIE_KEY_BYTES];
            self.entropy.random_bytes(&mut fresh);
            self.keys.rotate(fresh, now_ms);
        }
        self.table.sweep_if_due(now_ms);
    }

    fn send_counted(&mut self, send: &mut Sender<'_>, datagram: &[u8]) {
        if send(datagram) {
            self.stats.responses_sent += 1;
        }
    }

    pub fn handle(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        now_ms: u64,
        send: &mut Sender<'_>,
    ) -> Option<Vec<u8>> {
        self.tick(now_ms);
        match wire::parse(datagram) {
            Some(Message::Hello {
                level,
                auth_request,
                ..
            }) if level == K::LEVEL_ID => {
                self.answer_hello(src, datagram, auth_request, now_ms, send);
                None
            }
            Some(Message::KeyFragment {
                level,
                cookie,
                index,
                count,
                header,
                sealed,
            }) if level == K::LEVEL_ID => {
                let fragment = KeyFragmentPacket {
                    cookie,
                    index,
                    count,
                    header,
                    sealed,
                };
                self.accept_key_fragment(src, &fragment, now_ms, send)
            }
            _ => {
                self.stats.rejected_malformed += 1;
                None
            }
        }
    }

    fn answer_hello(
        &mut self,
        src: SocketAddr,
        hello: &[u8],
        auth_request: &[u8],
        now_ms: u64,
        send: &mut Sender<'_>,
    ) {
        if auth_request.len() != self.auth.request_bytes() {
            self.stats.rejected_malformed += 1;
            return;
        }
        self.stats.auth_proofs += 1;
        let Some(k_auth) = self.auth.accept(auth_request) else {
            self.stats.rejected_auth += 1;
            return;
        };
        let session = SessionKeys::derive(&k_auth);
        let cookie = self.keys.issue(&src, now_ms, self.random_nonce(), &k_auth);
        let nonce = self.random_nonce();
        let reply = wire::encode_server_hello(&session.server_to_client, &nonce, hello, &cookie);
        self.stats.hellos_answered += 1;
        self.send_counted(send, &reply);
    }

    fn random_nonce(&self) -> Nonce {
        let mut nonce = [0u8; NONCE_BYTES];
        self.entropy.random_bytes(&mut nonce);
        nonce
    }

    fn upload_bytes(&self) -> usize {
        K::PUBLIC_KEY_BYTES
    }

    fn fragment_is_well_formed(&self, index: usize, count: usize, sealed: &[u8]) -> bool {
        let total = self.upload_bytes();
        count == wire::key_fragment_count(total)
            && index < count
            && sealed.len() == wire::key_fragment_range(index, total).len() + TAG_BYTES
    }

    fn accept_key_fragment(
        &mut self,
        src: SocketAddr,
        packet: &KeyFragmentPacket<'_>,
        now_ms: u64,
        send: &mut Sender<'_>,
    ) -> Option<Vec<u8>> {
        let (index, count) = (packet.index as usize, packet.count as usize);
        if !self.fragment_is_well_formed(index, count, packet.sealed) {
            self.stats.rejected_malformed += 1;
            return None;
        }
        let Some(k_auth) =
            self.keys
                .open(&src, &packet.cookie, now_ms, self.config.cookie_lifetime_ms)
        else {
            self.stats.rejected_cookie += 1;
            return None;
        };
        let session = SessionKeys::derive(&k_auth);
        let Ok(plaintext) = wire::open_key_fragment(
            &session.client_to_server,
            &packet.cookie,
            packet.index,
            packet.header,
            packet.sealed,
        ) else {
            self.stats.rejected_ae += 1;
            return None;
        };
        let total = self.upload_bytes();
        let fragment = Fragment {
            index,
            offset: wire::key_fragment_range(index, total).start,
            data: &plaintext,
        };
        let key = EntryKey {
            addr: src,
            cookie: packet.cookie,
        };
        match self.table.accept(key, now_ms, total, count, fragment) {
            Accepted::Complete(public_key) => {
                self.encapsulate_and_reply(&public_key, &k_auth, &session, send)
            }
            Accepted::Incomplete => {
                self.stats.fragments_accepted += 1;
                None
            }
            Accepted::Duplicate => {
                self.stats.fragments_duplicate += 1;
                None
            }
            Accepted::Dropped(DropReason::SourceLimit) => {
                self.stats.dropped_source_limit += 1;
                None
            }
            Accepted::Dropped(DropReason::TableFull) => {
                self.stats.dropped_table_full += 1;
                None
            }
        }
    }

    fn encapsulate_and_reply(
        &mut self,
        public_key: &[u8],
        k_auth: &AuthSecret,
        session: &SessionKeys,
        send: &mut Sender<'_>,
    ) -> Option<Vec<u8>> {
        self.stats.fragments_accepted += 1;
        let mut seed = [0u8; ENTROPY_BYTES];
        self.entropy.random_bytes(&mut seed);
        let Some((ciphertext, hqc_secret)) = K::encaps(&seed, public_key) else {
            self.stats.encaps_failed += 1;
            return None;
        };
        self.stats.encaps_completed += 1;
        let digest = transcript(K::LEVEL_ID, public_key, &ciphertext);
        let proof = self.auth.prove(k_auth, &digest, &hqc_secret);
        let response = [ciphertext.as_slice(), proof.tag.as_slice()].concat();
        let mut ct_id = [0u8; CT_ID_BYTES];
        self.entropy.random_bytes(&mut ct_id);
        for index in 0..wire::ct_fragment_count(response.len()) {
            let datagram = wire::encode_ct_fragment(
                &session.server_to_client,
                &self.random_nonce(),
                K::LEVEL_ID,
                &ct_id,
                index,
                &response,
            );
            self.send_counted(send, &datagram);
        }
        Some(proof.session_secret)
    }
}

struct KeyFragmentPacket<'a> {
    cookie: Cookie,
    index: u16,
    count: u16,
    header: &'a [u8],
    sealed: &'a [u8],
}
