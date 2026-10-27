use super::config::TableConfig;
use super::cookie::COOKIE_BYTES;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};

pub const ENTRY_OVERHEAD_BYTES: usize = 160;
const IPV6_SOURCE_PREFIX_BYTES: usize = 8;
const MAX_FRAGMENTS: usize = u64::BITS as usize;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct EntryKey {
    pub addr: SocketAddr,
    pub cookie: [u8; COOKIE_BYTES],
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct SourceKey([u8; IPV6_SOURCE_PREFIX_BYTES], bool);

impl SourceKey {
    fn of(addr: &SocketAddr) -> Self {
        match addr.ip() {
            IpAddr::V4(ip) => {
                let mut bytes = [0u8; IPV6_SOURCE_PREFIX_BYTES];
                bytes[..4].copy_from_slice(&ip.octets());
                Self(bytes, false)
            }
            IpAddr::V6(ip) => Self(
                ip.octets()[..IPV6_SOURCE_PREFIX_BYTES].try_into().unwrap(),
                true,
            ),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DropReason {
    SourceLimit,
    TableFull,
}

#[derive(Debug)]
pub enum Accepted {
    Duplicate,
    Incomplete,
    Complete(Vec<u8>),
    Dropped(DropReason),
}

pub struct Fragment<'a> {
    pub index: usize,
    pub offset: usize,
    pub data: &'a [u8],
}

struct Entry {
    buffer: Vec<u8>,
    received_mask: u64,
    age_rank: u64,
    last_progress_ms: u64,
    created_ms: u64,
}

impl Entry {
    fn complete_mask(&self, fragment_count: usize) -> u64 {
        if fragment_count == MAX_FRAGMENTS {
            u64::MAX
        } else {
            (1u64 << fragment_count) - 1
        }
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct TableCounters {
    pub created: u64,
    pub evictions: u64,
    pub timeouts: u64,
    pub watched_created: u64,
    pub watched_evictions: u64,
    pub watched_timeouts: u64,
    pub watched_dropped_table_full: u64,
    pub peak_entries: u64,
    pub peak_bytes: u64,
}

pub struct ReassemblyTable {
    config: TableConfig,
    entries: HashMap<EntryKey, Entry>,
    by_age: BTreeMap<u64, EntryKey>,
    per_source: HashMap<SourceKey, usize>,
    next_age_rank: u64,
    accounted_bytes: usize,
    last_sweep_ms: u64,
    counters: TableCounters,
    watched_source: Option<IpAddr>,
}

fn entry_cost(buffer_len: usize) -> usize {
    buffer_len + ENTRY_OVERHEAD_BYTES
}

impl ReassemblyTable {
    pub fn new(config: TableConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            by_age: BTreeMap::new(),
            per_source: HashMap::new(),
            next_age_rank: 0,
            accounted_bytes: 0,
            last_sweep_ms: 0,
            counters: TableCounters::default(),
            watched_source: None,
        }
    }

    pub fn watch_source(&mut self, ip: IpAddr) {
        self.watched_source = Some(ip);
    }

    fn is_watched(&self, key: &EntryKey) -> bool {
        self.watched_source == Some(key.addr.ip())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn accounted_bytes(&self) -> usize {
        self.accounted_bytes
    }

    pub fn counters(&self) -> TableCounters {
        self.counters
    }

    /// Age (ms) of the single oldest entry in the table, or 0 if empty.
    /// F2 (round 3 T3): used to validate that a sustained attacker keeps
    /// the table full enough that the oldest entry never gets old before
    /// being evicted or completing.
    pub fn oldest_entry_age_ms(&self, now_ms: u64) -> u64 {
        let Some((_, key)) = self.by_age.first_key_value() else {
            return 0;
        };
        let Some(entry) = self.entries.get(key) else {
            return 0;
        };
        now_ms.saturating_sub(entry.created_ms)
    }

    pub fn contains(&self, key: &EntryKey) -> bool {
        self.entries.contains_key(key)
    }

    pub fn entries_for_source(&self, addr: &SocketAddr) -> usize {
        self.per_source
            .get(&SourceKey::of(addr))
            .copied()
            .unwrap_or(0)
    }

    fn remove(&mut self, key: &EntryKey) -> Option<Entry> {
        let entry = self.entries.remove(key)?;
        self.by_age.remove(&entry.age_rank);
        self.accounted_bytes -= entry_cost(entry.buffer.len());
        let source = SourceKey::of(&key.addr);
        if let Some(count) = self.per_source.get_mut(&source) {
            *count -= 1;
            if *count == 0 {
                self.per_source.remove(&source);
            }
        }
        Some(entry)
    }

    pub fn sweep_if_due(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.last_sweep_ms) >= self.config.sweep_interval_ms {
            self.sweep(now_ms);
        }
    }

    pub fn sweep(&mut self, now_ms: u64) {
        self.last_sweep_ms = now_ms;
        let expired: Vec<EntryKey> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                now_ms.saturating_sub(e.last_progress_ms) > self.config.idle_timeout_ms
                    || now_ms.saturating_sub(e.created_ms) > self.config.max_lifetime_ms
            })
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            self.remove(&key);
            self.counters.timeouts += 1;
            self.counters.watched_timeouts += u64::from(self.is_watched(&key));
        }
    }

    fn has_room_for(&self, cost: usize) -> bool {
        self.entries.len() < self.config.max_entries
            && self.accounted_bytes + cost <= self.config.max_bytes
    }

    fn evict_oldest_if_old_enough(&mut self, now_ms: u64) -> bool {
        let Some((_, key)) = self.by_age.first_key_value() else {
            return false;
        };
        let key = *key;
        let age = now_ms.saturating_sub(self.entries[&key].created_ms);
        if age < self.config.evict_min_age_ms {
            return false;
        }
        self.remove(&key);
        self.counters.evictions += 1;
        self.counters.watched_evictions += u64::from(self.is_watched(&key));
        true
    }

    fn make_room(&mut self, cost: usize, now_ms: u64) -> bool {
        while !self.has_room_for(cost) {
            if !self.evict_oldest_if_old_enough(now_ms) {
                return false;
            }
        }
        true
    }

    fn insert_new(
        &mut self,
        key: EntryKey,
        buffer_len: usize,
        now_ms: u64,
    ) -> Result<(), DropReason> {
        if self.entries_for_source(&key.addr) >= self.config.max_entries_per_source {
            return Err(DropReason::SourceLimit);
        }
        let cost = entry_cost(buffer_len);
        if !self.make_room(cost, now_ms) {
            self.counters.watched_dropped_table_full += u64::from(self.is_watched(&key));
            return Err(DropReason::TableFull);
        }
        let age_rank = self.next_age_rank;
        self.next_age_rank += 1;
        self.by_age.insert(age_rank, key);
        self.entries.insert(
            key,
            Entry {
                buffer: vec![0u8; buffer_len],
                received_mask: 0,
                age_rank,
                last_progress_ms: now_ms,
                created_ms: now_ms,
            },
        );
        *self.per_source.entry(SourceKey::of(&key.addr)).or_insert(0) += 1;
        self.accounted_bytes += cost;
        self.counters.created += 1;
        self.counters.watched_created += u64::from(self.is_watched(&key));
        self.counters.peak_entries = self.counters.peak_entries.max(self.entries.len() as u64);
        self.counters.peak_bytes = self.counters.peak_bytes.max(self.accounted_bytes as u64);
        Ok(())
    }

    pub fn accept(
        &mut self,
        key: EntryKey,
        now_ms: u64,
        buffer_len: usize,
        fragment_count: usize,
        fragment: Fragment<'_>,
    ) -> Accepted {
        assert!(fragment_count <= MAX_FRAGMENTS);
        if !self.entries.contains_key(&key)
            && let Err(reason) = self.insert_new(key, buffer_len, now_ms)
        {
            return Accepted::Dropped(reason);
        }
        let entry = self.entries.get_mut(&key).unwrap();
        let bit = 1u64 << fragment.index;
        if entry.received_mask & bit != 0 {
            return Accepted::Duplicate;
        }
        entry.buffer[fragment.offset..fragment.offset + fragment.data.len()]
            .copy_from_slice(fragment.data);
        entry.received_mask |= bit;
        entry.last_progress_ms = now_ms;
        if entry.received_mask == entry.complete_mask(fragment_count) {
            let done = self.remove(&key).unwrap();
            return Accepted::Complete(done.buffer);
        }
        Accepted::Incomplete
    }
}
