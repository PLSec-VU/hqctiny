use std::sync::Mutex;

pub const STATS_QUERY: &[u8] = b"HQCLETHE_STATEFUL_STATS_QUERY_V1";
pub const RESPONSES_ONLY_QUERY: &[u8] = b"HQCLETHE_FLOOD_STATS_QUERY_V1";

#[derive(Default, Debug, Clone, Copy)]
pub struct Stats {
    pub responses_sent: u64,
    pub hellos_answered: u64,
    pub fragments_accepted: u64,
    pub fragments_duplicate: u64,
    pub rejected_malformed: u64,
    pub rejected_cookie: u64,
    pub dropped_source_limit: u64,
    pub dropped_table_full: u64,
    pub encaps_completed: u64,
    pub encaps_failed: u64,
    pub auth_proofs: u64,
    pub rejected_auth: u64,
    pub rejected_ae: u64,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct StatsSnapshot {
    pub stats: Stats,
    pub table_entries: u64,
    pub table_bytes: u64,
    pub evictions: u64,
    pub timeouts: u64,
    pub peak_entries: u64,
    pub peak_bytes: u64,
    pub entries_created: u64,
    pub watched_created: u64,
    pub watched_evictions: u64,
    pub watched_timeouts: u64,
    pub oldest_entry_age_ms: u64,
}

impl Stats {
    fn add(&mut self, other: &Stats) {
        self.responses_sent += other.responses_sent;
        self.hellos_answered += other.hellos_answered;
        self.fragments_accepted += other.fragments_accepted;
        self.fragments_duplicate += other.fragments_duplicate;
        self.rejected_malformed += other.rejected_malformed;
        self.rejected_cookie += other.rejected_cookie;
        self.dropped_source_limit += other.dropped_source_limit;
        self.dropped_table_full += other.dropped_table_full;
        self.encaps_completed += other.encaps_completed;
        self.encaps_failed += other.encaps_failed;
        self.auth_proofs += other.auth_proofs;
        self.rejected_auth += other.rejected_auth;
        self.rejected_ae += other.rejected_ae;
    }
}

impl StatsSnapshot {
    /// Adds the snapshot of another shard. The peaks become the sum of the
    /// shard peaks, which is an upper bound on the true peak of the union.
    pub fn add_shard(&mut self, other: &StatsSnapshot) {
        self.stats.add(&other.stats);
        self.table_entries += other.table_entries;
        self.table_bytes += other.table_bytes;
        self.evictions += other.evictions;
        self.timeouts += other.timeouts;
        self.peak_entries += other.peak_entries;
        self.peak_bytes += other.peak_bytes;
        self.entries_created += other.entries_created;
        self.watched_created += other.watched_created;
        self.watched_evictions += other.watched_evictions;
        self.watched_timeouts += other.watched_timeouts;
        self.oldest_entry_age_ms = self.oldest_entry_age_ms.max(other.oldest_entry_age_ms);
    }

    pub fn to_probe_bytes(&self) -> Vec<u8> {
        let s = &self.stats;
        [
            s.responses_sent,
            s.hellos_answered,
            s.fragments_accepted,
            s.fragments_duplicate,
            s.rejected_malformed,
            s.rejected_cookie,
            s.dropped_source_limit,
            s.dropped_table_full,
            s.encaps_completed,
            s.encaps_failed,
            s.auth_proofs,
            s.rejected_auth,
            self.table_entries,
            self.table_bytes,
            self.evictions,
            self.timeouts,
            self.peak_entries,
            self.peak_bytes,
            self.entries_created,
            self.watched_created,
            self.watched_evictions,
            self.watched_timeouts,
            self.oldest_entry_age_ms,
            s.rejected_ae,
        ]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect()
    }

    pub const FIELD_NAMES: [&'static str; 24] = [
        "responses_sent",
        "hellos_answered",
        "fragments_accepted",
        "fragments_duplicate",
        "rejected_malformed",
        "rejected_cookie",
        "dropped_source_limit",
        "dropped_table_full",
        "encaps_completed",
        "encaps_failed",
        "auth_proofs",
        "rejected_auth",
        "table_entries",
        "table_bytes",
        "evictions",
        "timeouts",
        "peak_entries",
        "peak_bytes",
        "entries_created",
        "watched_created",
        "watched_evictions",
        "watched_timeouts",
        "oldest_entry_age_ms",
        "rejected_ae",
    ];
}

/// The latest snapshot of each shard, so that any shard can answer a stats
/// probe with the totals over all shards.
pub struct StatsBoard {
    shards: Vec<Mutex<StatsSnapshot>>,
}

impl StatsBoard {
    pub fn new(shard_count: usize) -> Self {
        Self {
            shards: (0..shard_count).map(|_| Mutex::default()).collect(),
        }
    }

    pub fn publish(&self, shard: usize, snapshot: StatsSnapshot) {
        *self.shards[shard].lock().unwrap() = snapshot;
    }

    pub fn total(&self) -> StatsSnapshot {
        let mut total = StatsSnapshot::default();
        for shard in &self.shards {
            total.add_shard(&shard.lock().unwrap());
        }
        total
    }
}
