pub const DEFAULT_COOKIE_LIFETIME_MS: u64 = 30_000;
pub const DEFAULT_KEY_ROTATION_MS: u64 = 30_000;
pub const DEFAULT_MAX_ENTRIES: usize = 1024;
pub const DEFAULT_MAX_TABLE_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_ENTRIES_PER_SOURCE: usize = 4;
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 3_000;
pub const DEFAULT_MAX_LIFETIME_MS: u64 = 10_000;
pub const DEFAULT_EVICT_MIN_AGE_MS: u64 = 1_000;
pub const DEFAULT_SWEEP_INTERVAL_MS: u64 = 250;

#[derive(Clone, Debug)]
pub struct TableConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub max_entries_per_source: usize,
    pub idle_timeout_ms: u64,
    pub max_lifetime_ms: u64,
    pub evict_min_age_ms: u64,
    pub sweep_interval_ms: u64,
}

impl Default for TableConfig {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_TABLE_BYTES,
            max_entries_per_source: DEFAULT_MAX_ENTRIES_PER_SOURCE,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
            max_lifetime_ms: DEFAULT_MAX_LIFETIME_MS,
            evict_min_age_ms: DEFAULT_EVICT_MIN_AGE_MS,
            sweep_interval_ms: DEFAULT_SWEEP_INTERVAL_MS,
        }
    }
}

impl TableConfig {
    /// The budget of one of `shard_count` tables that together hold the
    /// budget of `self`. The limit per source stays the same in each shard.
    pub fn shard(&self, shard_count: usize) -> Self {
        Self {
            max_entries: (self.max_entries / shard_count).max(1),
            max_bytes: self.max_bytes / shard_count,
            ..self.clone()
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub cookie_lifetime_ms: u64,
    pub key_rotation_ms: u64,
    pub table: TableConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            cookie_lifetime_ms: DEFAULT_COOKIE_LIFETIME_MS,
            key_rotation_ms: DEFAULT_KEY_ROTATION_MS,
            table: TableConfig::default(),
        }
    }
}
