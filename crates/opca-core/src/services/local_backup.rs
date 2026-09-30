//! Rolling local copies of the CA database, written on every save so a bad
//! 1Password write can be undone without the private store.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::OpcaError;
use crate::op::{CommandRunner, Op};
use crate::services::database::CertificateAuthorityDB;
use crate::settings;
use crate::utils::files::write_bytes;

pub const KEEP_LOCAL_BACKUPS: usize = 30;

const FILE_PREFIX: &str = "ca-database-";
const UNREADABLE_SUFFIX: &str = "-unreadable";
const HEADER_PREFIX: &str = "-- opca-backup ";
const TIMESTAMP_FORMAT: &str = "%Y%m%dT%H%M%SZ";

/// Which vault a backup came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSource {
    pub vault: String,
    pub vault_id: Option<String>,
}

impl BackupSource {
    pub fn of<R: CommandRunner>(op: &Op<R>) -> Self {
        Self {
            vault: op.vault.clone(),
            vault_id: op.vault_id.clone(),
        }
    }

    fn dir_name(&self) -> String {
        path_safe(&match &self.vault_id {
            Some(id) => id.clone(),
            None => format!("name-{}", self.vault.trim().to_lowercase()),
        })
    }
}

/// The backup file's first line, as a SQL comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Header {
    account: String,
    #[serde(flatten)]
    source: BackupSource,
    taken_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupEntry {
    pub path: PathBuf,
    pub taken_at: DateTime<Utc>,
    pub size: u64,
    pub source: Option<BackupSource>,
    /// `None` when the backup itself cannot be loaded.
    pub cert_count: Option<i64>,
}

/// One 1Password account's backups: `<root>/<account key>/<vault id>/`.
#[derive(Debug, Clone)]
pub struct LocalBackup {
    root: PathBuf,
    account: String,
    keep: usize,
}

impl LocalBackup {
    pub fn new(root: impl Into<PathBuf>, account_key: impl Into<String>, keep: usize) -> Self {
        Self { root: root.into(), account: account_key.into(), keep }
    }

    /// The store for `account` under the settings directory, keyed like the
    /// rest of the settings so any alias of an account finds the same backups.
    pub fn for_account(account: Option<&str>) -> Result<Self, OpcaError> {
        Ok(Self::new(settings::backups_dir()?, settings::account_key(account), KEEP_LOCAL_BACKUPS))
    }

    /// [`Self::for_account`] when automatic backups are switched on.
    pub fn if_enabled(account: Option<&str>) -> Option<Self> {
        if !settings::local_backup_enabled() {
            return None;
        }
        Self::for_account(account)
            .map_err(|e| log::warn!("[backup] no local backup directory: {e}"))
            .ok()
    }

    pub fn dir_for(&self, source: &BackupSource) -> PathBuf {
        self.root.join(path_safe(&self.account)).join(source.dir_name())
    }

    /// Write a backup unless it matches the newest one; returns the new file.
    pub fn write(&self, source: &BackupSource, sql: &str) -> Result<Option<PathBuf>, OpcaError> {
        let newest = self.backup_files(source)?.into_iter().last();
        if let Some(newest) = newest {
            if fs::read_to_string(&newest).is_ok_and(|prev| strip_header(&prev) == sql) {
                return Ok(None);
            }
        }
        let path = self.write_file(source, sql, "")?;
        self.prune(source)?;
        Ok(Some(path))
    }

    /// Keep an unreadable 1Password copy for inspection; never pruned or listed.
    pub fn write_unreadable(&self, source: &BackupSource, sql: &str) -> Result<PathBuf, OpcaError> {
        self.write_file(source, sql, UNREADABLE_SUFFIX)
    }

    /// Backups for this vault, newest first.
    pub fn list(&self, source: &BackupSource) -> Result<Vec<BackupEntry>, OpcaError> {
        let mut entries = self
            .backup_files(source)?
            .into_iter()
            .filter_map(|path| read_entry(&path))
            .collect::<Vec<_>>();
        entries.reverse();
        Ok(entries)
    }

    /// True when `path` is a backup file belonging to `source`'s directory.
    pub fn owns(&self, source: &BackupSource, path: &Path) -> bool {
        let dir = self.dir_for(source);
        match (fs::canonicalize(path), fs::canonicalize(&dir)) {
            (Ok(path), Ok(dir)) => path.parent() == Some(dir.as_path()) && backup_time(&path).is_some(),
            _ => false,
        }
    }

    fn write_file(&self, source: &BackupSource, sql: &str, suffix: &str) -> Result<PathBuf, OpcaError> {
        let taken_at = Utc::now();
        let header = Header { account: self.account.clone(), source: source.clone(), taken_at };
        let header_json = serde_json::to_string(&header)
            .map_err(|e| OpcaError::Other(format!("backup header: {e}")))?;
        let name = format!("{FILE_PREFIX}{}{suffix}.sql", taken_at.format(TIMESTAMP_FORMAT));
        let contents = format!("{HEADER_PREFIX}{header_json}\n{sql}");
        write_bytes(self.dir_for(source).join(name), contents.as_bytes(), true, true, true, 0o600)
    }

    /// Regular (non-unreadable) backup files, oldest first.
    fn backup_files(&self, source: &BackupSource) -> Result<Vec<PathBuf>, OpcaError> {
        let dir = self.dir_for(source);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut files: Vec<PathBuf> = fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| backup_time(p).is_some())
            .collect();
        files.sort();
        Ok(files)
    }

    fn prune(&self, source: &BackupSource) -> Result<(), OpcaError> {
        let files = self.backup_files(source)?;
        let excess = files.len().saturating_sub(self.keep);
        for old in &files[..excess] {
            fs::remove_file(old)?;
        }
        Ok(())
    }
}

/// The dump without the backup header line, ready for 1Password or import.
pub fn strip_header(contents: &str) -> &str {
    match contents.strip_prefix(HEADER_PREFIX) {
        Some(rest) => rest.split_once('\n').map_or("", |(_, sql)| sql),
        None => contents,
    }
}

pub fn read_source(contents: &str) -> Option<BackupSource> {
    let line = contents.strip_prefix(HEADER_PREFIX)?.lines().next()?;
    serde_json::from_str::<Header>(line).ok().map(|h| h.source)
}

/// "just now", "5 minutes ago", "3 days ago".
pub fn age_phrase(taken_at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let secs = (now - taken_at).num_seconds().max(0);
    let (n, unit) = match secs {
        0..=59 => return "just now".into(),
        60..=3599 => (secs / 60, "minute"),
        3600..=86_399 => (secs / 3600, "hour"),
        _ => (secs / 86_400, "day"),
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

fn read_entry(path: &Path) -> Option<BackupEntry> {
    let taken_at = backup_time(path)?;
    let contents = fs::read_to_string(path).ok()?;
    let cert_count = CertificateAuthorityDB::from_sql_dump(strip_header(&contents))
        .ok()
        .and_then(|(db, _)| db.count_certs().ok());
    Some(BackupEntry {
        path: path.to_path_buf(),
        taken_at,
        size: contents.len() as u64,
        source: read_source(&contents),
        cert_count,
    })
}

/// When the backup was taken, from its filename rather than its mtime,
/// which copying or syncing the folder would change.
fn backup_time(path: &Path) -> Option<DateTime<Utc>> {
    let stamp = path
        .file_name()?
        .to_str()?
        .strip_prefix(FILE_PREFIX)?
        .strip_suffix(".sql")?;
    NaiveDateTime::parse_from_str(stamp, TIMESTAMP_FORMAT)
        .ok()
        .map(|t| t.and_utc())
}

fn path_safe(segment: &str) -> String {
    let cleaned: String = segment
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "-_.".contains(c) { c } else { '_' })
        .collect();
    match cleaned.trim_start_matches('.') {
        "" => "_".to_string(),
        safe => safe.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(vault_id: &str) -> BackupSource {
        BackupSource { vault: "CA Xentro".into(), vault_id: Some(vault_id.into()) }
    }

    fn store(root: &Path, keep: usize) -> LocalBackup {
        LocalBackup::new(root, "user-uuid", keep)
    }

    fn backup_files(dir: &Path) -> Vec<PathBuf> {
        let mut files: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
        files.sort();
        files
    }

    fn seed(backup: &LocalBackup, src: &BackupSource, stamps: &[&str]) {
        let dir = backup.dir_for(src);
        fs::create_dir_all(&dir).unwrap();
        for stamp in stamps {
            fs::write(dir.join(format!("{FILE_PREFIX}{stamp}.sql")), format!("-- {stamp}\n")).unwrap();
        }
    }

    #[test]
    fn write_records_source_and_keeps_dump_loadable() {
        let root = tempfile::tempdir().unwrap();
        let backup = store(root.path(), 5);
        let src = source("abc123");

        let path = backup.write(&src, "BEGIN TRANSACTION;\nCOMMIT;\n").unwrap().unwrap();
        let contents = fs::read_to_string(&path).unwrap();

        assert_eq!(read_source(&contents), Some(src.clone()));
        assert_eq!(strip_header(&contents), "BEGIN TRANSACTION;\nCOMMIT;\n");
        assert_eq!(path.parent().unwrap(), root.path().join("user-uuid").join("abc123"));
    }

    #[test]
    fn write_skips_dump_identical_to_newest() {
        let root = tempfile::tempdir().unwrap();
        let backup = store(root.path(), 5);
        let src = source("abc123");

        assert!(backup.write(&src, "same").unwrap().is_some());
        assert!(backup.write(&src, "same").unwrap().is_none());
        assert_eq!(backup_files(&backup.dir_for(&src)).len(), 1);
    }

    #[test]
    fn write_prunes_to_newest_keep() {
        let root = tempfile::tempdir().unwrap();
        let backup = store(root.path(), 2);
        let src = source("abc123");
        seed(&backup, &src, &["20200101T000000Z", "20200102T000000Z", "20200103T000000Z"]);

        backup.write(&src, "new").unwrap();

        let files = backup_files(&backup.dir_for(&src));
        assert_eq!(files.len(), 2);
        assert!(files[0].ends_with(format!("{FILE_PREFIX}20200103T000000Z.sql")));
    }

    #[test]
    fn unreadable_copies_are_neither_listed_nor_pruned() {
        let root = tempfile::tempdir().unwrap();
        let backup = store(root.path(), 1);
        let src = source("abc123");

        backup.write_unreadable(&src, "BEGIN TRANSACTION;").unwrap();
        backup.write(&src, "a").unwrap();

        assert_eq!(backup.list(&src).unwrap().len(), 1);
        assert_eq!(backup_files(&backup.dir_for(&src)).len(), 2);
    }

    #[test]
    fn list_is_newest_first_with_age_from_filename() {
        let root = tempfile::tempdir().unwrap();
        let backup = store(root.path(), 5);
        let src = source("abc123");
        seed(&backup, &src, &["20260101T000000Z", "20260929T235739Z"]);

        let entries = backup.list(&src).unwrap();

        assert_eq!(entries[0].taken_at.to_rfc3339(), "2026-09-29T23:57:39+00:00");
        assert_eq!(entries[1].taken_at.to_rfc3339(), "2026-01-01T00:00:00+00:00");
        assert_eq!(entries[0].cert_count, None);
    }

    #[test]
    fn age_phrase_picks_the_largest_whole_unit() {
        let now = Utc::now();
        assert_eq!(age_phrase(now, now), "just now");
        assert_eq!(age_phrase(now - chrono::Duration::minutes(1), now), "1 minute ago");
        assert_eq!(age_phrase(now - chrono::Duration::hours(10), now), "10 hours ago");
        assert_eq!(age_phrase(now - chrono::Duration::days(3), now), "3 days ago");
    }

    #[test]
    fn vaults_sharing_a_name_get_separate_directories() {
        let backup = store(Path::new("/backups"), 5);
        assert_ne!(backup.dir_for(&source("aaa")), backup.dir_for(&source("bbb")));
    }

    #[test]
    fn vault_without_id_falls_back_to_safe_name() {
        let backup = store(Path::new("/backups"), 5);
        let src = BackupSource { vault: "../CA X".into(), vault_id: None };
        assert_eq!(backup.dir_for(&src), PathBuf::from("/backups/user-uuid/name-.._ca_x"));
    }

    #[test]
    fn owns_rejects_paths_outside_the_vault_directory() {
        let root = tempfile::tempdir().unwrap();
        let backup = store(root.path(), 5);
        let path = backup.write(&source("aaa"), "x").unwrap().unwrap();

        assert!(backup.owns(&source("aaa"), &path));
        assert!(!backup.owns(&source("bbb"), &path));
    }
}
