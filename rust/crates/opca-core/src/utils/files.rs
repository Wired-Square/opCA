use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::error::OpcaError;

/// A parsed entry from a bulk certificate file.
#[derive(Debug, Clone)]
pub struct BulkEntry {
    pub cn: String,
    pub alt_dns_names: Option<Vec<String>>,
}

/// Read a file as bytes with path expansion (`~` and env vars).
pub fn read_bytes(path: impl AsRef<Path>) -> Result<Vec<u8>, OpcaError> {
    let file_path = expand_path(path.as_ref());
    fs::read(&file_path).map_err(|e| {
        OpcaError::Io(format!("Failed to read '{}': {e}", file_path.display()))
    })
}

/// Write bytes to a file with optional atomic replacement and permission setting.
///
/// - `overwrite`: if `false` and the file exists, returns an error.
/// - `create_dirs`: create parent directories if needed.
/// - `atomic`: write to a temp file in the same directory, fsync, then replace.
/// - `mode`: Unix permission mode (default `0o600`).
pub fn write_bytes(
    path: impl AsRef<Path>,
    data: &[u8],
    overwrite: bool,
    create_dirs: bool,
    atomic: bool,
    #[cfg_attr(not(unix), allow(unused_variables))]
    mode: u32,
) -> Result<PathBuf, OpcaError> {
    let file_path = expand_path(path.as_ref());
    let parent = file_path
        .parent()
        .ok_or_else(|| OpcaError::Io(format!("No parent directory for '{}'", file_path.display())))?;

    if file_path.exists() && !overwrite {
        return Err(OpcaError::Io(format!(
            "File '{}' already exists. Aborting.",
            file_path.display()
        )));
    }

    if create_dirs {
        fs::create_dir_all(parent)?;
    }

    if !atomic {
        fs::write(&file_path, data)?;
        #[cfg(unix)]
        fs::set_permissions(&file_path, fs::Permissions::from_mode(mode))?;
        return Ok(file_path);
    }

    // Atomic write: temp file in same dir → fsync → replace → fsync dir
    let tmp = tempfile::NamedTempFile::new_in(parent)?;
    fs::write(tmp.path(), data)?;
    tmp.as_file().sync_all()?;

    #[cfg(unix)]
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode))?;

    let tmp_path = tmp.into_temp_path();
    tmp_path.persist(&file_path).map_err(|e| {
        OpcaError::Io(format!(
            "Failed to persist temp file to '{}': {e}",
            file_path.display()
        ))
    })?;

    // fsync the containing directory so the rename is durable
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(file_path)
}

/// Parse a bulk certificate file.
///
/// Each non-empty, non-comment line has the format:
/// ```text
/// CN [--alt alt1] [--alt alt2] ...
/// ```
pub fn parse_bulk_file(path: impl AsRef<Path>) -> Result<Vec<BulkEntry>, OpcaError> {
    let data = read_bytes(path)?;
    let text = String::from_utf8(data)
        .map_err(|e| OpcaError::Io(format!("Invalid UTF-8 in bulk file: {e}")))?;

    let mut entries = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split("--alt").collect();
        let cn = parts[0].trim().to_string();
        let alt_dns_names = if parts.len() > 1 {
            let names: Vec<String> = parts[1..]
                .iter()
                .map(|p| p.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if names.is_empty() {
                None
            } else {
                Some(names)
            }
        } else {
            None
        };

        entries.push(BulkEntry { cn, alt_dns_names });
    }

    Ok(entries)
}

/// Expand `~` and environment variables in a path.
fn expand_path(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with('~') {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(s.strip_prefix("~/").unwrap_or(&s[1..]));
        }
    }
    PathBuf::from(shellexpand::tilde(&s).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_bytes_nonexistent() {
        let result = read_bytes("/tmp/opca_test_nonexistent_file_xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_write_and_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        let data = b"hello world";

        write_bytes(&path, data, false, false, true, 0o600).unwrap();
        let read = read_bytes(&path).unwrap();
        assert_eq!(read, data);

        // Verify permissions
        #[cfg(unix)]
        {
            let meta = fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_write_no_overwrite_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");

        write_bytes(&path, b"first", false, false, true, 0o600).unwrap();
        let result = write_bytes(&path, b"second", false, false, true, 0o600);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_overwrite_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");

        write_bytes(&path, b"first", false, false, true, 0o600).unwrap();
        write_bytes(&path, b"second", true, false, true, 0o600).unwrap();

        let data = read_bytes(&path).unwrap();
        assert_eq!(data, b"second");
    }

    #[test]
    fn test_write_create_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("dir").join("test.txt");

        write_bytes(&path, b"hello", false, true, true, 0o600).unwrap();
        let data = read_bytes(&path).unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_write_non_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");

        write_bytes(&path, b"data", false, false, false, 0o644).unwrap();
        let data = read_bytes(&path).unwrap();
        assert_eq!(data, b"data");

        #[cfg(unix)]
        {
            let meta = fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o644);
        }
    }

    #[test]
    fn test_parse_bulk_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bulk.txt");
        let content = b"# comment\nserver.example.com\nclient.example.com --alt client1.example.com --alt client2.example.com\n\n";
        write_bytes(&path, content, false, false, false, 0o600).unwrap();

        let entries = parse_bulk_file(&path).unwrap();
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].cn, "server.example.com");
        assert!(entries[0].alt_dns_names.is_none());

        assert_eq!(entries[1].cn, "client.example.com");
        let alts = entries[1].alt_dns_names.as_ref().unwrap();
        assert_eq!(alts.len(), 2);
        assert_eq!(alts[0], "client1.example.com");
        assert_eq!(alts[1], "client2.example.com");
    }

    #[test]
    fn test_parse_bulk_file_skips_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bulk.txt");
        let content = b"# header comment\n\n  # another\nonly.example.com\n  \n";
        write_bytes(&path, content, false, false, false, 0o600).unwrap();

        let entries = parse_bulk_file(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cn, "only.example.com");
    }
}
