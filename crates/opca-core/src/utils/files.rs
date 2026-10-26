use std::fs;
use std::path::{Path, PathBuf};

use wslib_file_atomic::{Options, Readers};

use crate::error::OpcaError;

/// A parsed entry from a bulk certificate file.
#[derive(Debug, Clone)]
pub struct BulkEntry {
    pub cn: String,
    pub alt_names: Option<Vec<String>>,
}

/// Read a file as bytes with path expansion (`~` and env vars).
pub fn read_bytes(path: impl AsRef<Path>) -> Result<Vec<u8>, OpcaError> {
    let file_path = expand_path(path.as_ref());
    fs::read(&file_path).map_err(|e| {
        OpcaError::Io(format!("Failed to read '{}': {e}", file_path.display()))
    })
}

/// Write bytes to a file, whole or not at all, readable by `readers` from creation.
///
/// - `overwrite`: if `false` and the file exists, returns an error.
/// - `create_dirs`: create parent directories if needed.
pub fn write_bytes(
    path: impl AsRef<Path>,
    data: &[u8],
    overwrite: bool,
    create_dirs: bool,
    readers: Readers,
) -> Result<PathBuf, OpcaError> {
    let file_path = expand_path(path.as_ref());
    Options::new()
        .readers(readers)
        .create_new(!overwrite)
        .create_parents(create_dirs)
        .write(&file_path, data)
        .map_err(|e| OpcaError::Io(format!("Failed to write '{}': {e}", file_path.display())))?;
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
        let alt_names = if parts.len() > 1 {
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

        entries.push(BulkEntry { cn, alt_names });
    }

    Ok(entries)
}

/// Expand `~` and environment variables in a path.
fn expand_path(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with('~')
        && let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(s.strip_prefix("~/").unwrap_or(&s[1..]));
        }
    PathBuf::from(shellexpand::tilde(&s).into_owned())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

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

        write_bytes(&path, data, false, false, Readers::Private).unwrap();
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

        write_bytes(&path, b"first", false, false, Readers::Private).unwrap();
        let result = write_bytes(&path, b"second", false, false, Readers::Private);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_overwrite_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");

        write_bytes(&path, b"first", false, false, Readers::Private).unwrap();
        write_bytes(&path, b"second", true, false, Readers::Private).unwrap();

        let data = read_bytes(&path).unwrap();
        assert_eq!(data, b"second");
    }

    #[test]
    fn test_write_create_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("dir").join("test.txt");

        write_bytes(&path, b"hello", false, true, Readers::Private).unwrap();
        let data = read_bytes(&path).unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_write_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");

        write_bytes(&path, b"data", false, false, Readers::Readable).unwrap();
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
        write_bytes(&path, content, false, false, Readers::Private).unwrap();

        let entries = parse_bulk_file(&path).unwrap();
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].cn, "server.example.com");
        assert!(entries[0].alt_names.is_none());

        assert_eq!(entries[1].cn, "client.example.com");
        let alts = entries[1].alt_names.as_ref().unwrap();
        assert_eq!(alts.len(), 2);
        assert_eq!(alts[0], "client1.example.com");
        assert_eq!(alts[1], "client2.example.com");
    }

    #[test]
    fn test_parse_bulk_file_skips_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bulk.txt");
        let content = b"# header comment\n\n  # another\nonly.example.com\n  \n";
        write_bytes(&path, content, false, false, Readers::Private).unwrap();

        let entries = parse_bulk_file(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cn, "only.example.com");
    }
}
