use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};

use crate::error::OpcaError;

/// Supported datetime format styles, matching the Python `OutputFormat` type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateTimeFormat {
    /// X.509/CRL-friendly: `%Y%m%d%H%M%SZ` (e.g. `"20251231235959Z"`)
    Openssl,
    /// Human-readable: `%b %d %H:%M:%S %Y UTC` (e.g. `"Dec 31 23:59:59 2025 UTC"`)
    Text,
    /// Compact: `%H:%M %d %b %Y` (e.g. `"23:59 31 Dec 2025"`)
    Compact,
}

impl DateTimeFormat {
    fn strftime_pattern(self) -> &'static str {
        match self {
            DateTimeFormat::Openssl => "%Y%m%d%H%M%SZ",
            DateTimeFormat::Text => "%b %d %H:%M:%S %Y UTC",
            DateTimeFormat::Compact => "%H:%M %d %b %Y",
        }
    }
}

/// Format a UTC datetime using one of OPCA's canonical styles.
pub fn format_datetime(dt: DateTime<Utc>, fmt: DateTimeFormat) -> String {
    dt.format(fmt.strftime_pattern()).to_string()
}

/// Return the current UTC time.
pub fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

/// Return the current UTC time formatted as a string.
pub fn now_utc_str(fmt: DateTimeFormat) -> String {
    format_datetime(now_utc(), fmt)
}

/// Return the current UTC time plus the given offset.
pub fn now_utc_plus(
    days: i64,
    hours: i64,
    minutes: i64,
    seconds: i64,
) -> DateTime<Utc> {
    now_utc()
        + Duration::days(days)
        + Duration::hours(hours)
        + Duration::minutes(minutes)
        + Duration::seconds(seconds)
}

/// Parse a datetime string into a UTC-aware `DateTime<Utc>`.
pub fn parse_datetime(value: &str, fmt: DateTimeFormat) -> Result<DateTime<Utc>, OpcaError> {
    let pattern = fmt.strftime_pattern();
    let naive = NaiveDateTime::parse_from_str(value, pattern)
        .map_err(|e| OpcaError::Other(format!("Failed to parse datetime '{value}': {e}")))?;
    Ok(Utc.from_utc_datetime(&naive))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_openssl() {
        let dt = Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(
            format_datetime(dt, DateTimeFormat::Openssl),
            "20251231235959Z"
        );
    }

    #[test]
    fn test_format_text() {
        let dt = Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(
            format_datetime(dt, DateTimeFormat::Text),
            "Dec 31 23:59:59 2025 UTC"
        );
    }

    #[test]
    fn test_format_compact() {
        let dt = Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(
            format_datetime(dt, DateTimeFormat::Compact),
            "23:59 31 Dec 2025"
        );
    }

    #[test]
    fn test_parse_openssl() {
        let dt = parse_datetime("20251231235959Z", DateTimeFormat::Openssl).unwrap();
        assert_eq!(dt, Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap());
    }

    #[test]
    fn test_parse_text() {
        let dt = parse_datetime("Dec 31 23:59:59 2025 UTC", DateTimeFormat::Text).unwrap();
        assert_eq!(dt, Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap());
    }

    #[test]
    fn test_parse_compact() {
        let dt = parse_datetime("23:59 31 Dec 2025", DateTimeFormat::Compact).unwrap();
        // Compact format has no seconds — parsed as :00
        let expected = Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 0).unwrap();
        assert_eq!(dt, expected);
    }

    #[test]
    fn test_roundtrip_openssl() {
        let original = Utc.with_ymd_and_hms(2030, 6, 15, 12, 0, 0).unwrap();
        let s = format_datetime(original, DateTimeFormat::Openssl);
        let parsed = parse_datetime(&s, DateTimeFormat::Openssl).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_roundtrip_text() {
        let original = Utc.with_ymd_and_hms(2030, 6, 15, 12, 0, 0).unwrap();
        let s = format_datetime(original, DateTimeFormat::Text);
        let parsed = parse_datetime(&s, DateTimeFormat::Text).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_parse_invalid_returns_error() {
        let result = parse_datetime("not-a-date", DateTimeFormat::Openssl);
        assert!(result.is_err());
    }

    #[test]
    fn test_now_utc_str_openssl_format() {
        let s = now_utc_str(DateTimeFormat::Openssl);
        // Should end with 'Z' and be 15 chars long
        assert!(s.ends_with('Z'));
        assert_eq!(s.len(), 15);
    }

    #[test]
    fn test_now_utc_plus_adds_days() {
        let now = now_utc();
        let future = now_utc_plus(30, 0, 0, 0);
        let diff = future - now;
        // Should be approximately 30 days (within a second of tolerance)
        assert!(diff.num_days() >= 29 && diff.num_days() <= 30);
    }

    #[test]
    fn test_leap_year_date() {
        let dt = parse_datetime("20240229120000Z", DateTimeFormat::Openssl).unwrap();
        assert_eq!(dt, Utc.with_ymd_and_hms(2024, 2, 29, 12, 0, 0).unwrap());
    }

    #[test]
    fn test_epoch_date() {
        let dt = parse_datetime("19700101000000Z", DateTimeFormat::Openssl).unwrap();
        assert_eq!(dt, Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap());
    }
}
