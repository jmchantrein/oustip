//! Common utility functions used across modules.
//!
//! This module provides shared formatting and utility functions:
//! - [`format_bytes`] - Format byte sizes (KB, MB, GB)
//! - [`format_count`] - Format counts with K/M suffix (1.5K, 2.3M)
//! - [`format_count_with_separator`] - Format counts with thousands separator (1,234,567)
//! - [`truncate`] - Truncate strings with ellipsis

/// Format a count with K/M suffix for compact display.
///
/// # Examples
/// ```
/// use oustip::utils::format_count;
/// assert_eq!(format_count(500), "500");
/// assert_eq!(format_count(1500), "1.5K");
/// assert_eq!(format_count(1_500_000), "1.5M");
/// ```
pub fn format_count(count: usize) -> String {
    if count >= 1_000_000 {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{:.1}K", count as f64 / 1_000.0)
    } else {
        count.to_string()
    }
}

/// Format a number with thousands separators (commas).
///
/// # Examples
/// ```
/// use oustip::utils::format_count_with_separator;
/// assert_eq!(format_count_with_separator(1000), "1,000");
/// assert_eq!(format_count_with_separator(1234567), "1,234,567");
/// ```
pub fn format_count_with_separator(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Format bytes in human-readable form (KB, MB, GB).
///
/// # Examples
/// ```
/// use oustip::utils::format_bytes;
/// assert_eq!(format_bytes(1024), "1.0 KB");
/// assert_eq!(format_bytes(1_500_000), "1.4 MB");
/// ```
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Truncate a string to a maximum length, adding "..." if truncated.
///
/// # Examples
/// ```
/// use oustip::utils::truncate;
/// assert_eq!(truncate("short", 10), "short");
/// assert_eq!(truncate("this is long", 10), "this is...");
/// ```
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        "...".to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_count() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(500), "500");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1000), "1.0K");
        assert_eq!(format_count(1500), "1.5K");
        assert_eq!(format_count(999_999), "1000.0K");
        assert_eq!(format_count(1_000_000), "1.0M");
        assert_eq!(format_count(1_500_000), "1.5M");
    }

    #[test]
    fn test_format_count_with_separator() {
        assert_eq!(format_count_with_separator(0), "0");
        assert_eq!(format_count_with_separator(5), "5");
        assert_eq!(format_count_with_separator(42), "42");
        assert_eq!(format_count_with_separator(999), "999");
        assert_eq!(format_count_with_separator(1000), "1,000");
        assert_eq!(format_count_with_separator(1234), "1,234");
        assert_eq!(format_count_with_separator(9999), "9,999");
        assert_eq!(format_count_with_separator(10000), "10,000");
        assert_eq!(format_count_with_separator(12345), "12,345");
        assert_eq!(format_count_with_separator(99999), "99,999");
        assert_eq!(format_count_with_separator(100000), "100,000");
        assert_eq!(format_count_with_separator(123456), "123,456");
        assert_eq!(format_count_with_separator(1000000), "1,000,000");
        assert_eq!(format_count_with_separator(1234567), "1,234,567");
        assert_eq!(format_count_with_separator(1000000000), "1,000,000,000");
        assert_eq!(format_count_with_separator(1234567890), "1,234,567,890");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1500), "1.5 KB");
        assert_eq!(format_bytes(1_500_000), "1.4 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.4 GB");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is a long string", 10), "this is...");
        assert_eq!(truncate("exactly10!", 10), "exactly10!");
        assert_eq!(truncate("test", 3), "...");
    }
}
