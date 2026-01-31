//! Connectivity tests - verify external service availability.
//!
//! These tests check that oustip can reach the blocklist sources and
//! other external services it depends on.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::config::Config;

use super::output::{DiagnosticResult, Severity, TestCategory};

/// Run all connectivity tests
pub async fn run_tests(config_path: &Path) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();

    // Load config
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(_) => {
            results.push(DiagnosticResult::skip(
                "connectivity_all",
                "Connectivity tests",
                TestCategory::Connectivity,
                "Config file could not be loaded (see smoke tests)",
            ));
            return results;
        }
    };

    // Test basic internet connectivity
    results.push(test_internet_connectivity().await);

    // Test DNS resolution
    results.push(test_dns_resolution().await);

    // Test blocklist source connectivity (sample)
    let enabled_lists = config.get_enabled_blocklists(None);
    if !enabled_lists.is_empty() {
        // Test first enabled blocklist as a sample
        let sample_list = enabled_lists[0];
        results.push(test_blocklist_source(&sample_list.name, &sample_list.url).await);
    }

    // Test CDN allowlist sources if enabled
    if config.auto_allowlist.cloudflare {
        results.push(test_cdn_source("Cloudflare", "https://www.cloudflare.com/ips-v4").await);
    }

    if config.auto_allowlist.github {
        results.push(test_cdn_source("GitHub", "https://api.github.com/meta").await);
    }

    results
}

/// Test: Basic internet connectivity
async fn test_internet_connectivity() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "connectivity_internet";
    let test_name = "Internet connectivity";

    // Try to reach a reliable endpoint
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return DiagnosticResult::fail(
                test_id,
                test_name,
                TestCategory::Connectivity,
                Severity::Critical,
                "Cannot create HTTP client",
                "HTTP client should initialize",
                &e.to_string(),
                "Failed to create the HTTP client. This is an internal error.",
                "This is unusual - check system TLS configuration and available memory.",
                start.elapsed().as_millis() as u64,
            );
        }
    };

    // Try multiple endpoints for reliability
    let endpoints = [
        "https://www.google.com",
        "https://www.cloudflare.com",
        "https://github.com",
    ];

    for endpoint in &endpoints {
        match client.head(*endpoint).send().await {
            Ok(resp) if resp.status().is_success() || resp.status().is_redirection() => {
                return DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Connectivity,
                    &format!("Internet reachable (tested: {})", endpoint),
                    start.elapsed().as_millis() as u64,
                );
            }
            _ => continue,
        }
    }

    DiagnosticResult::fail(
        test_id,
        test_name,
        TestCategory::Connectivity,
        Severity::Critical,
        "No internet connectivity",
        "At least one endpoint reachable",
        "All test endpoints unreachable",
        "Cannot reach any of the test endpoints (google.com, cloudflare.com, github.com). \
         This could indicate no internet connection, DNS issues, or firewall blocking.",
        "Check network connectivity with 'ping 8.8.8.8'. If ping works but HTTPS doesn't, \
         check firewall rules for outgoing HTTPS (port 443). Ensure DNS is configured correctly.",
        start.elapsed().as_millis() as u64,
    )
}

/// Test: DNS resolution
async fn test_dns_resolution() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "connectivity_dns";
    let test_name = "DNS resolution";

    // Try to resolve a reliable domain
    let test_domains = ["google.com", "cloudflare.com", "github.com"];

    for domain in &test_domains {
        match tokio::net::lookup_host(format!("{}:443", domain)).await {
            Ok(mut addrs) => {
                if addrs.next().is_some() {
                    return DiagnosticResult::pass(
                        test_id,
                        test_name,
                        TestCategory::Connectivity,
                        &format!("DNS working (resolved: {})", domain),
                        start.elapsed().as_millis() as u64,
                    );
                }
            }
            Err(_) => continue,
        }
    }

    DiagnosticResult::fail(
        test_id,
        test_name,
        TestCategory::Connectivity,
        Severity::Critical,
        "DNS resolution failed",
        "At least one domain resolvable",
        "Could not resolve any test domains",
        "DNS resolution is not working. Cannot resolve google.com, cloudflare.com, or github.com. \
         This will prevent oustip from fetching blocklists.",
        "Check DNS configuration in /etc/resolv.conf. Try 'nslookup google.com' to test DNS. \
         Consider using public DNS servers like 8.8.8.8 or 1.1.1.1.",
        start.elapsed().as_millis() as u64,
    )
}

/// Test: Blocklist source connectivity
async fn test_blocklist_source(name: &str, url: &str) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = format!("connectivity_blocklist_{}", name.replace([' ', '-'], "_"));
    let test_name = format!("Blocklist source: {}", name);

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(format!("oustip-diagnose/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return DiagnosticResult::fail(
                &test_id,
                &test_name,
                TestCategory::Connectivity,
                Severity::Warning,
                "Cannot create HTTP client",
                "HTTP client should initialize",
                &e.to_string(),
                "Failed to create HTTP client for blocklist test.",
                "Check system TLS/SSL configuration.",
                start.elapsed().as_millis() as u64,
            );
        }
    };

    match client.head(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                let size = resp
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|s| format!(" (~{} KB)", s / 1024))
                    .unwrap_or_default();

                DiagnosticResult::pass(
                    &test_id,
                    &test_name,
                    TestCategory::Connectivity,
                    &format!("Reachable (HTTP {}{})", status.as_u16(), size),
                    start.elapsed().as_millis() as u64,
                )
            } else if status.as_u16() == 403 || status.as_u16() == 429 {
                DiagnosticResult::warning(
                    &test_id,
                    &test_name,
                    TestCategory::Connectivity,
                    &format!("Rate limited or forbidden (HTTP {})", status.as_u16()),
                    "The blocklist server returned a rate limit or forbidden error. This may be \
                     temporary or due to too frequent requests.",
                    "Wait a few minutes and try again. If persistent, the blocklist source may \
                     have blocked your IP or changed its access policy.",
                    start.elapsed().as_millis() as u64,
                )
            } else {
                DiagnosticResult::fail(
                    &test_id,
                    &test_name,
                    TestCategory::Connectivity,
                    Severity::Warning,
                    &format!("Unexpected response (HTTP {})", status.as_u16()),
                    "HTTP 200 OK",
                    &format!("HTTP {}", status.as_u16()),
                    &format!(
                        "The blocklist at {} returned HTTP {}. This could indicate the URL is \
                         incorrect, the service is down, or access is restricted.",
                        url,
                        status.as_u16()
                    ),
                    "Verify the URL is correct. Check if the blocklist source is still active. \
                     Consider using an alternative blocklist source.",
                    start.elapsed().as_millis() as u64,
                )
            }
        }
        Err(e) => {
            let error_str = e.to_string();
            let (diagnosis, suggestion) = if error_str.contains("timeout") {
                (
                    format!("Connection to {} timed out after 15 seconds. The server may be slow or unreachable.", url),
                    "Check network connectivity. Try accessing the URL in a browser. Consider using a different blocklist source.".to_string()
                )
            } else if error_str.contains("certificate") || error_str.contains("SSL") || error_str.contains("TLS") {
                (
                    format!("TLS/SSL error connecting to {}. The server's certificate may be invalid or expired.", url),
                    "Check if the URL is correct. The blocklist source may have certificate issues. Consider using an alternative source.".to_string()
                )
            } else if error_str.contains("resolve") || error_str.contains("DNS") {
                (
                    format!("Cannot resolve hostname for {}. DNS lookup failed.", url),
                    "Check DNS configuration. The hostname may be incorrect or the DNS server may be unreachable.".to_string()
                )
            } else {
                (
                    format!("Connection error to {}: {}", url, error_str),
                    "Check network connectivity and firewall rules. The blocklist source may be temporarily unavailable.".to_string()
                )
            };

            DiagnosticResult::fail(
                &test_id,
                &test_name,
                TestCategory::Connectivity,
                Severity::Warning,
                "Cannot reach blocklist source",
                "Successful connection",
                &error_str,
                &diagnosis,
                &suggestion,
                start.elapsed().as_millis() as u64,
            )
        }
    }
}

/// Test: CDN allowlist source connectivity
async fn test_cdn_source(name: &str, url: &str) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = format!("connectivity_cdn_{}", name.to_lowercase());
    let test_name = format!("CDN allowlist: {}", name);

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(format!("oustip-diagnose/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            return DiagnosticResult::skip(
                &test_id,
                &test_name,
                TestCategory::Connectivity,
                "Cannot create HTTP client",
            );
        }
    };

    match client.head(url).send().await {
        Ok(resp) if resp.status().is_success() => DiagnosticResult::pass(
            &test_id,
            &test_name,
            TestCategory::Connectivity,
            &format!("{} API reachable", name),
            start.elapsed().as_millis() as u64,
        ),
        Ok(resp) => DiagnosticResult::warning(
            &test_id,
            &test_name,
            TestCategory::Connectivity,
            &format!("{} API returned HTTP {}", name, resp.status().as_u16()),
            &format!(
                "The {} API returned an unexpected status. Auto-allowlist for {} may not work.",
                name, name
            ),
            &format!(
                "This is usually temporary. {} IPs will use cached values if available.",
                name
            ),
            start.elapsed().as_millis() as u64,
        ),
        Err(e) => DiagnosticResult::warning(
            &test_id,
            &test_name,
            TestCategory::Connectivity,
            &format!("Cannot reach {} API", name),
            &format!(
                "Failed to connect to {}: {}. Auto-allowlist for {} will not work.",
                url, e, name
            ),
            &format!(
                "Check network connectivity. If {} auto-allowlist is important, verify the URL is accessible.",
                name
            ),
            start.elapsed().as_millis() as u64,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require network access and may be flaky in CI
    // They are marked with #[ignore] and should be run manually

    #[tokio::test]
    #[ignore]
    async fn test_internet_connectivity_live() {
        let result = test_internet_connectivity().await;
        // Should pass if we have internet
        println!("Internet connectivity: {:?}", result.status);
    }

    #[tokio::test]
    #[ignore]
    async fn test_dns_resolution_live() {
        let result = test_dns_resolution().await;
        println!("DNS resolution: {:?}", result.status);
    }
}
