//! HTTP fetcher for downloading blocklists and allowlists.

use anyhow::{Context, Result};
use ipnet::IpNet;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::config::{AutoAllowlist, BlocklistSource};

const TIMEOUT_SECS: u64 = 30;
const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 2000;

/// Maximum size per blocklist file (10 MB)
/// Largest known list (firehol_level4) is ~1.2 MB, so 10 MB provides ample margin
const MAX_BLOCKLIST_SIZE: usize = 10 * 1024 * 1024;

/// Maximum total size for all downloads combined (50 MB)
const MAX_TOTAL_SIZE: usize = 50 * 1024 * 1024;

/// Result of fetching a blocklist
#[derive(Debug)]
pub struct FetchResult {
    pub name: String,
    pub ips: Vec<IpNet>,
    pub raw_count: usize,
}

/// HTTP client for fetching lists
pub struct Fetcher {
    client: Client,
}

impl Fetcher {
    /// Create a new fetcher with default settings
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .user_agent(format!("oustip/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .context("Failed to create HTTP client")?;
        Ok(Self { client })
    }

    /// Fetch a single blocklist with retry logic
    pub async fn fetch_blocklist(&self, source: &BlocklistSource) -> Result<FetchResult> {
        info!("Fetching {}...", source.name);

        let content = self.fetch_with_retry(&source.url).await
            .with_context(|| format!("Failed to fetch {}", source.name))?;

        let ips = parse_blocklist(&content);
        let raw_count = ips.len();

        info!(
            "Fetched {} - {} IPs",
            source.name,
            format_count(raw_count)
        );

        Ok(FetchResult {
            name: source.name.clone(),
            ips,
            raw_count,
        })
    }

    /// Fetch multiple blocklists concurrently
    pub async fn fetch_blocklists(&self, sources: &[&BlocklistSource]) -> Vec<Result<FetchResult>> {
        let futures: Vec<_> = sources
            .iter()
            .map(|source| self.fetch_blocklist(source))
            .collect();

        futures::future::join_all(futures).await
    }

    /// Fetch auto-allowlist IPs from CDN providers
    pub async fn fetch_auto_allowlist(&self, config: &AutoAllowlist) -> Result<Vec<IpNet>> {
        let mut ips = Vec::new();

        if config.cloudflare {
            match self.fetch_cloudflare_ips().await {
                Ok(cf_ips) => {
                    info!("Fetched Cloudflare allowlist - {} ranges", cf_ips.len());
                    ips.extend(cf_ips);
                }
                Err(e) => warn!("Failed to fetch Cloudflare IPs: {}", e),
            }
        }

        if config.github {
            match self.fetch_github_ips().await {
                Ok(gh_ips) => {
                    info!("Fetched GitHub allowlist - {} ranges", gh_ips.len());
                    ips.extend(gh_ips);
                }
                Err(e) => warn!("Failed to fetch GitHub IPs: {}", e),
            }
        }

        if config.google_cloud {
            match self.fetch_google_cloud_ips().await {
                Ok(gc_ips) => {
                    info!("Fetched Google Cloud allowlist - {} ranges", gc_ips.len());
                    ips.extend(gc_ips);
                }
                Err(e) => warn!("Failed to fetch Google Cloud IPs: {}", e),
            }
        }

        if config.aws {
            match self.fetch_aws_ips().await {
                Ok(aws_ips) => {
                    info!("Fetched AWS allowlist - {} ranges", aws_ips.len());
                    ips.extend(aws_ips);
                }
                Err(e) => warn!("Failed to fetch AWS IPs: {}", e),
            }
        }

        if config.fastly {
            match self.fetch_fastly_ips().await {
                Ok(fl_ips) => {
                    info!("Fetched Fastly allowlist - {} ranges", fl_ips.len());
                    ips.extend(fl_ips);
                }
                Err(e) => warn!("Failed to fetch Fastly IPs: {}", e),
            }
        }

        Ok(ips)
    }

    /// Fetch content with retry logic and size validation
    async fn fetch_with_retry(&self, url: &str) -> Result<String> {
        self.fetch_with_retry_and_limit(url, MAX_BLOCKLIST_SIZE).await
    }

    /// Fetch content with retry logic and custom size limit
    async fn fetch_with_retry_and_limit(&self, url: &str, max_size: usize) -> Result<String> {
        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                let delay = RETRY_DELAY_MS * (1 << (attempt - 1));
                debug!("Retry {} after {}ms for {}", attempt, delay, url);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            match self.client.get(url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        // Check Content-Length header if available
                        if let Some(content_length) = response.content_length() {
                            if content_length as usize > max_size {
                                return Err(anyhow::anyhow!(
                                    "Response too large: {} bytes (max: {} bytes)",
                                    content_length,
                                    max_size
                                ));
                            }
                        }

                        let body = response.text().await.context("Failed to read response body")?;

                        // Double-check actual size after download
                        if body.len() > max_size {
                            return Err(anyhow::anyhow!(
                                "Downloaded content too large: {} bytes (max: {} bytes)",
                                body.len(),
                                max_size
                            ));
                        }

                        return Ok(body);
                    }
                    last_error = Some(anyhow::anyhow!("HTTP {}", response.status()));
                }
                Err(e) => {
                    last_error = Some(e.into());
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Unknown error")))
    }

    /// Fetch Cloudflare IPv4 ranges
    async fn fetch_cloudflare_ips(&self) -> Result<Vec<IpNet>> {
        let content = self.fetch_with_retry("https://www.cloudflare.com/ips-v4").await?;
        Ok(parse_simple_list(&content))
    }

    /// Fetch GitHub IP ranges
    async fn fetch_github_ips(&self) -> Result<Vec<IpNet>> {
        #[derive(Deserialize)]
        struct GitHubMeta {
            hooks: Option<Vec<String>>,
            web: Option<Vec<String>>,
            api: Option<Vec<String>>,
            git: Option<Vec<String>>,
            actions: Option<Vec<String>>,
        }

        let content = self.fetch_with_retry("https://api.github.com/meta").await?;
        let meta: GitHubMeta = serde_json::from_str(&content)?;

        let mut ips = HashSet::new();
        for list in [meta.hooks, meta.web, meta.api, meta.git, meta.actions].into_iter().flatten() {
            for ip_str in list {
                if let Ok(net) = ip_str.parse::<IpNet>() {
                    // Only IPv4 for now
                    if matches!(net, IpNet::V4(_)) {
                        ips.insert(net);
                    }
                }
            }
        }

        Ok(ips.into_iter().collect())
    }

    /// Fetch Google Cloud IP ranges
    async fn fetch_google_cloud_ips(&self) -> Result<Vec<IpNet>> {
        #[derive(Deserialize)]
        struct GoogleCloudRanges {
            prefixes: Vec<GooglePrefix>,
        }

        #[derive(Deserialize)]
        struct GooglePrefix {
            #[serde(rename = "ipv4Prefix")]
            ipv4_prefix: Option<String>,
        }

        let content = self.fetch_with_retry("https://www.gstatic.com/ipranges/cloud.json").await?;
        let ranges: GoogleCloudRanges = serde_json::from_str(&content)?;

        let ips: Vec<IpNet> = ranges
            .prefixes
            .iter()
            .filter_map(|p| p.ipv4_prefix.as_ref())
            .filter_map(|s| s.parse().ok())
            .collect();

        Ok(ips)
    }

    /// Fetch AWS IP ranges
    async fn fetch_aws_ips(&self) -> Result<Vec<IpNet>> {
        #[derive(Deserialize)]
        struct AwsRanges {
            prefixes: Vec<AwsPrefix>,
        }

        #[derive(Deserialize)]
        struct AwsPrefix {
            ip_prefix: String,
        }

        let content = self.fetch_with_retry("https://ip-ranges.amazonaws.com/ip-ranges.json").await?;
        let ranges: AwsRanges = serde_json::from_str(&content)?;

        let ips: Vec<IpNet> = ranges
            .prefixes
            .iter()
            .filter_map(|p| p.ip_prefix.parse().ok())
            .collect();

        Ok(ips)
    }

    /// Fetch Fastly IP ranges
    async fn fetch_fastly_ips(&self) -> Result<Vec<IpNet>> {
        #[derive(Deserialize)]
        struct FastlyRanges {
            addresses: Vec<String>,
        }

        let content = self.fetch_with_retry("https://api.fastly.com/public-ip-list").await?;
        let ranges: FastlyRanges = serde_json::from_str(&content)?;

        let ips: Vec<IpNet> = ranges
            .addresses
            .iter()
            .filter_map(|s| s.parse().ok())
            .filter(|net: &IpNet| matches!(net, IpNet::V4(_)))
            .collect();

        Ok(ips)
    }
}

// Note: Default is intentionally not implemented for Fetcher
// because new() can fail and we want explicit error handling.

/// Parse a blocklist in FireHOL .netset format
pub fn parse_blocklist(content: &str) -> Vec<IpNet> {
    content
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .filter_map(|line| {
            let trimmed = line.trim();
            // Handle IP or CIDR
            if trimmed.contains('/') {
                trimmed.parse::<IpNet>().ok()
            } else {
                trimmed.parse::<IpAddr>().ok().map(IpNet::from)
            }
        })
        .collect()
}

/// Parse a simple list (one IP/CIDR per line)
fn parse_simple_list(content: &str) -> Vec<IpNet> {
    content
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

/// Format a count with K/M suffix
pub fn format_count(count: usize) -> String {
    if count >= 1_000_000 {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{:.1}K", count as f64 / 1_000.0)
    } else {
        count.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_blocklist_ip() {
        let content = "# comment\n192.168.1.1\n10.0.0.1\n";
        let ips = parse_blocklist(content);
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_parse_blocklist_cidr() {
        let content = "192.168.0.0/24\n10.0.0.0/8\n";
        let ips = parse_blocklist(content);
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].prefix_len(), 24);
        assert_eq!(ips[1].prefix_len(), 8);
    }

    #[test]
    fn test_parse_blocklist_mixed() {
        let content = "# FireHOL blocklist\n\n192.168.1.1\n10.0.0.0/8\n# another comment\n172.16.0.0/12";
        let ips = parse_blocklist(content);
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn test_format_count() {
        assert_eq!(format_count(500), "500");
        assert_eq!(format_count(1500), "1.5K");
        assert_eq!(format_count(1_500_000), "1.5M");
    }
}
