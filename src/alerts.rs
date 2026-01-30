//! Alert system for OustIP (Gotify, email, webhook).

use anyhow::{Context, Result};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tracing::{debug, error};

use crate::config::AlertsConfig;

/// Timeout for alert HTTP requests (30s for slow networks/SMTP)
const TIMEOUT_SECS: u64 = 30;

/// Alert severity levels
#[derive(Debug, Clone, Copy)]
pub enum AlertLevel {
    Info,
    Warning,
    Error,
}

impl AlertLevel {
    fn as_str(&self) -> &'static str {
        match self {
            AlertLevel::Info => "INFO",
            AlertLevel::Warning => "WARNING",
            AlertLevel::Error => "ERROR",
        }
    }

    fn gotify_priority(&self) -> u8 {
        match self {
            AlertLevel::Info => 2,
            AlertLevel::Warning => 5,
            AlertLevel::Error => 8,
        }
    }
}

/// Alert manager
pub struct AlertManager {
    config: AlertsConfig,
    client: Client,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(config: AlertsConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .build()
            .context("Failed to create HTTP client for alerts")?;

        Ok(Self { config, client })
    }

    /// Send an alert to all configured destinations
    pub async fn send(&self, level: AlertLevel, title: &str, message: &str) {
        let mut success_count = 0;
        let mut destinations = Vec::new();

        if self.config.gotify.enabled {
            destinations.push("Gotify");
            if self.send_gotify(level, title, message).await.is_ok() {
                success_count += 1;
            }
        }

        if self.config.email.enabled {
            destinations.push("Email");
            if self.send_email(level, title, message).await.is_ok() {
                success_count += 1;
            }
        }

        if self.config.webhook.enabled {
            destinations.push("Webhook");
            if self.send_webhook(level, title, message).await.is_ok() {
                success_count += 1;
            }
        }

        if !destinations.is_empty() {
            debug!(
                "Alert sent to {}/{} destinations: {}",
                success_count,
                destinations.len(),
                destinations.join(", ")
            );
        }
    }

    /// Send alert via Gotify
    async fn send_gotify(&self, level: AlertLevel, title: &str, message: &str) -> Result<()> {
        let url = format!("{}/message", self.config.gotify.url.trim_end_matches('/'));

        #[derive(Serialize)]
        struct GotifyMessage<'a> {
            title: &'a str,
            message: &'a str,
            priority: u8,
        }

        let payload = GotifyMessage {
            title,
            message,
            priority: level.gotify_priority(),
        };

        // Get token from env var or config (SecureString is zeroed on drop)
        let token = self.config.gotify.get_token();

        let response = self
            .client
            .post(&url)
            .header("X-Gotify-Key", token.as_str())
            .json(&payload)
            .send()
            .await
            .context("Failed to send Gotify alert")?;

        if !response.status().is_success() {
            let status = response.status();
            // Don't log response body as it may contain sensitive info
            error!("Gotify alert failed with status: {}", status);
            anyhow::bail!("Gotify returned {}", status);
        }

        debug!("Gotify alert sent successfully");
        Ok(())
    }

    /// Send alert via email (runs in blocking task to avoid blocking async executor)
    async fn send_email(&self, level: AlertLevel, title: &str, message: &str) -> Result<()> {
        let email_config = self.config.email.clone();
        let level_str = level.as_str().to_string();
        let title = title.to_string();
        let message = message.to_string();

        // Run SMTP operations in blocking task
        tokio::task::spawn_blocking(move || {
            let subject = format!("[OustIP {}] {}", level_str, title);
            let body = format!(
                "OustIP Alert\n\
                 ==============\n\n\
                 Level: {}\n\
                 Title: {}\n\n\
                 Message:\n{}\n",
                level_str, title, message
            );

            let email = Message::builder()
                .from(
                    email_config
                        .from
                        .parse()
                        .context("Invalid 'from' email address")?,
                )
                .to(email_config
                    .to
                    .parse()
                    .context("Invalid 'to' email address")?)
                .subject(subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body)
                .context("Failed to build email")?;

            // Get password from env var or config (SecureString is zeroed on drop)
            let password = email_config.get_password();

            let creds = Credentials::new(
                email_config.smtp_user.clone(),
                password.as_str().to_string(),
            );

            let mailer = SmtpTransport::relay(&email_config.smtp_host)
                .context("Failed to create SMTP transport")?
                .port(email_config.smtp_port)
                .credentials(creds)
                .build();

            mailer.send(&email).context("Failed to send email")?;

            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Email task panicked")??;

        debug!("Email alert sent successfully");
        Ok(())
    }

    /// Send alert via webhook
    async fn send_webhook(&self, level: AlertLevel, title: &str, message: &str) -> Result<()> {
        #[derive(Serialize)]
        struct WebhookPayload<'a> {
            level: &'a str,
            title: &'a str,
            message: &'a str,
            timestamp: String,
            source: &'a str,
        }

        let payload = WebhookPayload {
            level: level.as_str(),
            title,
            message,
            timestamp: chrono::Utc::now().to_rfc3339(),
            source: "oustip",
        };

        let mut request = self.client.post(&self.config.webhook.url).json(&payload);

        // Add custom headers (validated during config deserialization to prevent injection)
        for (key, value) in &self.config.webhook.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let response = request.send().await.context("Failed to send webhook")?;

        if !response.status().is_success() {
            anyhow::bail!("Webhook returned non-success status: {}", response.status());
        }

        debug!("Webhook alert sent successfully");
        Ok(())
    }
}

/// Alert types for common events
pub struct AlertTypes;

impl AlertTypes {
    /// Alert for successful update
    pub fn update_success(entries: usize, ips: u128) -> (AlertLevel, String, String) {
        (
            AlertLevel::Info,
            "Blocklist Updated".to_string(),
            format!(
                "Successfully updated blocklist.\n\
                 Entries: {}\n\
                 IPs covered: {}",
                entries, ips
            ),
        )
    }

    /// Alert for update failure
    pub fn update_failed(error: &str) -> (AlertLevel, String, String) {
        (
            AlertLevel::Error,
            "Blocklist Update Failed".to_string(),
            format!("Failed to update blocklist:\n{}", error),
        )
    }

    /// Alert for fetch failure (single source)
    pub fn fetch_failed(source: &str, error: &str) -> (AlertLevel, String, String) {
        (
            AlertLevel::Warning,
            format!("Failed to fetch {}", source),
            format!("Could not download blocklist from {}:\n{}", source, error),
        )
    }

    /// Alert for outbound connection to blocked IP
    pub fn outbound_to_blocked(src_ip: &str, dst_ip: &str) -> (AlertLevel, String, String) {
        (
            AlertLevel::Warning,
            "Outbound to Blocked IP".to_string(),
            format!(
                "A device on your network ({}) attempted to connect to a blocked IP ({}).\n\
                 This may indicate compromise.",
                src_ip, dst_ip
            ),
        )
    }

    /// Alert for allow+block overlap detected
    pub fn overlap_detected(
        overlaps: &[(String, String, Vec<String>)],
    ) -> (AlertLevel, String, String) {
        let mut details = String::new();
        for (ip, hostname, sources) in overlaps {
            details.push_str(&format!(
                "  {} ({}) - found in: {}\n",
                ip,
                hostname,
                sources.join(", ")
            ));
        }

        (
            AlertLevel::Info,
            "Allow+Block Overlap Detected".to_string(),
            format!(
                "The following IPs are in both allowlist AND blocklist:\n\n{}\n\
                 These IPs are NOT blocked (allowlist takes precedence).\n\n\
                 To acknowledge and stop these notifications:\n\
                   oustip assume add <ip>",
                details
            ),
        )
    }

    /// Alert for significant blocklist content change
    /// This indicates the upstream blocklist sources have changed substantially
    pub fn blocklist_changed(
        old_ips: u128,
        new_ips: u128,
        change_percent: f64,
    ) -> (AlertLevel, String, String) {
        let direction = if new_ips > old_ips {
            "increased"
        } else {
            "decreased"
        };
        let diff = new_ips.abs_diff(old_ips);

        (
            AlertLevel::Warning,
            "Blocklist Content Changed".to_string(),
            format!(
                "The blocklist content has {} significantly.\n\n\
                 Previous: {} IPs\n\
                 Current: {} IPs\n\
                 Change: {} IPs ({:.1}%)\n\n\
                 This may indicate:\n\
                 - Upstream blocklist sources were updated\n\
                 - A blocklist source is unavailable or corrupted\n\
                 - Network issues during fetch\n\n\
                 Review the changes with: oustip stats",
                direction, old_ips, new_ips, diff, change_percent
            ),
        )
    }

    /// Alert for firewall rollback performed after rule application failure
    /// This indicates that applying new firewall rules failed and the previous
    /// ruleset has been (or attempted to be) restored
    pub fn rollback_performed(error: &str, restored: bool) -> (AlertLevel, String, String) {
        let status = if restored {
            "Previous firewall rules have been successfully restored."
        } else {
            "WARNING: Failed to restore previous firewall rules. \
             Manual intervention may be required."
        };

        (
            AlertLevel::Error,
            "Firewall Rollback Performed".to_string(),
            format!(
                "Failed to apply new firewall rules. A rollback was attempted.\n\n\
                 Error: {}\n\n\
                 Rollback Status: {}\n\n\
                 This may indicate:\n\
                 - Invalid IP addresses in blocklist\n\
                 - Firewall backend issues\n\
                 - Insufficient permissions\n\
                 - System resource constraints\n\n\
                 Please investigate and run: oustip update",
                error, status
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_level() {
        assert_eq!(AlertLevel::Info.as_str(), "INFO");
        assert_eq!(AlertLevel::Warning.as_str(), "WARNING");
        assert_eq!(AlertLevel::Error.as_str(), "ERROR");
    }

    #[test]
    fn test_gotify_priority() {
        assert_eq!(AlertLevel::Info.gotify_priority(), 2);
        assert_eq!(AlertLevel::Warning.gotify_priority(), 5);
        assert_eq!(AlertLevel::Error.gotify_priority(), 8);
    }

    #[test]
    fn test_alert_types_update_success() {
        let (level, title, body) = AlertTypes::update_success(1000, 50000);
        assert!(matches!(level, AlertLevel::Info));
        assert_eq!(title, "Blocklist Updated");
        assert!(body.contains("1000"));
        assert!(body.contains("50000"));
    }

    #[test]
    fn test_alert_types_update_failed() {
        let (level, title, body) = AlertTypes::update_failed("Connection timeout");
        assert!(matches!(level, AlertLevel::Error));
        assert_eq!(title, "Blocklist Update Failed");
        assert!(body.contains("Connection timeout"));
    }

    #[test]
    fn test_alert_types_fetch_failed() {
        let (level, title, body) = AlertTypes::fetch_failed("firehol_level1", "404 Not Found");
        assert!(matches!(level, AlertLevel::Warning));
        assert!(title.contains("firehol_level1"));
        assert!(body.contains("404 Not Found"));
    }

    #[test]
    fn test_alert_types_outbound_to_blocked() {
        let (level, title, body) = AlertTypes::outbound_to_blocked("192.168.1.100", "1.2.3.4");
        assert!(matches!(level, AlertLevel::Warning));
        assert_eq!(title, "Outbound to Blocked IP");
        assert!(body.contains("192.168.1.100"));
        assert!(body.contains("1.2.3.4"));
        assert!(body.contains("compromise"));
    }

    #[test]
    fn test_alert_types_overlap_detected() {
        let overlaps = vec![
            (
                "8.8.8.8".to_string(),
                "dns.google".to_string(),
                vec!["firehol_level1".to_string()],
            ),
            (
                "1.1.1.1".to_string(),
                "one.one.one.one".to_string(),
                vec!["spamhaus".to_string(), "dshield".to_string()],
            ),
        ];
        let (level, title, body) = AlertTypes::overlap_detected(&overlaps);
        assert!(matches!(level, AlertLevel::Info));
        assert!(title.contains("Overlap"));
        assert!(body.contains("8.8.8.8"));
        assert!(body.contains("dns.google"));
        assert!(body.contains("1.1.1.1"));
        assert!(body.contains("oustip assume add"));
    }

    #[test]
    fn test_alert_types_overlap_empty() {
        let overlaps: Vec<(String, String, Vec<String>)> = vec![];
        let (level, title, body) = AlertTypes::overlap_detected(&overlaps);
        assert!(matches!(level, AlertLevel::Info));
        assert!(!title.is_empty());
        assert!(body.contains("allowlist"));
    }

    #[test]
    fn test_alert_level_display() {
        // Test all variants have non-empty string representation
        for level in [AlertLevel::Info, AlertLevel::Warning, AlertLevel::Error] {
            assert!(!level.as_str().is_empty());
            assert!(level.gotify_priority() > 0);
        }
    }

    #[test]
    fn test_alert_types_blocklist_changed_increase() {
        let (level, title, body) = AlertTypes::blocklist_changed(100_000, 120_000, 20.0);
        assert!(matches!(level, AlertLevel::Warning));
        assert_eq!(title, "Blocklist Content Changed");
        assert!(body.contains("increased"));
        assert!(body.contains("100000"));
        assert!(body.contains("120000"));
        assert!(body.contains("20000"));
        assert!(body.contains("20.0%"));
    }

    #[test]
    fn test_alert_types_blocklist_changed_decrease() {
        let (level, title, body) = AlertTypes::blocklist_changed(150_000, 100_000, 33.3);
        assert!(matches!(level, AlertLevel::Warning));
        assert_eq!(title, "Blocklist Content Changed");
        assert!(body.contains("decreased"));
        assert!(body.contains("150000"));
        assert!(body.contains("100000"));
        assert!(body.contains("50000"));
        assert!(body.contains("33.3%"));
    }

    #[test]
    fn test_alert_types_blocklist_changed_content() {
        let (_, _, body) = AlertTypes::blocklist_changed(1000, 1200, 20.0);
        // Should contain helpful information
        assert!(body.contains("Upstream blocklist"));
        assert!(body.contains("oustip stats"));
    }

    #[test]
    fn test_alert_types_rollback_performed_success() {
        let (level, title, body) = AlertTypes::rollback_performed("nft failed: syntax error", true);
        assert!(matches!(level, AlertLevel::Error));
        assert_eq!(title, "Firewall Rollback Performed");
        assert!(body.contains("nft failed: syntax error"));
        assert!(body.contains("successfully restored"));
        assert!(body.contains("oustip update"));
    }

    #[test]
    fn test_alert_types_rollback_performed_failure() {
        let (level, title, body) =
            AlertTypes::rollback_performed("iptables failed: permission denied", false);
        assert!(matches!(level, AlertLevel::Error));
        assert_eq!(title, "Firewall Rollback Performed");
        assert!(body.contains("iptables failed: permission denied"));
        assert!(body.contains("Failed to restore"));
        assert!(body.contains("Manual intervention"));
    }

    #[test]
    fn test_alert_types_rollback_performed_content() {
        let (_, _, body) = AlertTypes::rollback_performed("test error", true);
        // Should contain helpful diagnostic information
        assert!(body.contains("Invalid IP addresses"));
        assert!(body.contains("Firewall backend"));
        assert!(body.contains("permissions"));
    }
}
