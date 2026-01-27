//! Alert system for OustIP (Gotify, email, webhook).

use anyhow::{Context, Result};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tracing::{debug, error, warn};

use crate::config::AlertsConfig;

const TIMEOUT_SECS: u64 = 10;

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
            if self.send_email(level, title, message).is_ok() {
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

        // Get token from env var or config
        let token = self.config.gotify.get_token();

        let response = self
            .client
            .post(&url)
            .header("X-Gotify-Key", &token)
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

    /// Send alert via email
    fn send_email(&self, level: AlertLevel, title: &str, message: &str) -> Result<()> {
        let email_config = &self.config.email;

        let subject = format!("[OustIP {}] {}", level.as_str(), title);
        let body = format!(
            "OustIP Alert\n\
             ==============\n\n\
             Level: {}\n\
             Title: {}\n\n\
             Message:\n{}\n",
            level.as_str(),
            title,
            message
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

        // Get password from env var or config
        let password = email_config.get_password();

        let creds = Credentials::new(
            email_config.smtp_user.clone(),
            password,
        );

        let mailer = SmtpTransport::relay(&email_config.smtp_host)
            .context("Failed to create SMTP transport")?
            .port(email_config.smtp_port)
            .credentials(creds)
            .build();

        mailer.send(&email).context("Failed to send email")?;

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
            let status = response.status();
            warn!("Webhook returned non-success status: {}", status);
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
            format!(
                "Could not download blocklist from {}:\n{}",
                source, error
            ),
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
}
