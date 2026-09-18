//! Mail sidecar → Core callbacks for the node-owned email transport.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::email::{self, Attachment, EmailTransportConfig, OutboundEmail};

const PLUGIN_ID: &str = "@ryu/mail";

#[derive(Debug, Clone)]
pub struct EmailHost {
    client: reqwest::Client,
    core_base: Option<String>,
    local_transport: Option<EmailTransportConfig>,
    plugin_id: String,
    token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub struct EmailSendAttachment {
    #[serde(alias = "content_base64", rename = "content")]
    pub content_base64: String,
    #[serde(default)]
    pub content_id: Option<String>,
    pub content_type: String,
    pub filename: String,
    #[serde(default)]
    pub inline: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct EmailSendRequest {
    pub attachments: Vec<EmailSendAttachment>,
    pub bcc: Vec<String>,
    pub cc: Vec<String>,
    pub from: Option<String>,
    pub headers: std::collections::BTreeMap<String, String>,
    pub html: Option<String>,
    pub in_reply_to: Option<String>,
    pub labels: Vec<String>,
    pub reply_to: Vec<String>,
    pub references: Option<String>,
    pub subject: String,
    pub text: Option<String>,
    pub track_opens: bool,
    pub to: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct EmailStatusResponse {
    configured: bool,
}

impl EmailHost {
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            client: reqwest::Client::new(),
            core_base: std::env::var("RYU_CORE_PORT")
                .ok()
                .map(|port| format!("http://127.0.0.1:{}", port.trim()))
                .filter(|base| !base.ends_with(':')),
            local_transport: email::resolve_transport(),
            plugin_id: std::env::var("RYU_EXT_PLUGIN_ID")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| PLUGIN_ID.to_owned()),
            token: std::env::var("RYU_EXT_TOKEN")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
        }
    }

    #[must_use]
    pub fn disabled() -> Self {
        Self {
            client: reqwest::Client::new(),
            core_base: None,
            local_transport: None,
            plugin_id: PLUGIN_ID.to_owned(),
            token: None,
        }
    }

    #[must_use]
    pub fn available(&self) -> bool {
        (self.core_base.is_some() && self.token.is_some()) || self.local_transport.is_some()
    }

    pub async fn status(&self) -> Result<bool> {
        if self.core_base.is_some() && self.token.is_some() {
            let value = self.post("email.status", &()).await?;
            let value: EmailStatusResponse = serde_json::from_value(value)?;
            return Ok(value.configured);
        }
        Ok(self.local_transport.is_some())
    }

    pub async fn send(&self, request: &EmailSendRequest) -> Result<String> {
        if self.core_base.is_some() && self.token.is_some() {
            let response: serde_json::Value = self.post("email.send", request).await?;
            return response
                .get("messageId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("Core email callback returned no message id"));
        }

        let Some(config) = self.local_transport.as_ref() else {
            return Err(anyhow!("email transport is not configured"));
        };
        let attachments = request
            .attachments
            .iter()
            .map(|attachment| {
                use base64::Engine as _;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&attachment.content_base64)
                    .map_err(|error| anyhow!("invalid attachment base64: {error}"))?;
                Ok(Attachment {
                    bytes,
                    content_type: attachment.content_type.clone(),
                    filename: attachment.filename.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        email::send_email(
            config,
            &OutboundEmail {
                attachments,
                bcc: request.bcc.clone(),
                cc: request.cc.clone(),
                from: request.from.clone(),
                headers: request.headers.clone(),
                html: request.html.clone(),
                in_reply_to: request.in_reply_to.clone(),
                references: request.references.clone(),
                reply_to: request.reply_to.first().cloned(),
                subject: request.subject.clone(),
                text: request.text.clone(),
                to: request.to.clone(),
            },
        )
        .await
        .map_err(|error| anyhow!(error.to_string()))
    }

    async fn post<T: Serialize>(&self, capability: &str, body: &T) -> Result<serde_json::Value> {
        let Some(base) = self.core_base.as_deref() else {
            return Err(anyhow!("email transport is not configured"));
        };
        let Some(token) = self.token.as_deref() else {
            return Err(anyhow!("email transport is not configured"));
        };
        let response = self
            .client
            .post(format!(
                "{}/api/host/capability/{capability}",
                base.trim_end_matches('/')
            ))
            .bearer_auth(token)
            .header("x-ryu-plugin-id", &self.plugin_id)
            .json(body)
            .timeout(Duration::from_secs(30))
            .send()
            .await?;
        let status = response.status();
        let value = response.json::<serde_json::Value>().await?;
        if !status.is_success() {
            return Err(anyhow!(
                "Core email callback returned HTTP {status}: {}",
                value
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown error")
            ));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::EmailHost;

    #[test]
    fn standalone_host_fails_closed_without_core_callback() {
        assert!(!EmailHost::disabled().available());
    }
}
