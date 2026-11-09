//! Strength check for the standalone API bearer (`RYU_MAIL_API_TOKEN`).

use std::net::IpAddr;

/// Shortest standalone API token accepted for a bind beyond loopback.
const MIN_PUBLIC_TOKEN_CHARS: usize = 32;

/// Example values from docs and templates that must never guard a public bind.
const PLACEHOLDER_TOKENS: &[&str] = &[
    "replace-me",
    "mail-example-secret",
    "changeme",
    "change-me",
    "secret",
    "token",
];

/// The standalone bearer is the single credential for every protected route,
/// including send and delete, and the service does no auth throttling of its
/// own. A bind beyond loopback therefore needs a token that cannot be guessed;
/// a weak token on loopback is only warned about.
pub(crate) fn check_standalone_token(token: &str, host: IpAddr) -> anyhow::Result<()> {
    let weak = token.chars().count() < MIN_PUBLIC_TOKEN_CHARS
        || PLACEHOLDER_TOKENS
            .iter()
            .any(|placeholder| token.eq_ignore_ascii_case(placeholder));
    if !weak {
        return Ok(());
    }
    if host.is_loopback() {
        tracing::warn!(
            "ryu-mail: RYU_MAIL_API_TOKEN is short or a placeholder; generate one with `openssl rand -hex 32` before exposing the service"
        );
        return Ok(());
    }
    anyhow::bail!(
        "RYU_MAIL_API_TOKEN must be at least {MIN_PUBLIC_TOKEN_CHARS} characters and not a placeholder before Mail binds beyond loopback; generate one with `openssl rand -hex 32`"
    )
}

#[cfg(test)]
mod tests {
    use super::check_standalone_token;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn a_public_bind_needs_a_strong_standalone_token() {
        let public = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let strong = "0123456789abcdef0123456789abcdef";
        for weak in ["a", "replace-me", "Mail-Example-Secret", &strong[..31]] {
            assert!(check_standalone_token(weak, public).is_err(), "{weak}");
        }
        assert!(check_standalone_token(strong, public).is_ok());
        // Loopback is the developer path: warn, do not refuse.
        assert!(check_standalone_token("replace-me", IpAddr::V4(Ipv4Addr::LOCALHOST)).is_ok());
    }
}
