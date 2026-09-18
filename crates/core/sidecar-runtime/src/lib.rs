//! Small, framework-neutral helpers for Ryu-managed sidecar boundaries.
//!
//! Domain sidecars still own their routes, stores, and liveness semantics. This
//! crate keeps the repeated security/process substrate—fail-closed bearer checks
//! and the Core-compatible data-directory resolution—in one place.

use std::path::PathBuf;
use std::sync::OnceLock;

const RYU_DIR_ENV: &str = "RYU_DIR";
const RYU_PROFILE_ENV: &str = "RYU_PROFILE";
const RELEASE_PROFILE: &str = "release";
const PROFILE_SUFFIXES: &[(&str, &str)] = &[
    ("release", ""),
    ("dev", "-dev"),
    ("canary", "-canary"),
    ("nightly", "-nightly"),
    ("beta", "-beta"),
];

/// Constant-time equality for shared secrets and webhook signatures.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Check a complete `Authorization` header against an expected sidecar token.
/// Missing/empty expected tokens fail closed.
#[must_use]
pub fn bearer_ok(auth_header: Option<&str>, expected: Option<&str>) -> bool {
    let provided = auth_header.and_then(|value| value.strip_prefix("Bearer "));
    token_ok(provided, expected)
}

/// Check an already-parsed bearer value against an expected sidecar token.
#[must_use]
pub fn token_ok(provided: Option<&str>, expected: Option<&str>) -> bool {
    let Some(expected) = expected.filter(|value| !value.is_empty()) else {
        return false;
    };
    constant_time_eq(provided.unwrap_or("").as_bytes(), expected.as_bytes())
}

fn profile_suffix() -> String {
    let profile = std::env::var(RYU_PROFILE_ENV)
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| RELEASE_PROFILE.to_owned());
    PROFILE_SUFFIXES
        .iter()
        .find_map(|(name, suffix)| (*name == profile).then_some((*suffix).to_owned()))
        .unwrap_or_else(|| {
            panic!(
				"unsupported RYU_PROFILE '{profile}'; expected release, dev, canary, nightly, or beta"
			)
        })
}

fn default_data_dir() -> PathBuf {
    let name = format!(".ryu{}", profile_suffix());
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(name)
}

fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(default_data_dir)
        .join(format!("ryu{}", profile_suffix()))
}

#[derive(Debug, Default, serde::Deserialize)]
struct DataPathPointer {
    #[serde(default)]
    data_dir: Option<String>,
}

fn resolve_data_dir() -> PathBuf {
    if let Some(value) = std::env::var_os(RYU_DIR_ENV) {
        let path = PathBuf::from(value);
        if !path.as_os_str().is_empty() {
            return path;
        }
    }
    let pointer_path = config_dir().join("data-path.json");
    if let Ok(bytes) = std::fs::read(pointer_path) {
        if let Some(value) = serde_json::from_slice::<DataPathPointer>(&bytes)
            .ok()
            .and_then(|pointer| pointer.data_dir)
        {
            let path = PathBuf::from(value);
            if !path.as_os_str().is_empty() {
                return path;
            }
        }
    }
    default_data_dir()
}

/// Resolve the same profile-aware, pointer-aware data directory Core passes to
/// its managed sidecars. The result is cached for the process lifetime.
#[must_use]
pub fn ryu_dir() -> PathBuf {
    static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();
    DATA_DIR.get_or_init(resolve_data_dir).clone()
}

#[cfg(test)]
mod tests {
    use super::{bearer_ok, constant_time_eq, ryu_dir, token_ok};

    #[test]
    fn bearer_checks_fail_closed_and_require_the_scheme() {
        assert!(bearer_ok(Some("Bearer secret"), Some("secret")));
        assert!(!bearer_ok(Some("secret"), Some("secret")));
        assert!(!bearer_ok(Some("Bearer wrong"), Some("secret")));
        assert!(!bearer_ok(None, None));
        assert!(!token_ok(Some("secret"), Some("")));
    }

    #[test]
    fn constant_time_equality_matches_value_and_length() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn data_directory_is_non_empty() {
        assert!(!ryu_dir().as_os_str().is_empty());
    }
}
