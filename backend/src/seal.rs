//! At-rest sealing for the secrets Mail stores: inbox inbound secrets, webhook
//! signing secrets, and webhook custom header values.
//!
//! Every secret Mail writes is sealed with the `@ryu/mail` plugin subkey
//! ([`ryu_crypto::PluginCipher`], `encp:v1:` envelope, ChaCha20-Poly1305). The
//! subkey is an HKDF-SHA256 derivation of the master key that Core hands the
//! sidecar at spawn (`RYU_SEAL_KEY` + `RYU_SEAL_SCOPE=plugin:@ryu/mail`); a
//! standalone Mail derives the same subkey from `RYU_MASTER_KEY`. The master key
//! itself never reaches a Core-hosted sidecar, and nothing key-related is written
//! to disk.
//!
//! Without a key, writes of a secret fail closed (an inbox or webhook cannot be
//! created); there is no plaintext fallback.
//!
//! Reads accept three forms: the `encp:v1:` envelope, legacy plaintext (rows from
//! an older version), and the older Mail scheme (`enc:v1:` under a Mail-specific
//! HKDF subkey of `RYU_MASTER_KEY`, salt `ryu-mail-secrets-v1`) when
//! `RYU_MASTER_KEY` is set. [`crate::MailStore`] reseals both legacy forms into
//! `encp:v1:` when it opens the store.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use ryu_crypto::{FieldCipher, PluginCipher};

/// Env var carrying the base64-encoded 32-byte operator master key.
pub const MASTER_KEY_ENV: &str = "RYU_MASTER_KEY";

/// The canonical plugin id: the HKDF `info` input of Mail's subkey.
pub const PLUGIN_ID: &str = "@ryu/mail";

/// HKDF salt of the older Mail scheme. Kept only to read rows it sealed.
const LEGACY_SUBKEY_SALT: &[u8] = b"ryu-mail-secrets-v1";
/// HKDF info of the older Mail scheme.
const LEGACY_SUBKEY_INFO: &[u8] = b"ryu-mail:stored-secrets";

/// Seals stored secrets under the `@ryu/mail` plugin subkey and opens both the
/// current envelope and the older `RYU_MASTER_KEY` scheme.
#[derive(Clone)]
pub struct SecretSealer {
    cipher: PluginCipher,
    legacy: Option<FieldCipher>,
}

impl SecretSealer {
    /// A sealer over the plugin subkey, with no legacy reader.
    pub fn new(cipher: PluginCipher) -> Self {
        Self {
            cipher,
            legacy: None,
        }
    }

    /// Also open values the older Mail scheme sealed under `master`.
    #[must_use]
    pub fn with_legacy_master_key(mut self, master: &[u8; 32]) -> Self {
        self.legacy = Some(legacy_cipher(master));
        self
    }

    /// The process's sealer from its resolved keys (see [`crate::seal_keys`]):
    /// `None` in compat mode, where secret writes fail closed as before. Values
    /// the older `RYU_MASTER_KEY` scheme sealed stay readable when that key is set.
    pub fn from_keys(keys: &crate::seal_keys::PluginKeys) -> Result<Option<Self>> {
        let Some(cipher) = keys.plugin_cipher() else {
            tracing::warn!("ryu-mail: no sealing key; secret writes will fail");
            return Ok(None);
        };
        let sealer = Self::new(cipher.clone());
        Ok(Some(match std::env::var(MASTER_KEY_ENV) {
            Ok(value) if !value.trim().is_empty() => {
                sealer.with_legacy_master_key(&decode_master_key(&value)?)
            }
            _ => sealer,
        }))
    }

    /// The plugin cipher this sealer seals with (its content subkeys seal
    /// message bodies, see [`crate::store`]).
    pub fn plugin_cipher(&self) -> &PluginCipher {
        &self.cipher
    }

    /// Seal one secret into the `encp:v1:` envelope.
    pub fn seal(&self, plaintext: &str) -> Result<String> {
        self.cipher.seal(plaintext)
    }

    /// Open a stored value; legacy plaintext is returned verbatim.
    pub fn open(&self, stored: &str) -> Result<String> {
        if PluginCipher::is_sealed(stored) {
            return self
                .cipher
                .open(stored)
                .context("a stored Mail secret could not be opened with this node's key");
        }
        if FieldCipher::is_sealed(stored) {
            let Some(legacy) = &self.legacy else {
                bail!(
                    "a stored Mail secret was sealed by an older ryu-mail with RYU_MASTER_KEY; \
                     start it once with the same RYU_MASTER_KEY to migrate it"
                );
            };
            return legacy.open(stored).context(
                "a stored Mail secret could not be opened; RYU_MASTER_KEY differs from the key that sealed it",
            );
        }
        if ryu_crypto::looks_sealed(stored) {
            bail!("a stored Mail secret is sealed under an unknown key scheme");
        }
        Ok(stored.to_owned())
    }

    /// Whether `stored` is already in the current envelope (no reseal needed).
    pub fn is_current(stored: &str) -> bool {
        PluginCipher::is_sealed(stored)
    }
}

fn decode_master_key(encoded: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .context("RYU_MASTER_KEY must be base64")?;
    <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| anyhow!("RYU_MASTER_KEY must decode to exactly 32 bytes"))
}

/// The older Mail scheme's cipher: an HKDF subkey of the raw master key.
fn legacy_cipher(master: &[u8; 32]) -> FieldCipher {
    let mut subkey = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(LEGACY_SUBKEY_SALT), master)
        .expand(LEGACY_SUBKEY_INFO, &mut subkey)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    FieldCipher::new(&subkey)
}

/// Whether a stored value carries any Ryu envelope.
pub fn is_sealed(stored: &str) -> bool {
    ryu_crypto::looks_sealed(stored)
}

/// Seal `plaintext`. Without a sealer this is an error: Mail never stores a
/// secret in plaintext.
pub fn seal_with(sealer: Option<&SecretSealer>, plaintext: &str) -> Result<String> {
    match sealer {
        Some(sealer) => sealer.seal(plaintext),
        None => Err(anyhow!(
            "ryu-mail has no sealing key, so it cannot store a secret; run it from Ryu Core \
             or set RYU_MASTER_KEY"
        )),
    }
}

/// Open a stored value. A sealed value without a configured key is an error,
/// never an empty or placeholder secret: an empty HMAC key would let anyone sign.
pub fn open_with(sealer: Option<&SecretSealer>, stored: &str) -> Result<String> {
    match sealer {
        Some(sealer) => sealer.open(stored),
        None if is_sealed(stored) => Err(anyhow!(
            "a stored Mail secret is sealed but ryu-mail has no sealing key"
        )),
        None => Ok(stored.to_owned()),
    }
}

/// A fixed-key sealer for tests (never resolves a process key).
#[cfg(test)]
pub(crate) fn test_sealer(byte: u8) -> SecretSealer {
    let subkey = base64::engine::general_purpose::STANDARD.encode([byte; 32]);
    SecretSealer::new(PluginCipher::from_subkey_b64(PLUGIN_ID, &subkey).expect("test subkey"))
}

/// The older scheme, as a pre-change ryu-mail sealed with `RYU_MASTER_KEY`.
#[cfg(test)]
pub(crate) fn legacy_seal(master: &[u8; 32], plaintext: &str) -> String {
    legacy_cipher(master).seal(plaintext).expect("legacy seal")
}

#[cfg(test)]
mod tests {
    use super::{decode_master_key, is_sealed, legacy_seal, open_with, seal_with, test_sealer};
    use base64::Engine as _;

    #[test]
    fn sealed_values_round_trip_and_plaintext_passes_through() {
        let sealer = test_sealer(7);
        let sealed = sealer.seal("whsec_secret").unwrap();
        assert!(sealed.starts_with("encp:v1:"), "{sealed}");
        assert!(is_sealed(&sealed));
        assert!(!sealed.contains("whsec_secret"));
        assert_eq!(sealer.open(&sealed).unwrap(), "whsec_secret");
        // A row written before sealing existed still reads.
        assert_eq!(sealer.open("legacy-plaintext").unwrap(), "legacy-plaintext");
    }

    #[test]
    fn a_different_key_cannot_open_and_a_missing_key_fails_closed() {
        let sealed = test_sealer(7).seal("secret").unwrap();
        assert!(test_sealer(8).open(&sealed).is_err());
        assert!(open_with(None, &sealed).is_err());
        assert_eq!(open_with(None, "plain").unwrap(), "plain");
        // No key, no plaintext write.
        assert!(seal_with(None, "plain").is_err());
    }

    #[test]
    fn values_from_the_older_master_key_scheme_open_only_with_that_key() {
        let old = legacy_seal(&[9; 32], "old-secret");
        assert!(old.starts_with("enc:v1:"));
        assert!(test_sealer(7).open(&old).is_err());
        let sealer = test_sealer(7).with_legacy_master_key(&[9; 32]);
        assert_eq!(sealer.open(&old).unwrap(), "old-secret");
        let wrong = test_sealer(7).with_legacy_master_key(&[1; 32]);
        assert!(wrong.open(&old).is_err());
        // The legacy subkey is not the raw master key.
        assert!(ryu_crypto::FieldCipher::new(&[9; 32]).open(&old).is_err());
    }

    #[test]
    fn malformed_master_keys_are_refused() {
        assert!(decode_master_key("not base64!").is_err());
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        assert!(decode_master_key(&short).is_err());
    }
}
