//! Shared Ryu sidecar data-directory seam.

use std::path::PathBuf;

/// This app's own data dir: `<data dir>/plugin-data/@ryu+mail` (`RYU_PLUGIN_DATA_DIR`
/// when Core spawned the process). Every file the app persists lives under it.
pub fn data_dir() -> PathBuf {
    ryu_sidecar_runtime::plugin_data_dir("@ryu/mail")
}
