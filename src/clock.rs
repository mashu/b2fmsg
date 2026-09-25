//! Wall clock and entropy that work both natively and in the browser.

use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Milliseconds since the Unix epoch.
#[cfg(not(target_arch = "wasm32"))]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Milliseconds since the Unix epoch (`Date.now()` in the browser).
#[cfg(target_arch = "wasm32")]
pub fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

pub fn now_secs() -> i64 {
    (now_ms() / 1000) as i64
}

/// Not cryptographic: just enough to keep message IDs unique.
pub fn entropy() -> u64 {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = seed();
    base ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

#[cfg(not(target_arch = "wasm32"))]
fn seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    nanos ^ (u64::from(std::process::id()) << 32)
}

#[cfg(target_arch = "wasm32")]
fn seed() -> u64 {
    let r = (js_sys::Math::random() * 9_007_199_254_740_992.0) as u64;
    r ^ (js_sys::Date::now() as u64).rotate_left(21)
}
