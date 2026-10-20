//! RedOS kernel — external build script.
//!
//! Cargo does not track libraries passed via command-line link args, so an
//! incrementally rebuilt `build/libredcrypto.free.a` would silently NOT
//! relink the kernel (stale crypto shipping in a green build — observed and
//! fixed in v0.3.0 review). This script makes the dependency explicit.
//!
//! CEP: CEP-2 | Complete (build tooling)
//! Cost: O(1) stat calls per rebuild decision.
//! Fail: a missing archive fails at link time (named rust-lld error), not
//!       silently.
fn main() {
    println!("cargo:rerun-if-changed=../build/libredcrypto.free.a");
    println!("cargo:rerun-if-changed=../crypto/src/aes.c");
    println!("cargo:rerun-if-changed=../crypto/src/gcm.c");
    println!("cargo:rerun-if-changed=../crypto/include/red/crypto.h");
    println!("cargo:rustc-link-search=native=../build");
    println!("cargo:rustc-link-arg=-lredcrypto.free");
}
