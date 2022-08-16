//! Rust benchmarks are located in an external module, and cannot access private functions.
//! This module re-exports some internals for the purposes of benchmarking.
//! Should not be used by regular users.

use rand_core::OsRng;

use crate::capsule::{Capsule, KeySeed, OpenReencryptedError};
use crate::capsule_frag::CapsuleFrag;
use crate::keys::{PublicKey, SecretKey};
use crate::secret_box::SecretBox;

/// Exported `Capsule::from_public_key()` for benchmark purposes.
pub fn capsule_from_public_key(delegating_pk: &PublicKey) -> (Capsule, SecretBox<KeySeed>) {
    Capsule::from_public_key(&mut OsRng, delegating_pk)
}

/// Exported `Capsule::open_original()` for benchmark purposes.
pub fn capsule_open_original(capsule: &Capsule, delegating_sk: &SecretKey) -> SecretBox<KeySeed> {
    capsule.derive_key(delegating_sk)
}

/// Exported `Capsule::open_reencrypted()` for benchmark purposes.
pub fn capsule_derive_key_reencrypted(
    capsule: &Capsule,
    reader_sk: &SecretKey,
    delegator_pk: &PublicKey,
    cfrags: &[&CapsuleFrag],
) -> Result<SecretBox<KeySeed>, OpenReencryptedError> {
    capsule.derive_key_reencrypted(reader_sk, delegator_pk, cfrags)
}
