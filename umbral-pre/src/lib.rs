//! `umbral-pre` is the Rust implementation of the [Umbral][umbral]
//! threshold proxy re-encryption scheme.
//!
//! Using `umbral-pre`, Alice (the data owner) can delegate decryption rights to Bob
//! for any ciphertext intended to her, through a re-encryption process
//! performed by a set of semi-trusted proxies or Ursulas.
//! When a threshold of these proxies participate by performing re-encryption,
//! Bob is able to combine these independent re-encryptions and decrypt the original message
//! using his private key.
//!
//! ## Available feature flags
//!
//! * `default-rng` - adds methods that use the system RNG (default).
//! * `serde-support` - implements `serde`-based serialization and deserialization.
//! * `bindings-python` - adds a `bindings_python` submodule allowing dependent crates
//!        to use and re-export some of the Python-wrapped Umbral types.
//! * `bindings-wasm` - adds a `bindings_wasm` submodule allowing dependent crates
//!        to use and re-export some of the WASM-wrapped Umbral types.
//!
//! # Usage
//!
//! ```
//! use umbral_pre::*;
//!
//! // As in any public-key cryptosystem, users need a pair of public and private keys.
//!
//! // Key Generation (on Alice's side)
//! let alice_sk = SecretKey::random();
//! let alice_pk = alice_sk.public_key();
//!
//! // Key Generation (on Bob's side)
//! let bob_sk = SecretKey::random();
//! let bob_pk = bob_sk.public_key();
//!
//! // Key Generation (on Proxy's side)
//! let proxy_sks: Vec<_> = (0..3).map(|_| SecretKey::random()).collect();
//! let proxy_pks: Vec<_> = proxy_sks.iter().map(|sk| sk.public_key()).collect();
//! let proxy_pks_ref: Vec<_> = proxy_pks.iter().map(|pk| pk).collect();
//!
//! // Now let's encrypt data with Alice's public key.
//! // Invocation of `encrypt()` returns both the ciphertext and a capsule.
//! // Note that anyone with Alice's public key can perform this operation.
//!
//! let plaintext = b"peace at dawn";
//! let (capsule, ciphertext) = encrypt(&alice_pk, plaintext).unwrap();
//!
//! // Verify capsule
//! assert!(capsule.verify());
//!
//! // Since data was encrypted with Alice's public key, Alice can open the capsule
//! // and decrypt the ciphertext with her private key.
//!
//! let plaintext_alice = decrypt(&alice_sk, &capsule, &ciphertext).unwrap();
//! assert_eq!(&plaintext_alice as &[u8], plaintext);
//!
//! // When Alice wants to grant Bob access to open her encrypted messages,
//! // she creates re-encryption key fragments, or "kfrags", which are then
//! // sent to `shares` proxies or Ursulas.
//!
//! let num_shares = 3; // how many fragments to create
//! let threshold = 2; // how many should be enough to decrypt
//!  // proxies' public keys are used for encrypting kfrags
//! let delegation = delegate(&alice_sk, threshold, num_shares, &proxy_pks_ref).unwrap();
//!
//! // Simulate network transfer
//! let delegation_back = Delegation::from_bytes(delegation.to_bytes()).unwrap();
//!
//! // Everyone can verify public parameters in delegation
//! delegation_back.verify_public(threshold, num_shares).unwrap();
//!
//! // proxy decrypts encrypted_kfrag to obtain kfrag and verify kfrag to obtain verified_kfrag
//! let verified_kfrags: Vec<_> = delegation_back.encrypted_kfrags.iter().zip(proxy_sks.iter())
//!          .map(|(ek, sk)| ek.decrypt(sk).unwrap().verify().unwrap()).collect();
//!
//! // Bob asks several proxies to re-encrypt the capsule so he can open it.
//! // Each proxy performs re-encryption on the capsule using the kfrag provided by Alice,
//! // obtaining this way a "capsule fragment", or cfrag.
//!  let cfrags: Vec<CapsuleFrag> = verified_kfrags.into_iter()
//!           .map(|vkfrag| reencrypt(&bob_pk, &capsule, vkfrag))
//!           .collect();
//!
//! // Simulate network transfer
//! let cfrags_back: Vec<_> = cfrags.iter()
//!           .map(|cfrag| CapsuleFrag::from_array(&cfrag.to_array()).unwrap())
//!           .collect();
//!
//! // Bob collects the resulting cfrags from several proxies and verifies cfrags.
//! // Bob must gather at least `threshold number of`cfrags in order to open the capsule.
//! let verified_cfrags: Vec<_> = cfrags_back
//!             .into_iter()
//!             .zip(delegation_back.encrypted_kfrags.iter())
//!             .map(|(cfrag, ek)| {
//!                 cfrag
//!                     .verify(&capsule, ek, &bob_pk)
//!                     .unwrap()
//!             })
//!             .collect();
//!
//! // Finally, Bob opens the capsule by using at least `threshold` cfrags,
//! // and then decrypts the re-encrypted ciphertext.
//! let verified_cfrags_ref: Vec<_> = verified_cfrags[0..threshold as usize].iter()
//!            .map(|vc| vc).collect();
//!
//! let plaintext_bob = decrypt_reencrypted(
//!             &bob_sk,
//!             &alice_pk,
//!             &capsule,
//!             &verified_cfrags_ref,
//!             &ciphertext,
//!         ).unwrap();
//!
//! assert_eq!(&plaintext_bob as &[u8], plaintext);
//! ```
//!
//! [umbral]: https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf

#![doc(html_root_url = "https://docs.rs/umbral-pre")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![no_std]
// Allows us to mark items in the documentation as gated under specific features.
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

#[cfg(feature = "bench-internals")]
pub mod bench; // Re-export some internals for benchmarks.

#[cfg(feature = "bindings-python")]
pub mod bindings_python;
#[cfg(feature = "bindings-wasm")]
pub mod bindings_wasm;

mod capsule;
mod capsule_frag;
mod curve;
mod dem;
mod hashing;
mod hashing_ds;
mod key_frag;
mod keys;

mod pre;
mod secret_box;
mod traits;

#[cfg(any(feature = "serde-support", feature = "bindings-wasm"))]
mod serde;

pub use capsule::{Capsule, OpenReencryptedError};
pub use capsule_frag::{CapsuleFrag, CapsuleFragVerificationError, VerifiedCapsuleFrag};
pub use dem::{DecryptionError, EncryptionError};
pub use key_frag::{EncryptedKeyFrag, KeyFrag, KeyFragVerificationError, VerifiedKeyFrag};
pub use keys::{get_digest, PublicKey, SecretKey, SecretKeyFactory, Signature, Signer};
pub use pre::{
    decrypt, decrypt_reencrypted, delegate_with_rng, encrypt_with_rng, reencrypt_with_rng,
    Delegation, DelegationError, ReencryptionError,
};
pub use secret_box::{CanBeZeroizedOnDrop, SecretBox};
pub use traits::{
    ConstructionError, DeserializableFromArray, DeserializationError, HasTypeName,
    RepresentableAsArray, SerializableToArray, SerializableToSecretArray, SizeMismatchError,
};

#[cfg(feature = "default-rng")]
pub use pre::{delegate, encrypt, reencrypt};
