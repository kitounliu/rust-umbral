//! The high-level functional reencryption API.
use alloc::format;
use alloc::string::String;
use core::fmt;

use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "default-rng")]
use rand_core::OsRng;

use crate::capsule::{Capsule, OpenReencryptedError};
use crate::capsule_frag::{CapsuleFrag, VerifiedCapsuleFrag};
use crate::dem::{DecryptionError, EncryptionError, DEM};
use crate::key_frag::{EncryptedKeyFrag, KeyFragBase, VerifiedKeyFrag};
use crate::keys::{PublicKey, SecretKey};
use crate::traits::{
    DeserializableFromArray, DeserializationError, HasTypeName, RepresentableAsArray,
    SerializableToArray, SizeMismatchError,
};

use crate::curve::{CurvePoint, NonZeroCurveScalar};
//use crate::{DeserializableFromArray, DeserializableFromBytes, DeserializationError, RepresentableAsArray, SizeMismatchError, HasTypeName};
//use alloc::boxed::Box;
use alloc::vec::Vec;
//use wasm_bindgen::__rt::std::io::Read;

/// Errors that can happen when decrypting a reencrypted ciphertext.
#[derive(Debug, PartialEq)]
pub enum ReencryptionError {
    /// An error when opening a capsule. See [`OpenReencryptedError`] for the options.
    OnOpen(OpenReencryptedError),
    /// An error when decrypting the ciphertext. See [`DecryptionError`] for the options.
    OnDecryption(DecryptionError),
}

impl fmt::Display for ReencryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OnOpen(err) => write!(f, "Re-encryption error on open: {}", err),
            Self::OnDecryption(err) => write!(f, "Re-encryption error on decryption: {}", err),
        }
    }
}

/// Errors that can happen when decrypting a reencrypted ciphertext.
#[derive(Debug, PartialEq)]
pub enum DelegationError {
    /// An error when opening a capsule. See [`OpenReencryptedError`] for the options.
    InvalidSize(String),
    /// An error when decrypting the ciphertext. See [`DecryptionError`] for the options.
    EncryptionError(EncryptionError),
    IncorrectIndex(String),
    VerificationFailed(usize),
}

impl fmt::Display for DelegationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize(err) => write!(f, "Delegation error on size: {}", err),
            Self::EncryptionError(err) => write!(f, "Delegation error on encryption: {}", err),
            Self::IncorrectIndex(err) => write!(f, "Delegation error on size: {}", err),
            Self::VerificationFailed(err) => {
                write!(f, "Delegation error on the verification of point U_{}", err)
            }
        }
    }
}

/// Encapsulated symmetric key used to encrypt the plaintext.
#[derive(Clone, Debug, PartialEq)]
pub struct Delegation {
    pub threshold: u32,
    pub num_shares: u32,
    pub pub_coeffs: Vec<CurvePoint>,
    pub encrypted_kfrags: Vec<EncryptedKeyFrag>,
}

impl Delegation {
    pub fn verify_public(&self) -> Result<(), DelegationError> {
        if self.threshold == 0 || self.num_shares == 0 {
            return Err(DelegationError::InvalidSize(format!(
                "Threshold {} and number of shares {} cannot be zero",
                self.threshold, self.num_shares
            )));
        }

        if self.threshold > self.num_shares {
            return Err(DelegationError::InvalidSize(format!(
                "Threshold {} cannot be greater than total number of shares {}",
                self.threshold, self.num_shares
            )));
        }

        if self.threshold as usize != self.pub_coeffs.len() {
            return Err(DelegationError::InvalidSize(format!(
                "Threshold {} does not match the length of public coefficients {}",
                self.threshold,
                self.pub_coeffs.len()
            )));
        }

        if self.num_shares as usize != self.encrypted_kfrags.len() {
            return Err(DelegationError::InvalidSize(
                format! {"Number {} of shares does not match the length of encrypted kfrags {}", self.num_shares, self.encrypted_kfrags.len()},
            ));
        }

        for (i, encrypted_kfrag) in self.encrypted_kfrags.iter().enumerate() {
            if i + 1 != encrypted_kfrag.index as usize {
                return Err(DelegationError::IncorrectIndex(
                    format! {"{}-th index should be {} instead of {}", i, i + 1, encrypted_kfrag.index as usize},
                ));
            }

            let index = NonZeroCurveScalar::from_u32(encrypted_kfrag.index);
            let mut exp = index.clone();
            let mut sum = self.pub_coeffs[0];
            for a in self.pub_coeffs.iter().skip(1) {
                sum = &sum + &(a * &exp);
                exp = &exp * &index;
            }
            if encrypted_kfrag.point_u != sum {
                return Err(DelegationError::VerificationFailed(i));
            }
        }

        Ok(())
    }

    // verify the i-th encrypted_kfrag
    pub fn verify_public_with_index(&self, i: usize) -> Result<(), DelegationError> {
        if self.threshold == 0 || self.num_shares == 0 {
            return Err(DelegationError::InvalidSize(format!(
                "Threshold {} and number of shares {} cannot be zero",
                self.threshold, self.num_shares
            )));
        }

        if self.threshold > self.num_shares {
            return Err(DelegationError::InvalidSize(format!(
                "Threshold {} cannot be greater than total number of shares {}",
                self.threshold, self.num_shares
            )));
        }

        if self.threshold as usize != self.pub_coeffs.len() {
            return Err(DelegationError::InvalidSize(format!(
                "Threshold {} does not match the length of public coefficients {}",
                self.threshold,
                self.pub_coeffs.len()
            )));
        }

        if self.num_shares as usize != self.encrypted_kfrags.len() {
            return Err(DelegationError::InvalidSize(
                format! {"Number {} of shares does not match the length {} of encrypted kfrags", self.num_shares, self.encrypted_kfrags.len()},
            ));
        }

        if i + 1 != self.encrypted_kfrags[i].index as usize {
            return Err(DelegationError::IncorrectIndex(
                format! {"{}-th index should be {} instead of {}", i, i + 1, self.encrypted_kfrags[i].index},
            ));
        }

        let index = NonZeroCurveScalar::from_u32(self.encrypted_kfrags[i].index);
        let mut exp = index.clone();
        let mut sum = self.pub_coeffs[0];
        for a in self.pub_coeffs.iter().skip(1) {
            sum = &sum + &(a * &exp);
            exp = &exp * &index;
        }
        if self.encrypted_kfrags[i].point_u != sum {
            return Err(DelegationError::VerificationFailed(i));
        }

        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        assert_eq!(self.threshold as usize, self.pub_coeffs.len());
        assert_eq!(self.num_shares as usize, self.encrypted_kfrags.len());

        let mut result = Vec::<u8>::new();
        result.extend_from_slice(&self.threshold.to_be_bytes());
        result.extend_from_slice(&self.num_shares.to_be_bytes());

        for p in self.pub_coeffs.iter() {
            result.extend_from_slice(p.to_array().as_slice());
        }

        for e in self.encrypted_kfrags.iter() {
            let e_bytes = e.to_bytes();
            let length: u32 = e_bytes.len().try_into().unwrap();
            result.extend_from_slice(&length.to_be_bytes());
            result.extend_from_slice(&e_bytes);
        }

        result
    }

    pub fn from_bytes(data: impl AsRef<[u8]>) -> Result<Self, DeserializationError> {
        let d = data.as_ref();
        let threshold = u32::from_be_bytes(d[0..4].try_into().unwrap());
        let num_shares = u32::from_be_bytes(d[4..8].try_into().unwrap());

        let mut pub_coeffs = Vec::<CurvePoint>::new();
        let psize = CurvePoint::serialized_size();
        let mut offset = 8;
        let mut end = offset + psize;
        for _ in 0..threshold as usize {
            pub_coeffs.push(CurvePoint::from_bytes(&d[offset..end])?);
            offset = end;
            end = end + psize;
        }
        let mut encrypted_kfrags = Vec::<EncryptedKeyFrag>::new();
        for _ in 0..num_shares as usize {
            end = offset + 4;
            let length = u32::from_be_bytes(d[offset..end].try_into().unwrap());
            offset = end;
            end = offset + length as usize;
            encrypted_kfrags.push(EncryptedKeyFrag::from_bytes(&d[offset..end])?);
            offset = end;
        }

        if end != d.len() {
            return Err(DeserializationError::SizeMismatch(SizeMismatchError::new(
                d.len(),
                end + 1,
            )));
        }

        Ok(Self {
            threshold,
            num_shares,
            pub_coeffs,
            encrypted_kfrags,
        })
    }
}

impl HasTypeName for Delegation {
    fn type_name() -> &'static str {
        "Delegation"
    }
}

impl fmt::Display for Delegation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        let mut hex_repr = [b'*'; 16]; // exactly 16 bytes long, to fit the encode() result
        hex::encode_to_slice(&bytes[0..8], &mut hex_repr).map_err(|_| fmt::Error)?;
        write!(
            f,
            "{}:{}",
            Self::type_name(),
            String::from_utf8_lossy(&hex_repr)
        )
    }
}

/// Encrypts the given plaintext message using a DEM scheme,
/// and encapsulates the key for later reencryption.
/// Returns the KEM [`Capsule`] and the ciphertext.
pub fn encrypt_with_rng(
    rng: &mut (impl CryptoRng + RngCore),
    delegator_pk: &PublicKey,
    plaintext: &[u8],
) -> Result<(Capsule, Vec<u8>), EncryptionError> {
    let (capsule, key_seed) = Capsule::from_public_key(rng, delegator_pk);
    let dem = DEM::new(&key_seed);
    dem.encrypt(rng, plaintext, &capsule.to_array())
        .map(|ciphertext| (capsule, ciphertext))
}

/// A synonym for [`encrypt`] with the default RNG.
#[cfg(feature = "default-rng")]
#[cfg_attr(docsrs, doc(cfg(feature = "default-rng")))]
pub fn encrypt(
    delegator_pk: &PublicKey,
    plaintext: &[u8],
) -> Result<(Capsule, Vec<u8>), EncryptionError> {
    encrypt_with_rng(&mut OsRng, delegator_pk, plaintext)
}

/// Attempts to decrypt the ciphertext using the receiver's secret key.
pub fn decrypt(
    delegator_sk: &SecretKey,
    capsule: &Capsule,
    ciphertext: impl AsRef<[u8]>,
) -> Result<Vec<u8>, DecryptionError> {
    let key_seed = capsule.derive_key(delegator_sk);
    let dem = DEM::new(&key_seed);
    dem.decrypt(ciphertext, &capsule.to_array())
}

/// Creates `shares` fragments of `delegating_sk`,
/// which will be possible to reencrypt to allow the creator of `receiving_pk`
/// decrypt the ciphertext encrypted with `delegating_sk`.
///
/// `threshold` sets the number of fragments necessary for decryption
/// (that is, fragments created with `threshold > num_frags` will be useless).
///
/// `signer` is used to sign the resulting [`KeyFrag`](`crate::KeyFrag`) objects,
/// which can be later verified by the associated public key.
///
/// If `sign_delegating_key` or `sign_receiving_key` are `true`,
/// the reencrypting party will be able to verify that a [`KeyFrag`](`crate::KeyFrag`)
/// corresponds to given delegating or receiving public keys
/// by supplying them to [`KeyFrag::verify()`](`crate::KeyFrag::verify`).
///
/// Returns a boxed slice of `shares` KeyFrags
#[allow(clippy::too_many_arguments)]
pub fn delegate_with_rng(
    rng: &mut (impl CryptoRng + RngCore),
    delegator_sk: &SecretKey,
    threshold: u32,
    num_shares: u32,
    proxy_pks: &[&PublicKey],
) -> Result<Delegation, DelegationError> {
    let base = KeyFragBase::new(rng, delegator_sk, threshold);
    let pub_coeffs = base.get_public_coeffs();
    if num_shares as usize != proxy_pks.len() {
        return Err(DelegationError::InvalidSize(format!(
            "The number {} of shares does not match the number {} of proxy public keys",
            num_shares,
            proxy_pks.len()
        )));
    }
    if threshold > num_shares {
        return Err(DelegationError::InvalidSize(format!(
            "Threshold {} cannot be greater than the total number {} of shares",
            threshold, num_shares
        )));
    }

    let mut encrypted_kfrags = Vec::<EncryptedKeyFrag>::new();
    for (i, proxy_pk) in proxy_pks.iter().enumerate() {
        let encrypted_kfrag = VerifiedKeyFrag::from_base((i + 1) as u32, &base)
            .encrypt_with_rng(rng, proxy_pk)
            .map_err(|x| DelegationError::EncryptionError(x))?;
        encrypted_kfrags.push(encrypted_kfrag);
    }

    Ok(Delegation {
        threshold,
        num_shares,
        pub_coeffs,
        encrypted_kfrags,
    })
}

/// A synonym for [`delegate_with_rng`] with the default RNG.
#[cfg(feature = "default-rng")]
#[cfg_attr(docsrs, doc(cfg(feature = "default-rng")))]
#[allow(clippy::too_many_arguments)]
pub fn delegate(
    delegator_sk: &SecretKey,
    threshold: u32,
    num_shares: u32,
    proxy_pks: &[&PublicKey],
) -> Result<Delegation, DelegationError> {
    delegate_with_rng(&mut OsRng, delegator_sk, threshold, num_shares, proxy_pks)
}

/// Reencrypts a [`Capsule`] object with a key fragment, creating a capsule fragment.
///
/// Having `threshold` (see [`generate_kfrags()`](`crate::generate_kfrags()`))
/// distinct fragments (along with the original capsule and the corresponding secret key)
/// allows one to decrypt the original plaintext.
///
/// One can call [`KeyFrag::verify()`](`crate::KeyFrag::verify`)
/// before reencryption to check its integrity.
pub fn reencrypt_with_rng(
    rng: &mut (impl CryptoRng + RngCore),
    reader_pk: &PublicKey,
    capsule: &Capsule,
    verified_kfrag: VerifiedKeyFrag,
) -> CapsuleFrag {
    CapsuleFrag::reencrypt(rng, capsule, &verified_kfrag.unverify(), reader_pk)
}

/// A synonym for [`reencrypt_with_rng`] with the default RNG.
#[cfg(feature = "default-rng")]
#[cfg_attr(docsrs, doc(cfg(feature = "default-rng")))]
pub fn reencrypt(
    reader_pk: &PublicKey,
    capsule: &Capsule,
    verified_kfrag: VerifiedKeyFrag,
) -> CapsuleFrag {
    reencrypt_with_rng(&mut OsRng, reader_pk, capsule, verified_kfrag)
}

/// Decrypts the ciphertext using previously reencrypted capsule fragments.
///
/// `decrypting_sk` is the secret key whose associated public key was used in
/// [`generate_kfrags()`](`crate::generate_kfrags()`).
///
/// `delegating_pk` is the public key of the encrypting party.
/// Used to check the validity of decryption.
///
/// One can call [`CapsuleFrag::verify()`](`crate::CapsuleFrag::verify`)
/// before reencryption to check its integrity.
pub fn decrypt_reencrypted<'a>(
    reader_sk: &SecretKey,
    delegator_pk: &PublicKey,
    capsule: &Capsule,
    verified_cfrags: impl AsRef<[&'a VerifiedCapsuleFrag]>,
    ciphertext: impl AsRef<[u8]>,
) -> Result<Vec<u8>, ReencryptionError> {
    let cfrags: Vec<_> = verified_cfrags
        .as_ref()
        .iter()
        .map(|&vc| &vc.cfrag)
        .collect();
    let key_seed = capsule
        .derive_key_reencrypted(reader_sk, delegator_pk, &cfrags)
        .map_err(ReencryptionError::OnOpen)?;
    let dem = DEM::new(&key_seed);
    dem.decrypt(&ciphertext, &capsule.to_array())
        .map_err(ReencryptionError::OnDecryption)
}

#[cfg(test)]
mod tests {

    use alloc::vec::Vec;

    use super::{decrypt, decrypt_reencrypted, delegate, encrypt, reencrypt};
    use crate::{
        get_digest, Capsule, CapsuleFrag, Delegation, DeserializableFromArray, SecretKey,
        SerializableToArray, Signature, Signer,
    };

    #[test]
    fn test_simple_api() {
        /*
        This test models the main interactions between NuCypher actors (i.e., Alice,
        Bob, Data Source, and Ursulas) and artifacts (i.e., public and private keys,
        ciphertexts, capsules, KeyFrags, CapsuleFrags, etc).

        The test covers all the main stages of data sharing with NuCypher:
        key generation, delegation, encryption, decryption by
        Alice, re-encryption by Ursula, and decryption by Bob.
        */

        let threshold: u32 = 2;
        let num: u32 = threshold + 1;

        // Key Generation (Alice)
        let delegator_sk = SecretKey::random();
        let delegator_pk = delegator_sk.public_key();

        let signer = Signer::new(SecretKey::random());
        let signer_pk = signer.verifying_key();

        // Key Generation (Bob)
        let reader_sk = SecretKey::random();
        let reader_pk = reader_sk.public_key();

        // Key Generation (Proxies)
        let proxy_sks: Vec<_> = (0..num as usize).map(|_| SecretKey::random()).collect();
        let proxy_pks: Vec<_> = proxy_sks.iter().map(|sk| sk.public_key()).collect();
        let proxy_pks_ref: Vec<_> = proxy_pks.iter().map(|pk| pk).collect();

        // Encryption by an unnamed data source
        let plaintext = b"peace at dawn";
        let (capsule, ciphertext) = encrypt(&delegator_pk, plaintext).unwrap();

        // Sign ciphertext to prove the data source; this could be Alice if she performs the encryption herself, but it could also be someone else
        // Hash the plaintext first (this could avoid sending plaintext onchain and reduce the onchain verification overhead)
        let capsule_bytes = capsule.to_array().to_vec();
        let cipher_digest = get_digest(&ciphertext);
        let sig = signer.sign_with_aux(&capsule_bytes, &cipher_digest);

        // Simulate network transfer
        let sig_back = Signature::from_bytes(sig.to_array().to_vec()).unwrap();
        assert_eq!(sig_back, sig);
        let capsule_back = Capsule::from_bytes(&capsule_bytes).unwrap();
        assert_eq!(capsule_back, capsule);

        // Recipient verifies signature to confirm the data origin
        assert!(sig_back.verify_with_aux(&signer_pk, &capsule_bytes, &cipher_digest));

        // Decryption by Alice
        let plaintext_alice = decrypt(&delegator_sk, &capsule, &ciphertext).unwrap();
        assert_eq!(&plaintext_alice as &[u8], plaintext);

        // Split Re-Encryption Key Generation (aka Delegation)
        let delegation = delegate(&delegator_sk, threshold, num, &proxy_pks_ref).unwrap();

        // Alice signs delegation -- this can be optional, for example, when delegation is sent onchain which already has a signature in transaction
        let delegation_bytes = delegation.to_bytes();
        let deleg_sig = signer.sign(&delegation_bytes);

        // Simulate network transfer
        let deleg_sig_back = Signature::from_bytes(&deleg_sig.to_array().to_vec()).unwrap();
        assert_eq!(deleg_sig_back, deleg_sig);
        let delegation_back = Delegation::from_bytes(&delegation_bytes).unwrap();
        assert_eq!(delegation_back, delegation);

        // Verify signature
        assert!(deleg_sig_back.verify(&signer_pk, &delegation_bytes));

        // Verify public parameters in delegation
        delegation_back.verify_public().unwrap();

        // Each proxy decrypts its own encrypted_kfrag to obtain kfrag and verifies kfrag
        let verified_kfrags: Vec<_> = delegation_back
            .encrypted_kfrags
            .iter()
            .zip(proxy_sks.iter())
            .map(|(ek, sk)| ek.decrypt(sk).unwrap().verify().unwrap())
            .collect();

        // Bob requests re-encryption to some set of `threshold` proxies
        // Proxy reencrypts capsule
        let cfrags: Vec<_> = verified_kfrags
            .into_iter()
            .map(|vkfrag| reencrypt(&reader_pk, &capsule, vkfrag))
            .collect();

        // Simulate network transfer
        let cfrags_back: Vec<_> = cfrags
            .iter()
            .map(|cfrag| CapsuleFrag::from_array(&cfrag.to_array()).unwrap())
            .collect();
        assert_eq!(cfrags, cfrags_back);

        // If Bob received cfrags from the network, he must check that they are valid
        let verified_cfrags: Vec<_> = cfrags
            .into_iter()
            .zip(delegation_back.encrypted_kfrags.iter())
            .map(|(cfrag, ek)| cfrag.verify(&capsule, ek, &reader_pk).unwrap())
            .collect();

        let verified_cfrags_ref: Vec<_> = verified_cfrags[0..threshold as usize]
            .iter()
            .map(|vc| vc)
            .collect();

        // Decryption by Bob using at least t verified_cfrags
        let plaintext_bob = decrypt_reencrypted(
            &reader_sk,
            &delegator_pk,
            &capsule,
            &verified_cfrags_ref,
            &ciphertext,
        )
        .unwrap();
        assert_eq!(&plaintext_bob as &[u8], plaintext);
    }
}
