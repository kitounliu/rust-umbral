//use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use typenum::{op, U4};

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::curve::{CurvePoint, CurveScalar, NonZeroCurveScalar};
use crate::dem::{DecryptionError, EncryptionError, DEM};
use crate::hashing_ds::hash_points_to_key;
use crate::keys::{PublicKey, SecretKey};

use crate::secret_box::SecretBox;
use crate::traits::{
    fmt_public, ConstructionError, DeserializableFromArray, DeserializationError, HasTypeName,
    RepresentableAsArray, SerializableToArray,
};

#[cfg(feature = "serde-support")]
use crate::serde::{serde_deserialize, serde_serialize, Representation};
use crate::SizeMismatchError;

type ScalarSize = <CurveScalar as RepresentableAsArray>::Size;
type PointSize = <CurvePoint as RepresentableAsArray>::Size;

/// A fragment of the encrypting party's key used to create a [`CapsuleFrag`](`crate::CapsuleFrag`).
#[derive(Clone, Debug, PartialEq)]
pub struct KeyFrag {
    pub(crate) index: u32,
    pub(crate) key: CurveScalar,
    pub(crate) point_u: CurvePoint,
}

impl RepresentableAsArray for KeyFrag {
    type Size = op!(U4 + ScalarSize + PointSize);
}

impl SerializableToArray for KeyFrag {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.index
            .to_array()
            .concat(self.key.to_array())
            .concat(self.point_u.to_array())
    }
}

impl DeserializableFromArray for KeyFrag {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        let (index, rest) = u32::take(*arr)?;
        let (key, rest) = CurveScalar::take(rest)?;
        let point_u = CurvePoint::take_last(rest)?;
        Ok(Self {
            index,
            key,
            point_u,
        })
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl Serialize for KeyFrag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_serialize(self, serializer, Representation::Base64)
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl<'de> Deserialize<'de> for KeyFrag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_deserialize(deserializer, Representation::Base64)
    }
}

impl HasTypeName for KeyFrag {
    fn type_name() -> &'static str {
        "KeyFrag"
    }
}

impl fmt::Display for KeyFrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public::<Self>(self, f)
    }
}

impl KeyFrag {
    fn from_base(non_zero_index: u32, base: &KeyFragBase) -> Self {
        let share_index = NonZeroCurveScalar::from_u32(non_zero_index);
        // The re-encryption key share is the result of evaluating the generating
        // polynomial for the index value
        let key = poly_eval(&base.coefficients, &share_index);
        let g = CurvePoint::generator();
        let point_u = &g * &key;

        Self {
            index: non_zero_index,
            key,
            point_u,
        }
    }

    fn encrypt_with_rng(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        proxy_pk: &PublicKey,
    ) -> Result<EncryptedKeyFrag, EncryptionError> {
        let g = CurvePoint::generator();
        let r = SecretBox::new(NonZeroCurveScalar::random(rng));
        let point_r = &g * r.as_secret();
        let pk = proxy_pk.to_point();
        let pk_r = &pk * r.as_secret();
        let points = &[&g, &pk, &point_r, &pk_r];
        let h = hash_points_to_key(points);
        let key_seed = SecretBox::new(CurveScalar::from(&h).to_array());
        let dem = DEM::new(&key_seed);
        let plaintext = self.key.to_array();
        let authenticated_data = self.point_u.to_array();
        let point_u = self.point_u.clone();
        dem.encrypt(rng, plaintext.as_slice(), authenticated_data.as_slice())
            .map(|cipher| EncryptedKeyFrag {
                index: self.index,
                point_r,
                cipher,
                point_u,
            })
    }

    /// Verifies the integrity of the key fragment, given the signing key,
    /// and (optionally) the encrypting party's and decrypting party's keys.
    ///
    /// If [`generate_kfrags()`](`crate::generate_kfrags()`) was called with `true`
    /// for `sign_delegating_key` or `sign_receiving_key`, and the respective key
    /// is not provided, the verification fails.
    pub fn verify(self) -> Result<VerifiedKeyFrag, (KeyFragVerificationError, Self)> {
        let g = CurvePoint::generator();
        let t = &g * &self.key;
        if self.point_u != t {
            return Err((KeyFragVerificationError::VerificationFailed, self));
        }

        Ok(VerifiedKeyFrag { kfrag: self })
    }

    /// Explicitly skips verification.
    /// Useful in cases when the verifying keys are impossible to obtain independently.
    ///
    /// **Warning:** make sure you considered the implications of not enforcing verification.
    pub fn skip_verification(self) -> VerifiedKeyFrag {
        VerifiedKeyFrag { kfrag: self }
    }
}

/// A fragment of the encrypting party's key used to create a [`CapsuleFrag`](`crate::CapsuleFrag`).
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptedKeyFrag {
    pub(crate) index: u32,
    pub(crate) cipher: Vec<u8>,
    pub(crate) point_r: CurvePoint,
    pub(crate) point_u: CurvePoint,
}

impl EncryptedKeyFrag {
    pub fn decrypt(&self, proxy_sk: &SecretKey) -> Result<KeyFrag, DecryptionError> {
        let g = CurvePoint::generator();
        let pk = proxy_sk.public_key().to_point();
        let pk_r = &self.point_r * proxy_sk.to_secret_scalar().as_secret();
        let points = &[&g, &pk, &self.point_r, &pk_r];
        let h = hash_points_to_key(points);
        let key_seed = SecretBox::new(CurveScalar::from(&h).to_array());

        let dem = DEM::new(&key_seed);
        let authenticated_data = self.point_u.to_array();
        dem.decrypt(&self.cipher, authenticated_data.as_slice())
            .map(|plaintext| {
                let key = CurveScalar::from_bytes(plaintext).unwrap();
                let point_u = self.point_u.clone();
                KeyFrag {
                    index: self.index,
                    key,
                    point_u,
                }
            })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let size = self.cipher.len() as u32;
        assert_eq!(size as usize, self.cipher.len());

        let mut result = Vec::<u8>::new();
        result.extend_from_slice(&self.index.to_be_bytes());
        result.extend_from_slice(size.to_be_bytes().as_slice());
        result.extend_from_slice(self.cipher.as_ref());
        result.extend_from_slice(&self.point_r.to_array().as_slice());
        result.extend_from_slice(&self.point_u.to_array().as_slice());

        result
    }

    pub fn from_bytes(data: impl AsRef<[u8]>) -> Result<Self, DeserializationError> {
        let d = data.as_ref();
        let index = u32::from_be_bytes(d[0..4].try_into().unwrap());
        let length = u32::from_be_bytes(d[4..8].try_into().unwrap()) as usize;
        let cipher = d[8..length + 8].to_vec();

        let psize = CurvePoint::serialized_size();
        let mut offset = length + 8;
        let mut end = offset + psize;
        let point_r = CurvePoint::from_bytes(&d[offset..end])?;
        offset = end;
        end = offset + psize;
        let point_u = CurvePoint::from_bytes(&d[offset..end])?;

        if end != d.len() {
            return Err(DeserializationError::SizeMismatch(SizeMismatchError::new(
                d.len(),
                end + 1,
            )));
        }

        Ok(EncryptedKeyFrag {
            index,
            cipher,
            point_r,
            point_u,
        })
    }
}

impl HasTypeName for EncryptedKeyFrag {
    fn type_name() -> &'static str {
        "EncryptedKeyFrag"
    }
}

impl fmt::Display for EncryptedKeyFrag {
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

/// Possible errors that can be returned by [`KeyFrag::verify`].
#[derive(Debug, PartialEq)]
pub enum KeyFragVerificationError {
    /// Inconsistent internal state leading to commitment verification failure.
    VerificationFailed,
}

impl fmt::Display for KeyFragVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerificationFailed => write!(f, "Invalid key or point_u"),
        }
    }
}

/// Verified key fragment, good for reencryption.
/// Can be serialized, but cannot be deserialized directly.
/// It can only be obtained from [`KeyFrag::verify`] or [`KeyFrag::skip_verification`].
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "bindings-wasm", derive(Serialize, Deserialize))]
pub struct VerifiedKeyFrag {
    kfrag: KeyFrag,
}

impl RepresentableAsArray for VerifiedKeyFrag {
    type Size = <KeyFrag as RepresentableAsArray>::Size;
}

impl SerializableToArray for VerifiedKeyFrag {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.kfrag.to_array()
    }
}

impl HasTypeName for VerifiedKeyFrag {
    fn type_name() -> &'static str {
        "VerifiedKeyFrag"
    }
}

impl fmt::Display for VerifiedKeyFrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public::<Self>(self, f)
    }
}

impl VerifiedKeyFrag {
    pub(crate) fn from_base(non_zero_index: u32, base: &KeyFragBase) -> Self {
        Self {
            //   kfrag: KeyFrag::from_base(rng, index, base, sign_delegating_key, sign_receiving_key),
            kfrag: KeyFrag::from_base(non_zero_index, base),
        }
    }

    pub(crate) fn encrypt_with_rng(
        self,
        rng: &mut (impl CryptoRng + RngCore),
        proxy_pk: &PublicKey,
    ) -> Result<EncryptedKeyFrag, EncryptionError> {
        self.unverify().encrypt_with_rng(rng, proxy_pk)
    }

    /// Restores a verified keyfrag directly from serialized bytes,
    /// skipping [`KeyFrag::verify`] call.
    ///
    /// Intended for internal storage;
    /// make sure that the bytes come from a trusted source.
    pub fn from_verified_bytes(data: impl AsRef<[u8]>) -> Result<Self, DeserializationError> {
        KeyFrag::from_bytes(data).map(|kfrag| Self { kfrag })
    }

    /// Clears the verification status from the keyfrag.
    /// Useful for the cases where it needs to be put in the protocol structure
    /// containing [`KeyFrag`] types (since those are the ones
    /// that can be serialized/deserialized freely).
    pub fn unverify(self) -> KeyFrag {
        self.kfrag
    }
}

pub(crate) struct KeyFragBase {
    coefficients: Vec<SecretBox<NonZeroCurveScalar>>,
}

impl KeyFragBase {
    pub(crate) fn new(
        rng: &mut (impl CryptoRng + RngCore),
        delegator_sk: &SecretKey,
        threshold: u32,
    ) -> Self {
        // Coefficients of the generating polynomial
        let coefficient0 = delegator_sk.to_secret_scalar();

        let mut coefficients =
            Vec::<SecretBox<NonZeroCurveScalar>>::with_capacity(threshold as usize);
        coefficients.push(coefficient0);
        for _i in 1..threshold as usize {
            coefficients.push(SecretBox::new(NonZeroCurveScalar::random(rng)));
        }

        Self { coefficients }
    }

    pub(crate) fn get_public_coeffs(&self) -> Vec<CurvePoint> {
        let g = CurvePoint::generator();
        self.coefficients
            .iter()
            .map(|a| &g * a.as_secret())
            .collect()
    }
}

// Coefficients of the generating polynomial
fn poly_eval(coeffs: &[SecretBox<NonZeroCurveScalar>], x: &NonZeroCurveScalar) -> CurveScalar {
    let mut result: SecretBox<CurveScalar> =
        SecretBox::new(coeffs[coeffs.len() - 1].as_secret().into());
    for i in (0..coeffs.len() - 1).rev() {
        // Keeping the intermediate results zeroized as well
        let temp = SecretBox::new(result.as_secret() * x);
        *result.as_mut_secret() = temp.as_secret() + coeffs[i].as_secret();
    }
    // This is not a secret anymore
    *result.as_secret()
}

#[cfg(test)]
mod tests {

    //use alloc::boxed::Box;

    use rand_core::OsRng;

    use super::{KeyFrag, KeyFragBase};

    use crate::{DeserializableFromArray, PublicKey, SecretKey, SerializableToArray};

    #[cfg(feature = "serde-support")]
    use crate::serde::tests::{check_deserialization, check_serialization};

    use crate::key_frag::EncryptedKeyFrag;
    #[cfg(feature = "serde-support")]
    use crate::serde::Representation;
    use alloc::{vec, vec::Vec};

    fn prepare_kfrags() -> (PublicKey, Vec<KeyFrag>) {
        let delegator_sk = SecretKey::random();
        let delegator_pk = delegator_sk.public_key();

        let base = KeyFragBase::new(&mut OsRng, &delegator_sk, 2);
        let kfrags = vec![
            KeyFrag::from_base(1, &base),
            KeyFrag::from_base(2, &base),
            KeyFrag::from_base(3, &base),
        ];

        (delegator_pk, kfrags)
    }

    #[test]
    fn test_verify() {
        let (_delegator_pk, kfrags) = prepare_kfrags();
        let kfrag_arr = kfrags[0].to_array();
        let kfrag = KeyFrag::from_array(&kfrag_arr).unwrap();

        // Check that the kfrag serializes to the same thing as the verified kfrag
        assert_eq!(kfrag.to_array(), kfrag_arr);
        kfrag.verify().unwrap();
    }

    #[test]
    fn test_encryption() {
        let (_delegator_pk, kfrags) = prepare_kfrags();
        let proxy_sk = SecretKey::random();
        let proxy_pk = proxy_sk.public_key();
        let encrypted_kfrag: EncryptedKeyFrag =
            kfrags[0].encrypt_with_rng(&mut OsRng, &proxy_pk).unwrap();
        let dec_kfrag = encrypted_kfrag.decrypt(&proxy_sk).unwrap();
        assert_eq!(dec_kfrag.to_array(), kfrags[0].to_array());

        let b = encrypted_kfrag.to_bytes();
        let e = EncryptedKeyFrag::from_bytes(b).unwrap();
        assert_eq!(e, encrypted_kfrag)
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn test_serde_serialization() {
        let (_delegating_pk, kfrags) = prepare_kfrags();

        let vkfrag = kfrags[0].clone();
        let kfrag = KeyFrag::from_array(&vkfrag.to_array()).unwrap();

        check_serialization(&kfrag, Representation::Base64);
        check_deserialization(&kfrag);
    }
}
