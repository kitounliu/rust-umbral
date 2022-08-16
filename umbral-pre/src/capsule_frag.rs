use core::fmt;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use typenum::{op, U4};

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::capsule::Capsule;
use crate::curve::{CurvePoint, CurveScalar, NonZeroCurveScalar};
use crate::hashing_ds::hash_to_cfrag_verification;
use crate::key_frag::{EncryptedKeyFrag, KeyFrag};
use crate::keys::PublicKey;
use crate::secret_box::SecretBox;
use crate::traits::{
    fmt_public, ConstructionError, DeserializableFromArray, DeserializationError, HasTypeName,
    RepresentableAsArray, SerializableToArray,
};

#[cfg(feature = "serde-support")]
use crate::serde::{serde_deserialize, serde_serialize, Representation};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CapsuleFragProof {
    c: CurveScalar,
    z1: CurveScalar,
    z2: CurveScalar,
}

type PointSize = <CurvePoint as RepresentableAsArray>::Size;
type ScalarSize = <CurveScalar as RepresentableAsArray>::Size;
type CapsuleFragProofSize = op!(ScalarSize + ScalarSize + ScalarSize);

impl RepresentableAsArray for CapsuleFragProof {
    type Size = CapsuleFragProofSize;
}

impl SerializableToArray for CapsuleFragProof {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.c
            .to_array()
            .concat(self.z1.to_array())
            .concat(self.z2.to_array())
    }
}

impl DeserializableFromArray for CapsuleFragProof {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        let (c, rest) = CurveScalar::take(*arr)?;
        let (z1, rest) = CurveScalar::take(rest)?;
        let z2 = CurveScalar::take_last(rest)?;
        Ok(Self { c, z1, z2 })
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl Serialize for CapsuleFragProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_serialize(self, serializer, Representation::Base64)
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl<'de> Deserialize<'de> for CapsuleFragProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_deserialize(deserializer, Representation::Base64)
    }
}

impl HasTypeName for CapsuleFragProof {
    fn type_name() -> &'static str {
        "CapsuleFragProof"
    }
}

impl fmt::Display for CapsuleFragProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public::<Self>(self, f)
    }
}

/// Possible errors that can be returned by [`CapsuleFrag::verify`].
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CapsuleFragVerificationError {
    /// Inconsistent indices leading to verification failure
    IndexMismatch(u32, u32),
    /// Inconsistent internal state leading to verification failure
    VerificationFailed,
}

impl fmt::Display for CapsuleFragVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexMismatch(i, j) => write!(
                f,
                "Index {} in cfrag does not match index {} in encrypted kfrag",
                i, j
            ),
            Self::VerificationFailed => write!(f, "Verification failed"),
        }
    }
}

/// A reencrypted fragment of a [`Capsule`] created by a proxy.
#[derive(Clone, Debug, PartialEq)]
pub struct CapsuleFrag {
    pub(crate) index: u32,
    pub(crate) point_c1: CurvePoint,
    pub(crate) point_c2: CurvePoint,
    pub(crate) proof: CapsuleFragProof,
}

impl RepresentableAsArray for CapsuleFrag {
    type Size = op!(U4 + PointSize + PointSize + CapsuleFragProofSize);
}

impl SerializableToArray for CapsuleFrag {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.index
            .to_array()
            .concat(self.point_c1.to_array())
            .concat(self.point_c2.to_array())
            .concat(self.proof.to_array())
    }
}

impl DeserializableFromArray for CapsuleFrag {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        let (index, rest) = u32::take(*arr)?;
        let (point_c1, rest) = CurvePoint::take(rest)?;
        let (point_c2, rest) = CurvePoint::take(rest)?;
        let proof = CapsuleFragProof::take_last(rest)?;
        Ok(Self {
            index,
            point_c1,
            point_c2,
            proof,
        })
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl Serialize for CapsuleFrag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_serialize(self, serializer, Representation::Base64)
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl<'de> Deserialize<'de> for CapsuleFrag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_deserialize(deserializer, Representation::Base64)
    }
}

impl HasTypeName for CapsuleFrag {
    fn type_name() -> &'static str {
        "CapsuleFrag"
    }
}

impl fmt::Display for CapsuleFrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public::<Self>(self, f)
    }
}

impl CapsuleFrag {
    pub(crate) fn reencrypt(
        rng: &mut (impl CryptoRng + RngCore),
        capsule: &Capsule,
        kfrag: &KeyFrag,
        reader_pk: &PublicKey,
    ) -> Self {
        // compute (C1, C2)
        let g = CurvePoint::generator();
        let cap_d = &capsule.point_e * &kfrag.key;
        let t = SecretBox::new(NonZeroCurveScalar::random(rng));
        let point_c1 = &g * t.as_secret();
        let pk = reader_pk.to_point();
        let pk_t = &pk * t.as_secret();
        let point_c2 = &cap_d + &pk_t;

        // create zkp proof to show (C1, C2) are formed correctly
        let rho1 = SecretBox::new(NonZeroCurveScalar::random(rng));
        let rho2 = SecretBox::new(NonZeroCurveScalar::random(rng));
        let cap_r1 = &g * rho1.as_secret();
        let cap_r2 = &(&capsule.point_e * rho2.as_secret()) + &(&pk * rho1.as_secret());
        let cap_r3 = &g * rho2.as_secret();
        let points = &[
            &g,
            &pk,
            &kfrag.point_u,
            &capsule.point_e,
            &point_c1,
            &point_c2,
            &cap_r1,
            &cap_r2,
            &cap_r3,
        ];
        let c = hash_to_cfrag_verification(points);
        let z1 = &(t.as_secret() * &c) + rho1.as_secret();
        let z2 = &(&kfrag.key * &c) + rho2.as_secret();
        let proof = CapsuleFragProof {
            c: c.into(),
            z1,
            z2,
        };

        Self {
            index: kfrag.index,
            point_c1,
            point_c2,
            proof,
        }
    }

    /// Verifies the integrity of the capsule fragment, given the original capsule,
    /// the encrypting party's key, the decrypting party's key, and the signing key.
    #[allow(clippy::many_single_char_names)]
    pub fn verify(
        self,
        capsule: &Capsule,
        encrypted_kfrag: &EncryptedKeyFrag,
        reader_pk: &PublicKey,
    ) -> Result<VerifiedCapsuleFrag, (CapsuleFragVerificationError, Self)> {
        if self.index != encrypted_kfrag.index {
            return Err((
                CapsuleFragVerificationError::IndexMismatch(self.index, encrypted_kfrag.index),
                self,
            ));
        }

        let g = CurvePoint::generator();
        let pk = reader_pk.to_point();
        let cap_r1 = &(&g * &self.proof.z1) - &(&self.point_c1 * &self.proof.c);
        let cap_r2 = &(&(&capsule.point_e * &self.proof.z2) + &(&pk * &self.proof.z1))
            - &(&self.point_c2 * &self.proof.c);
        let cap_r3 = &(&g * &self.proof.z2) - &(&encrypted_kfrag.point_u * &self.proof.c);
        let points = &[
            &g,
            &pk,
            &encrypted_kfrag.point_u,
            &capsule.point_e,
            &self.point_c1,
            &self.point_c2,
            &cap_r1,
            &cap_r2,
            &cap_r3,
        ];
        let c = hash_to_cfrag_verification(points);

        if self.proof.c != c.into() {
            return Err((CapsuleFragVerificationError::VerificationFailed, self));
        }

        Ok(VerifiedCapsuleFrag { cfrag: self })
    }

    /// Explicitly skips verification.
    /// Useful in cases when the verifying keys are impossible to obtain independently.
    ///
    /// **Warning:** make sure you considered the implications of not enforcing verification.
    pub fn skip_verification(self) -> VerifiedCapsuleFrag {
        VerifiedCapsuleFrag { cfrag: self }
    }
}

/// Verified capsule fragment, good for dencryption.
/// Can be serialized, but cannot be deserialized directly.
/// It can only be obtained from [`CapsuleFrag::verify`] or [`CapsuleFrag::skip_verification`].
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "bindings-wasm", derive(Serialize, Deserialize))]
pub struct VerifiedCapsuleFrag {
    pub(crate) cfrag: CapsuleFrag,
}

impl RepresentableAsArray for VerifiedCapsuleFrag {
    type Size = <CapsuleFrag as RepresentableAsArray>::Size;
}

impl SerializableToArray for VerifiedCapsuleFrag {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.cfrag.to_array()
    }
}

impl HasTypeName for VerifiedCapsuleFrag {
    fn type_name() -> &'static str {
        "VerifiedCapsuleFrag"
    }
}

impl fmt::Display for VerifiedCapsuleFrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public::<Self>(self, f)
    }
}

impl VerifiedCapsuleFrag {
    /// Restores a verified capsule frag directly from serialized bytes,
    /// skipping [`CapsuleFrag::verify`] call.
    ///
    /// Intended for internal storage;
    /// make sure that the bytes come from a trusted source.
    pub fn from_verified_bytes(data: impl AsRef<[u8]>) -> Result<Self, DeserializationError> {
        CapsuleFrag::from_bytes(data).map(|cfrag| Self { cfrag })
    }

    /// Clears the verification status from the capsule frag.
    /// Useful for the cases where it needs to be put in the protocol structure
    /// containing [`CapsuleFrag`] types (since those are the ones
    /// that can be serialized/deserialized freely).
    pub fn unverify(self) -> CapsuleFrag {
        self.cfrag
    }
}

#[cfg(test)]
mod tests {

    use alloc::vec::Vec;

    use super::{CapsuleFrag, VerifiedCapsuleFrag};

    use crate::{
        delegate, encrypt, reencrypt, Capsule, Delegation, DeserializableFromArray, PublicKey,
        SecretKey, SerializableToArray,
    };

    #[cfg(feature = "serde-support")]
    use crate::serde::tests::{check_deserialization, check_serialization};

    #[cfg(feature = "serde-support")]
    use crate::serde::Representation;

    fn prepare_cfrags() -> (
        PublicKey,
        PublicKey,
        Capsule,
        Delegation,
        Vec<VerifiedCapsuleFrag>,
    ) {
        let delegator_sk = SecretKey::random();
        let delegator_pk = delegator_sk.public_key();

        let reader_sk = SecretKey::random();
        let reader_pk = reader_sk.public_key();

        let plaintext = b"peace at dawn";
        let (capsule, _ciphertext) = encrypt(&delegator_pk, plaintext).unwrap();

        let proxy_sks: Vec<_> = (0..3).map(|_| SecretKey::random()).collect();
        let proxy_pks: Vec<_> = proxy_sks.iter().map(|sk| sk.public_key()).collect();
        let proxy_pks_ref: Vec<_> = proxy_pks.iter().map(|pk| pk).collect();

        let delegation = delegate(&delegator_sk, 2, 3, &proxy_pks_ref).unwrap();
        delegation.verify_public().unwrap();

        let vkfrags: Vec<_> = delegation
            .encrypted_kfrags
            .iter()
            .zip(proxy_sks.iter())
            .map(|(ekfrag, proxy_sk)| ekfrag.decrypt(proxy_sk).unwrap().verify().unwrap())
            .collect();

        let cfrags: Vec<_> = vkfrags
            .iter()
            .map(|v| reencrypt(&reader_pk, &capsule, v.clone()))
            .collect();

        let verified_cfrags: Vec<_> = cfrags
            .iter()
            .cloned()
            .zip(delegation.encrypted_kfrags.iter())
            .map(|(cf, ekf)| cf.verify(&capsule, ekf, &reader_pk).unwrap())
            .collect();

        (
            delegator_pk,
            reader_pk,
            capsule,
            delegation,
            verified_cfrags,
        )
    }

    #[test]
    fn test_verify() {
        let (_delegator_pk, reader_pk, capsule, delegation, verified_cfrags) = prepare_cfrags();

        for (vcf, ekf) in verified_cfrags
            .iter()
            .zip(delegation.encrypted_kfrags.iter())
        {
            let cfrag_array = vcf.to_array();
            let cfrag_back = CapsuleFrag::from_array(&cfrag_array).unwrap();

            assert_eq!(cfrag_back.to_array(), cfrag_array);

            let verified_cfrag_back = cfrag_back.verify(&capsule, ekf, &reader_pk).unwrap();

            assert_eq!(verified_cfrag_back, *vcf);
        }
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn test_serde_serialization() {
        let (_delegator_pk, _reader_pk, _capsule, _delegation, verified_cfrags) = prepare_cfrags();

        let vcfrag = verified_cfrags[0].clone();
        let cfrag = CapsuleFrag::from_array(&vcfrag.to_array()).unwrap();

        check_serialization(&cfrag, Representation::Base64);
        check_deserialization(&cfrag);
    }
}
