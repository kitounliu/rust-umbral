use alloc::vec::Vec;
use core::fmt;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use typenum::op;

#[cfg(feature = "serde-support")]
use crate::serde::{serde_deserialize, serde_serialize, Representation};

use crate::capsule_frag::CapsuleFrag;
use crate::curve::{CurvePoint, CurveScalar, NonZeroCurveScalar};
use crate::hashing_ds::{hash_capsule_points, hash_points_to_key};
use crate::keys::{PublicKey, SecretKey};

use crate::secret_box::SecretBox;
use crate::traits::{
    fmt_public, ConstructionError, DeserializableFromArray, HasTypeName, RepresentableAsArray,
    SerializableToArray,
};

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Errors that can happen when opening a `Capsule` using reencrypted `CapsuleFrag` objects.
#[derive(Debug, PartialEq)]
pub enum OpenReencryptedError {
    /// An empty capsule fragment list is given.
    NoCapsuleFrags,
    /// Some of the given capsule fragments are repeated.
    RepeatingCapsuleFrags,
}

impl fmt::Display for OpenReencryptedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCapsuleFrags => write!(f, "Empty CapsuleFrag sequence"),
            Self::RepeatingCapsuleFrags => write!(f, "Some of the CapsuleFrags are repeated"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CapsuleProof {
    pub(crate) c: CurveScalar,
    pub(crate) z: CurveScalar,
}

impl RepresentableAsArray for CapsuleProof {
    type Size = op!(ScalarSize + ScalarSize);
}

impl SerializableToArray for CapsuleProof {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.c.to_array().concat(self.z.to_array())
    }
}

impl DeserializableFromArray for CapsuleProof {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        let (c, rest) = CurveScalar::take(*arr)?;
        let z = CurveScalar::take_last(rest)?;

        Ok(CapsuleProof { c, z })
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl Serialize for CapsuleProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_serialize(self, serializer, Representation::Base64)
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl<'de> Deserialize<'de> for CapsuleProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_deserialize(deserializer, Representation::Base64)
    }
}

impl HasTypeName for CapsuleProof {
    fn type_name() -> &'static str {
        "CapsuleProof"
    }
}

impl fmt::Display for CapsuleProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public::<Self>(self, f)
    }
}

/// Encapsulated symmetric key used to encrypt the plaintext.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Capsule {
    pub(crate) point_e: CurvePoint,
    pub(crate) proof: CapsuleProof,
}

type PointSize = <CurvePoint as RepresentableAsArray>::Size;
type ScalarSize = <CurveScalar as RepresentableAsArray>::Size;
type CapsuleProofSize = <CapsuleProof as RepresentableAsArray>::Size;

impl RepresentableAsArray for Capsule {
    type Size = op!(PointSize + CapsuleProofSize);
}

impl SerializableToArray for Capsule {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.point_e.to_array().concat(self.proof.to_array())
    }
}

impl DeserializableFromArray for Capsule {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        let (point_e, rest) = CurvePoint::take(*arr)?;
        let proof = CapsuleProof::take_last(rest)?;

        Ok(Capsule { point_e, proof })
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl Serialize for Capsule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_serialize(self, serializer, Representation::Base64)
    }
}

#[cfg(feature = "serde-support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde-support")))]
impl<'de> Deserialize<'de> for Capsule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_deserialize(deserializer, Representation::Base64)
    }
}

impl HasTypeName for Capsule {
    fn type_name() -> &'static str {
        "Capsule"
    }
}

impl fmt::Display for Capsule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_public::<Self>(self, f)
    }
}

pub(crate) type KeySeed = GenericArray<u8, <CurveScalar as RepresentableAsArray>::Size>;

impl Capsule {
    fn new(point_e: CurvePoint, proof: CapsuleProof) -> Self {
        Self { point_e, proof }
    }

    /// Verifies the proof of the capsule.
    pub fn verify(&self) -> bool {
        let g = CurvePoint::generator();
        let cap_r = &(&g * &self.proof.z) - &(&self.point_e * &self.proof.c);
        let h = hash_capsule_points(&g, &self.point_e, &cap_r);
        //let tilde_c = CurveScalar::from(&h);
        self.proof.c == h.into()
    }

    /// Generates a symmetric key and its associated KEM ciphertext, using the given RNG.
    pub(crate) fn from_public_key(
        rng: &mut (impl CryptoRng + RngCore),
        delegator_pk: &PublicKey,
    ) -> (Capsule, SecretBox<KeySeed>) {
        let g = CurvePoint::generator();
        let pk = delegator_pk.to_point();
        let r = SecretBox::new(NonZeroCurveScalar::random(rng));
        let point_e = &g * r.as_secret();
        let pk_r = &pk * r.as_secret();

        // compute key seed for KDF function
        let points = &[&g, &pk, &point_e, &pk_r];
        let key_seed = CurveScalar::from(hash_points_to_key(points));

        // create proof
        let tau = SecretBox::new(NonZeroCurveScalar::random(rng));
        let cap_r = &g * tau.as_secret();
        let c = hash_capsule_points(&g, &point_e, &cap_r);
        let z = &(r.as_secret() * &c) + tau.as_secret();
        let proof = CapsuleProof { c: c.into(), z };

        let capsule = Self::new(point_e, proof);

        (capsule, SecretBox::new(key_seed.to_array()))
    }

    /// Derive the same symmetric key
    pub(crate) fn derive_key(&self, delegating_sk: &SecretKey) -> SecretBox<KeySeed> {
        let g = CurvePoint::generator();
        let pk = delegating_sk.public_key().to_point();
        let pk_r = &self.point_e * delegating_sk.to_secret_scalar().as_secret();
        let points = &[&g, &pk, &self.point_e, &pk_r];
        let key_seed = CurveScalar::from(hash_points_to_key(points)).to_array();

        SecretBox::new(key_seed)
    }

    #[allow(clippy::many_single_char_names)]
    pub(crate) fn derive_key_reencrypted(
        &self,
        reader_sk: &SecretKey,
        delegator_pk: &PublicKey,
        cfrags: &[&CapsuleFrag],
    ) -> Result<SecretBox<KeySeed>, OpenReencryptedError> {
        if cfrags.is_empty() {
            return Err(OpenReencryptedError::NoCapsuleFrags);
        }

        let sk = reader_sk.to_secret_scalar();
        let dec: Vec<_> = cfrags
            .iter()
            .map(|&c| &c.point_c2 - &(&c.point_c1 * sk.as_secret()))
            .collect();
        let delta: Vec<_> = cfrags
            .iter()
            .map(|&c| NonZeroCurveScalar::from_u32(c.index))
            .collect();

        let mut t = CurvePoint::identity();
        for (i, d) in dec.iter().enumerate() {
            let lambda =
                lambda_coeff(&delta, i).ok_or(OpenReencryptedError::RepeatingCapsuleFrags)?;
            t = &t + &(d * &lambda)
        }

        let g = CurvePoint::generator();
        let pk = delegator_pk.to_point();
        let points = &[&g, &pk, &self.point_e, &t];
        let key_seed = CurveScalar::from(hash_points_to_key(points)).to_array();

        Ok(SecretBox::new(key_seed))
    }
}

fn lambda_coeff(xs: &[NonZeroCurveScalar], i: usize) -> Option<CurveScalar> {
    let mut res = CurveScalar::one();
    for j in 0..xs.len() {
        if j != i {
            let inv_diff_opt: Option<CurveScalar> = (&xs[j] - &xs[i]).invert().into();
            let inv_diff = inv_diff_opt?;
            res = &(&res * &xs[j]) * &inv_diff;
        }
    }
    Some(res)
}

#[cfg(test)]
mod tests {

    use alloc::vec::Vec;

    use rand_core::OsRng;

    use super::{Capsule, OpenReencryptedError};

    use crate::{encrypt, reencrypt, DeserializableFromArray, SecretKey, SerializableToArray};

    #[cfg(feature = "serde-support")]
    use crate::serde::tests::{check_deserialization, check_serialization};

    use crate::pre::delegate;
    #[cfg(feature = "serde-support")]
    use crate::serde::Representation;

    #[test]
    fn test_capsule_serialize() {
        let delegator_sk = SecretKey::random();
        let delegator_pk = delegator_sk.public_key();

        let plaintext = b"peace at dawn";
        let (capsule, _ciphertext) = encrypt(&delegator_pk, plaintext).unwrap();

        let capsule_arr = capsule.to_array();
        let capsule_back = Capsule::from_array(&capsule_arr).unwrap();
        assert_eq!(capsule, capsule_back);
    }

    #[test]
    fn test_capsule_derive_key_reencrypted() {
        let delegator_sk = SecretKey::random();
        let delegator_pk = delegator_sk.public_key();

        let reader_sk = SecretKey::random();
        let reader_pk = reader_sk.public_key();

        let proxy_sks: Vec<_> = (0..3).map(|_| SecretKey::random()).collect();
        let proxy_pks: Vec<_> = proxy_sks.iter().map(|sk| sk.public_key()).collect();
        let proxy_pks_ref: Vec<_> = proxy_pks.iter().map(|pk| pk).collect();

        let (capsule, key_seed) = Capsule::from_public_key(&mut OsRng, &delegator_pk);

        let delegation = delegate(&delegator_sk, 2, 3, &proxy_pks_ref).unwrap();

        let vkfrags: Vec<_> = delegation
            .encrypted_kfrags
            .iter()
            .zip(proxy_sks.iter())
            .map(|(ekfrag, proxy_sk)| ekfrag.decrypt(proxy_sk).unwrap().skip_verification())
            .collect();

        let cfrags: Vec<_> = vkfrags
            .iter()
            .map(|v| reencrypt(&reader_pk, &capsule, v.clone()))
            .collect();

        // use all the cfrags
        let cfrags_ref: Vec<_> = cfrags.iter().map(|c| c).collect();
        let key_seed_reenc = capsule
            .derive_key_reencrypted(&reader_sk, &delegator_pk, &cfrags_ref)
            .unwrap();
        assert_eq!(key_seed.as_secret(), key_seed_reenc.as_secret());

        // use 2 cfrags
        let cfrags2_ref = [&cfrags[0], &cfrags[1]];
        let key_seed_reenc2 = capsule
            .derive_key_reencrypted(&reader_sk, &delegator_pk, &cfrags2_ref)
            .unwrap();
        assert_eq!(key_seed.as_secret(), key_seed_reenc2.as_secret());

        // Empty cfrag vector
        let result = capsule.derive_key_reencrypted(&reader_sk, &delegator_pk, &[]);
        assert_eq!(
            result.map(|x| *x.as_secret()),
            Err(OpenReencryptedError::NoCapsuleFrags)
        );

        // repeated cfrag
        let repeated_cfrags_ref = [&cfrags[0], &cfrags[0]];
        let result =
            capsule.derive_key_reencrypted(&reader_sk, &delegator_pk, &repeated_cfrags_ref);
        assert_eq!(
            result.map(|x| *x.as_secret()),
            Err(OpenReencryptedError::RepeatingCapsuleFrags)
        );
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn test_capsule_serde_serialization() {
        let delegator_sk = SecretKey::random();
        let delegator_pk = delegator_sk.public_key();
        let (capsule, _key_seed) = Capsule::from_public_key(&mut OsRng, &delegator_pk);

        check_serialization(&capsule, Representation::Base64);
        check_deserialization(&capsule);
    }
}
