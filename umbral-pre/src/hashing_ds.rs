//! This module contains hashing sequences with included domain separation tags
//! shared between different parts of the code.

use crate::curve::{CurvePoint, NonZeroCurveScalar};
use crate::hashing::ScalarDigest;

pub(crate) fn hash_capsule_points(
    g: &CurvePoint,
    cap_e: &CurvePoint,
    cap_r: &CurvePoint,
) -> NonZeroCurveScalar {
    ScalarDigest::new_with_dst(b"CAPSULE_POINTS")
        .chain_point(g)
        .chain_point(cap_e)
        .chain_point(cap_r)
        .finalize()
}

pub(crate) fn hash_points_to_key(points: &[&CurvePoint]) -> NonZeroCurveScalar {
    ScalarDigest::new_with_dst(b"HASH_POINTS_TO_CREAT_DEM_KEY")
        .chain_points(points)
        .finalize()
}

pub(crate) fn hash_to_cfrag_verification(points: &[&CurvePoint]) -> NonZeroCurveScalar {
    ScalarDigest::new_with_dst(b"CFRAG_VERIFICATION")
        .chain_points(points)
        .finalize()
}
