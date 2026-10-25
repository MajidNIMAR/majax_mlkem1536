//! Infrastructure for the KEM1536-EXP-P0 research project.
//!
//! Historical P0 metadata, reference ring arithmetic and the experimental R1 KEM.
//! The development engine has not passed security review or the J2/J3 gates.

use serde::{Deserialize, Serialize};

pub mod dev_kem;
mod engine_poly;
pub mod reference_ring;
mod secret_box;

pub const PROFILE_ID: &str = "KEM1536-EXP-P0";
pub const PROFILE_VERSION: &str = "0.1";
pub const IMPLEMENTATION_STATUS: &str = "experimental-r1-reference";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub profile: Identity,
    pub parameters: Parameters,
    pub expected_sizes: ObjectSizes,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Parameters {
    pub n: usize,
    pub k: usize,
    pub q: usize,
    pub eta1: usize,
    pub eta2: usize,
    pub du: usize,
    pub dv: usize,
    pub seed_bytes: usize,
    pub shared_secret_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectSizes {
    pub vector_bytes: usize,
    pub encapsulation_key_bytes: usize,
    pub decapsulation_key_bytes: usize,
    pub c1_bytes: usize,
    pub c2_bytes: usize,
    pub ciphertext_bytes: usize,
    pub shared_secret_bytes: usize,
}

impl Profile {
    /// Parse and validate the identity, dimensions, and encoded sizes of P0.
    /// This check makes no claim about cryptographic security or correctness.
    pub fn from_toml(input: &str) -> Result<Self, String> {
        let profile: Self = toml::from_str(input).map_err(|error| error.to_string())?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err("unsupported profile schema".into());
        }
        if self.profile.id != PROFILE_ID || self.profile.version != PROFILE_VERSION {
            return Err("unsupported profile identifier or version".into());
        }
        let p = &self.parameters;
        if p.n != 256 || p.k != 6 {
            return Err("this project requires n=256 and k=6".into());
        }
        if (
            p.q,
            p.eta1,
            p.eta2,
            p.du,
            p.dv,
            p.seed_bytes,
            p.shared_secret_bytes,
        ) != (3329, 2, 2, 11, 5, 32, 32)
        {
            return Err("P0 parameters changed: create and specify a new profile first".into());
        }
        if self.expected_sizes != self.derived_sizes() {
            return Err("declared object sizes disagree with the parameter-derived sizes".into());
        }
        Ok(())
    }

    /// Compute sizes only after validating the public parameters.
    pub fn checked_sizes(&self) -> Result<ObjectSizes, String> {
        self.validate()?;
        Ok(self.derived_sizes())
    }

    pub fn coefficient_count(&self) -> Result<usize, String> {
        self.validate()?;
        Ok(self.parameters.n * self.parameters.k)
    }

    fn derived_sizes(&self) -> ObjectSizes {
        let p = &self.parameters;
        let vector_bytes = p.n * 12 / 8 * p.k;
        let encapsulation_key_bytes = vector_bytes + p.seed_bytes;
        let decapsulation_key_bytes = vector_bytes + encapsulation_key_bytes + 32 + p.seed_bytes;
        let c1_bytes = p.n * p.du / 8 * p.k;
        let c2_bytes = p.n * p.dv / 8;
        ObjectSizes {
            vector_bytes,
            encapsulation_key_bytes,
            decapsulation_key_bytes,
            c1_bytes,
            c2_bytes,
            ciphertext_bytes: c1_bytes + c2_bytes,
            shared_secret_bytes: p.shared_secret_bytes,
        }
    }
}

pub fn embedded_profile() -> Result<Profile, String> {
    Profile::from_toml(include_str!("../../../profiles/kem1536-p0.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_profile_has_the_required_dimensions_and_sizes() {
        let profile = embedded_profile().unwrap();
        assert_eq!(profile.coefficient_count().unwrap(), 1536);
        let sizes = profile.checked_sizes().unwrap();
        assert_eq!(sizes.encapsulation_key_bytes, 2336);
        assert_eq!(sizes.decapsulation_key_bytes, 4704);
        assert_eq!(sizes.ciphertext_bytes, 2272);
        assert_eq!(sizes.c1_bytes + sizes.c2_bytes, sizes.ciphertext_bytes);
    }

    #[test]
    fn a_rank_four_profile_cannot_masquerade_as_p0() {
        let mut profile = embedded_profile().unwrap();
        profile.parameters.k = 4;
        assert!(profile.checked_sizes().is_err());
    }

    #[test]
    fn changed_noise_requires_a_new_profile() {
        let mut profile = embedded_profile().unwrap();
        profile.parameters.eta1 = 3;
        assert!(profile.validate().is_err());
    }

    #[test]
    fn inconsistent_declared_sizes_are_rejected() {
        let mut profile = embedded_profile().unwrap();
        profile.expected_sizes.ciphertext_bytes += 1;
        assert!(profile.validate().is_err());
    }

    #[test]
    fn a_profile_for_another_version_is_rejected() {
        let mut profile = embedded_profile().unwrap();
        profile.profile.version = "0.2".into();
        assert!(profile.validate().is_err());
    }

    #[test]
    fn unknown_configuration_fields_are_not_silently_ignored() {
        let input = include_str!("../../../profiles/kem1536-p0.toml").replace(
            "schema_version = 1",
            "schema_version = 1\nsecurity_bits = 1536",
        );
        assert!(Profile::from_toml(&input).is_err());
    }
}
