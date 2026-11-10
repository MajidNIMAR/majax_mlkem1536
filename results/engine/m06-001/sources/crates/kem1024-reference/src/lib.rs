//! A verification harness for the standard rank-four ML-KEM-1024 baseline.
//!
//! All deterministic keys come from public NIST test data. No candidate rank-six
//! algorithm is implemented here, and no private key is exposed by this API.

use ml_kem::{
    ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey},
    Decapsulate, Encapsulate, Kem, Key, KeyExport, MlKem1024, Seed, B32,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

// The deprecated expanded-key format is required to compare FIPS 203 / ACVP
// outputs. It is confined to this harness, not exposed as an application API.
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;

const MANIFEST: &str = include_str!("../../../references/manifest.json");
const KEYGEN_PROMPT: &[u8] =
    include_bytes!("../../../vectors/nist-acvp/ML-KEM-keyGen-FIPS203/prompt.json");
const KEYGEN_EXPECTED: &[u8] =
    include_bytes!("../../../vectors/nist-acvp/ML-KEM-keyGen-FIPS203/expectedResults.json");
const ENCAP_PROMPT: &[u8] =
    include_bytes!("../../../vectors/nist-acvp/ML-KEM-encapDecap-FIPS203/prompt.json");
const ENCAP_EXPECTED: &[u8] =
    include_bytes!("../../../vectors/nist-acvp/ML-KEM-encapDecap-FIPS203/expectedResults.json");
const TR1_PROMPT: &[u8] =
    include_bytes!("../../../vectors/nist-acvp/ML-KEM-encapDecap-FIPS203-tr1/prompt.json");
const TR1_EXPECTED: &[u8] =
    include_bytes!("../../../vectors/nist-acvp/ML-KEM-encapDecap-FIPS203-tr1/expectedResults.json");

struct Dataset {
    name: &'static str,
    prompt: &'static [u8],
    expected: &'static [u8],
}

const DATASETS: [Dataset; 3] = [
    Dataset {
        name: "ML-KEM-keyGen-FIPS203",
        prompt: KEYGEN_PROMPT,
        expected: KEYGEN_EXPECTED,
    },
    Dataset {
        name: "ML-KEM-encapDecap-FIPS203",
        prompt: ENCAP_PROMPT,
        expected: ENCAP_EXPECTED,
    },
    Dataset {
        name: "ML-KEM-encapDecap-FIPS203-tr1",
        prompt: TR1_PROMPT,
        expected: TR1_EXPECTED,
    },
];

#[derive(Debug, Serialize)]
pub struct GroupReport {
    pub dataset: &'static str,
    pub revision: String,
    pub group_id: u64,
    pub function: String,
    pub key_format: String,
    pub cases_passed: usize,
}

#[derive(Debug, Serialize)]
pub struct ReferenceReport {
    pub algorithm: &'static str,
    pub implementation: &'static str,
    pub acvp_source_commit: String,
    pub fixture_integrity: &'static str,
    pub keygen_cases: usize,
    pub encapsulation_cases: usize,
    pub decapsulation_cases: usize,
    pub key_validation_cases: usize,
    pub implicit_rejection_cases: usize,
    pub total_official_cases_passed: usize,
    pub fresh_round_trips: usize,
    pub groups: Vec<GroupReport>,
    pub scope: &'static str,
}

fn array(value: &Value) -> Result<&Vec<Value>, String> {
    value
        .as_array()
        .ok_or_else(|| "invalid vector array".into())
}

fn number(value: &Value) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or_else(|| "missing vector identifier".into())
}

fn text(value: &Value) -> Result<&str, String> {
    value.as_str().ok_or_else(|| "invalid vector string".into())
}

fn bytes(value: &Value) -> Result<Vec<u8>, String> {
    hex::decode(text(value)?).map_err(|_| "invalid hex in test data".into())
}

fn seed_from_test(test: &Value) -> Result<Seed, String> {
    let d = bytes(&test["d"])?;
    let z = bytes(&test["z"])?;
    if d.len() != 32 || z.len() != 32 {
        return Err("invalid seed length in test data".into());
    }
    Seed::try_from([d, z].concat().as_slice()).map_err(|_| "invalid seed encoding".into())
}

fn import_ek(input: &[u8]) -> Result<EncapsulationKey, String> {
    let encoded = Key::<EncapsulationKey>::try_from(input)
        .map_err(|_| "invalid encapsulation key length".to_string())?;
    EncapsulationKey::new(&encoded).map_err(|_| "noncanonical encapsulation key".into())
}

#[allow(deprecated)]
fn import_expanded_dk(input: &[u8]) -> Result<DecapsulationKey, String> {
    let encoded = ml_kem::ExpandedDecapsulationKey::<MlKem1024>::try_from(input)
        .map_err(|_| "invalid expanded decapsulation key length".to_string())?;
    DecapsulationKey::from_expanded_bytes(&encoded)
        .map_err(|_| "inconsistent expanded decapsulation key".into())
}

fn fallback_secret(z: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut hash = Shake256::default();
    hash.update(z);
    hash.update(ciphertext);
    let mut result = [0; 32];
    hash.finalize_xof().read(&mut result);
    result
}

fn equal(actual: &[u8], expected: &[u8], field: &str) -> Result<(), String> {
    // Public offline vectors only. This is not a secret-comparison application API.
    if actual != expected {
        return Err(format!("{field} differs from the official expected result"));
    }
    Ok(())
}

#[allow(deprecated)]
fn check_case(
    test: &Value,
    answer: &Value,
    function: &str,
    key_format: &str,
) -> Result<bool, String> {
    match function {
        "keyGen" => {
            let dk = DecapsulationKey::from_seed(seed_from_test(test)?);
            equal(
                dk.encapsulation_key().to_bytes().as_slice(),
                &bytes(&answer["ek"])?,
                "ek",
            )?;
            equal(
                dk.to_expanded_bytes().as_slice(),
                &bytes(&answer["dk"])?,
                "dk",
            )?;
        }
        "encapsulation" => {
            let ek = import_ek(&bytes(&test["ek"])?)?;
            let m = B32::try_from(bytes(&test["m"])?.as_slice())
                .map_err(|_| "invalid encapsulation randomness length".to_string())?;
            let (c, k) = ek.encapsulate_deterministic(&m);
            equal(c.as_slice(), &bytes(&answer["c"])?, "c")?;
            equal(k.as_slice(), &bytes(&answer["k"])?, "k")?;
        }
        "decapsulation" => {
            let (dk, z) = if key_format == "seed" {
                (
                    DecapsulationKey::from_seed(seed_from_test(test)?),
                    bytes(&test["z"])?,
                )
            } else if key_format == "expanded" {
                let raw = bytes(&test["dk"])?;
                let dk = import_expanded_dk(&raw)?;
                (dk, raw[raw.len() - 32..].to_vec())
            } else {
                return Err("unsupported decapsulation key format".into());
            };
            let raw_ciphertext = bytes(&test["c"])?;
            let c = Ciphertext::try_from(raw_ciphertext.as_slice())
                .map_err(|_| "invalid ciphertext length".to_string())?;
            let actual = dk.decapsulate(&c);
            let expected = bytes(&answer["k"])?;
            equal(actual.as_slice(), &expected, "k")?;
            return Ok(expected.as_slice() == fallback_secret(&z, &raw_ciphertext));
        }
        "encapsulationKeyCheck" | "decapsulationKeyCheck" => {
            let valid = if function == "encapsulationKeyCheck" {
                import_ek(&bytes(&test["ek"])?).is_ok()
            } else {
                import_expanded_dk(&bytes(&test["dk"])?).is_ok()
            };
            let expected = answer["testPassed"]
                .as_bool()
                .ok_or_else(|| "missing official key-validation result".to_string())?;
            if valid != expected {
                return Err("key validation differs from the official expected result".into());
            }
        }
        _ => return Err(format!("unsupported official test function: {function}")),
    }
    Ok(false)
}

fn verify_embedded_vectors() -> Result<Value, String> {
    let manifest: Value = serde_json::from_str(MANIFEST).map_err(|e| e.to_string())?;
    let entries = array(&manifest["files"])?;
    for dataset in &DATASETS {
        for (name, content) in [
            ("prompt.json", dataset.prompt),
            ("expectedResults.json", dataset.expected),
        ] {
            let path = format!("vectors/nist-acvp/{}/{name}", dataset.name);
            let record = entries
                .iter()
                .find(|entry| entry["path"] == path)
                .ok_or_else(|| format!("unregistered vector source: {path}"))?;
            let digest = hex::encode(Sha256::digest(content));
            if record["sha256"] != digest || record["bytes"] != content.len() {
                return Err(format!("vector integrity check failed: {path}"));
            }
        }
    }
    Ok(manifest)
}

/// Check every ML-KEM-1024 case in the three pinned official vector sets.
/// Runs offline, then tests 32 fresh round trips using operating-system entropy.
pub fn run_reference_checks() -> Result<ReferenceReport, String> {
    let manifest = verify_embedded_vectors()?;
    let mut report = ReferenceReport {
        algorithm: "ML-KEM-1024",
        implementation: "RustCrypto ml-kem 0.3.3",
        acvp_source_commit: text(&manifest["acvp_source_commit"])?.into(),
        fixture_integrity: "SHA-256 verified",
        keygen_cases: 0,
        encapsulation_cases: 0,
        decapsulation_cases: 0,
        key_validation_cases: 0,
        implicit_rejection_cases: 0,
        total_official_cases_passed: 0,
        fresh_round_trips: 0,
        groups: Vec::new(),
        scope: "offline standard ML-KEM-1024 baseline; rank-six candidate not implemented",
    };
    for dataset in &DATASETS {
        let prompt: Value = serde_json::from_slice(dataset.prompt).map_err(|e| e.to_string())?;
        let expected: Value =
            serde_json::from_slice(dataset.expected).map_err(|e| e.to_string())?;
        for field in ["vsId", "algorithm", "mode", "revision"] {
            if prompt[field] != expected[field] {
                return Err(format!(
                    "inconsistent vector metadata: {} / {field}",
                    dataset.name
                ));
            }
        }
        for group in array(&prompt["testGroups"])? {
            if group["parameterSet"] != "ML-KEM-1024" {
                continue;
            }
            let group_id = number(&group["tgId"])?;
            let answer_group = array(&expected["testGroups"])?
                .iter()
                .find(|candidate| candidate["tgId"] == group_id)
                .ok_or_else(|| "missing official answer group".to_string())?;
            let function = if prompt["mode"] == "keyGen" {
                "keyGen"
            } else {
                text(&group["function"])?
            };
            let key_format = group["keyFormat"].as_str().unwrap_or("expanded");
            let tests = array(&group["tests"])?;
            let answers = array(&answer_group["tests"])?;
            if tests.len() != answers.len() {
                return Err("incomplete official answer group".into());
            }
            let mut ids = std::collections::BTreeSet::new();
            for test in tests {
                let case_id = number(&test["tcId"])?;
                if !ids.insert(case_id) {
                    return Err("duplicate official case identifier".into());
                }
                let answer = answers
                    .iter()
                    .find(|candidate| candidate["tcId"] == case_id)
                    .ok_or_else(|| "missing official answer case".to_string())?;
                let rejected = check_case(test, answer, function, key_format).map_err(|error| {
                    format!(
                        "{} / group {group_id} / case {case_id}: {error}",
                        dataset.name
                    )
                })?;
                report.implicit_rejection_cases += usize::from(rejected);
                report.total_official_cases_passed += 1;
                match function {
                    "keyGen" => report.keygen_cases += 1,
                    "encapsulation" => report.encapsulation_cases += 1,
                    "decapsulation" => report.decapsulation_cases += 1,
                    _ => report.key_validation_cases += 1,
                }
            }
            report.groups.push(GroupReport {
                dataset: dataset.name,
                revision: text(&prompt["revision"])?.into(),
                group_id,
                function: function.into(),
                key_format: key_format.into(),
                cases_passed: tests.len(),
            });
        }
    }
    if (
        report.keygen_cases,
        report.encapsulation_cases,
        report.decapsulation_cases,
        report.key_validation_cases,
        report.implicit_rejection_cases,
    ) != (25, 50, 30, 40, 15)
    {
        return Err("unexpected coverage of the pinned ML-KEM-1024 vector sets".into());
    }
    for _ in 0..32 {
        let (dk, ek) = MlKem1024::generate_keypair();
        let (ciphertext, sent) = ek.encapsulate();
        let received = dk.decapsulate(&ciphertext);
        if sent != received {
            return Err("fresh ML-KEM-1024 round trip failed".into());
        }
        report.fresh_round_trips += 1;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_vectors_and_fresh_round_trips_pass() {
        let report = run_reference_checks().unwrap();
        assert_eq!(report.total_official_cases_passed, 145);
        assert_eq!(report.implicit_rejection_cases, 15);
        assert_eq!(report.fresh_round_trips, 32);
    }

    #[test]
    fn truncated_key_encodings_are_rejected() {
        assert!(import_ek(&[0; 1567]).is_err());
        assert!(import_expanded_dk(&[0; 3167]).is_err());
    }

    #[test]
    fn noncanonical_public_coefficients_are_rejected() {
        let dk = DecapsulationKey::from_seed(Seed::from([7; 64]));
        let mut raw = dk.encapsulation_key().to_bytes().to_vec();
        raw[0] = 1;
        raw[1] = (raw[1] & 0xf0) | 0x0d; // first coefficient = q = 3329
        assert!(import_ek(&raw).is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn a_corrupted_private_key_hash_is_rejected() {
        let dk = DecapsulationKey::from_seed(Seed::from([7; 64]));
        let mut raw = dk.to_expanded_bytes().to_vec();
        raw[3104] ^= 1;
        assert!(import_expanded_dk(&raw).is_err());
    }

    #[test]
    fn a_modified_expected_answer_is_detected() {
        let prompt: Value = serde_json::from_slice(KEYGEN_PROMPT).unwrap();
        let answers: Value = serde_json::from_slice(KEYGEN_EXPECTED).unwrap();
        let test = &prompt["testGroups"][2]["tests"][0];
        let mut answer = answers["testGroups"][2]["tests"][0].clone();
        let mut wrong = bytes(&answer["ek"]).unwrap();
        wrong[0] ^= 1;
        answer["ek"] = Value::String(hex::encode(wrong));
        assert!(check_case(test, &answer, "keyGen", "expanded").is_err());
    }
}
