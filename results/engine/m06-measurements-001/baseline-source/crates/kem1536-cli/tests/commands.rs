use std::process::Command;

#[test]
fn profile_output_is_machine_readable() {
    let output = Command::new(env!("CARGO_BIN_EXE_kem1536"))
        .arg("profile")
        .output()
        .unwrap();
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["coefficient_count"], 1536);
    assert_eq!(document["sizes_bytes"]["ciphertext_bytes"], 2272);
    assert_eq!(document["cryptographic_validation"], "pending");
}

#[test]
fn unavailable_crypto_commands_fail_instead_of_simulating_success() {
    let output = Command::new(env!("CARGO_BIN_EXE_kem1536"))
        .arg("keygen")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn development_profile_and_status_are_explicit() {
    for command in ["dev-profile", "status"] {
        let output = Command::new(env!("CARGO_BIN_EXE_kem1536"))
            .arg(command)
            .output()
            .unwrap();
        assert!(output.status.success());
        let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if command == "dev-profile" {
            assert_eq!(doc["profile"], "KEM1536-DEV-Q7681-R1");
            assert_eq!(doc["ciphertext_bytes"], 2656);
        } else {
            assert_eq!(doc["profile_id"], "KEM1536-DEV-Q7681-R1");
            assert_eq!(doc["decaps_implemented"], true);
            assert_eq!(doc["j2_closed"], false);
        }
    }
}

#[test]
fn invalid_stress_counts_fail_without_output() {
    for value in ["0", "100001", "-1", "bad"] {
        let output = Command::new(env!("CARGO_BIN_EXE_kem1536"))
            .args(["dev-stress", value])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[cfg(not(feature = "research-vectors"))]
#[test]
fn deterministic_vectors_are_absent_from_default_application() {
    let output = Command::new(env!("CARGO_BIN_EXE_kem1536"))
        .arg("dev-vectors")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
