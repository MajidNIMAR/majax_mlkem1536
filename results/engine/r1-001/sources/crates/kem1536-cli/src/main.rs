use kem1536::{embedded_profile, IMPLEMENTATION_STATUS};
use serde_json::json;
use std::process::ExitCode;

fn dev_self_test() -> Result<serde_json::Value, String> {
    serde_json::to_value(
        kem1536::dev_kem::run_diagnostics(16).map_err(|e| format!("R1 diagnostic: {e:?}"))?,
    )
    .map_err(|e| e.to_string())
}

#[cfg(feature = "research-vectors")]
fn dev_vectors(arguments: &[String]) -> Result<(), String> {
    use std::io::Write;
    let count: u32 = arguments
        .get(1)
        .map(|s| s.parse())
        .transpose()
        .map_err(|_| "invalid count")?
        .unwrap_or(1000);
    if !(1..=1000).contains(&count) {
        return Err("research count must be 1..1000".into());
    }
    let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
    for i in 0..count {
        serde_json::to_writer(
            &mut stdout,
            &kem1536::dev_kem::research_vectors::generate(i),
        )
        .map_err(|e| e.to_string())?;
        writeln!(&mut stdout).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.first().is_some_and(|s| s == "dev-stress") && arguments.len() == 2 {
        let count: usize = arguments[1]
            .parse()
            .map_err(|_| "invalid diagnostic count")?;
        if !(1..=100000).contains(&count) {
            return Err("diagnostic count must be 1..100000".into());
        }
        let result = kem1536::dev_kem::run_diagnostics(count)
            .map_err(|e| format!("R1 diagnostic: {e:?}"))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    #[cfg(feature = "research-vectors")]
    if arguments.first().is_some_and(|s| s == "dev-vectors") && arguments.len() <= 2 {
        return dev_vectors(&arguments);
    }
    if arguments.len() != 1 {
        return Err(
            "usage: kem1536 <profile|status|self-check|reference-1024|dev-profile|dev-self-test>"
                .into(),
        );
    }
    let profile = embedded_profile()?;
    let output = match arguments[0].as_str() {
        "profile" => json!({
            "profile": profile.profile,
            "parameters": profile.parameters,
            "sizes_bytes": profile.checked_sizes()?,
            "coefficient_count": profile.coefficient_count()?,
            "cryptographic_validation": "pending"
        }),
        "status" => json!({
            "profile_id": kem1536::dev_kem::PROFILE,
            "implementation_status": IMPLEMENTATION_STATUS,
            "keygen_implemented": true,
            "encaps_implemented": true,
            "decaps_implemented": true,
            "reference_1024": "available via reference-1024",
            "cryptographic_validation": "pending",
            "historical_profile":profile.profile.id,
            "j2_closed":false
        }),
        "dev-profile"=>json!({"profile":kem1536::dev_kem::PROFILE,"n":256,"k":6,"q":7681,"eta":3,"u_encoding":"exact-13-bit-canonical", "dv":5,
            "public_key_bytes":2528,"expanded_private_key_bytes":5088,"ciphertext_bytes":2656,"shared_secret_bytes":32,"security_validation":"pending"}),
        "dev-self-test"=>dev_self_test()?,
        "self-check" => json!({
            "configuration_check": "passed",
            "scope": "public parameters and object sizes only",
            "implementation_status": IMPLEMENTATION_STATUS
        }),
        "reference-1024" => serde_json::to_value(kem1024_reference::run_reference_checks()?)
            .map_err(|e| e.to_string())?,
        _ => {
            return Err(
                "unknown command; available: profile, status, self-check, reference-1024, dev-profile, dev-self-test".into(),
            )
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
