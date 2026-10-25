#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kem1536_fuzz::api_sequence(data));
