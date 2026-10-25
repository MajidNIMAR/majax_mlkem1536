#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kem1536_fuzz::import_public(data));
