#![no_main]
use hostmarshal::declarative::{CompiledConfig, parse_manifests};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The trusted manifest loader bounds total per-file bytes to 128 KiB.
    if data.len() > 128 * 1024 {
        return;
    }
    if let Ok(content) = std::str::from_utf8(data) {
        if let Ok(resources) = parse_manifests(content) {
            let _ = CompiledConfig::compile(resources);
        }
    }
});
