//! Deterministic, bounded parser mutation smoke test (FR-015).
//! Not a substitute for coverage-guided libFuzzer, which lives under fuzz/.
use hostmarshal::declarative::{CompiledConfig, parse_manifests};

fn next(seed: &mut u64) -> usize {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed as usize
}

#[test]
fn mutated_valid_yaml_never_panics() {
    let seeds = [
        include_bytes!("../config/v1alpha1/host.yaml").as_slice(),
        include_bytes!("../config/v1alpha1/capability.yaml").as_slice(),
        include_bytes!("../config/v1alpha1/grant.yaml").as_slice(),
    ];
    let mut state = 0x5230_5751_A83E_C019u64;
    for i in 0..1800 {
        let mut bytes = seeds[i % seeds.len()].to_vec();
        let edits = 1 + (next(&mut state) % 12);
        for _ in 0..edits {
            let index = next(&mut state) % (bytes.len() + 1);
            match next(&mut state) % 4 {
                0 if !bytes.is_empty() && index < bytes.len() => {
                    bytes[index] = next(&mut state) as u8;
                }
                1 if bytes.len() < 8192 => {
                    bytes.insert(index, next(&mut state) as u8);
                }
                2 if !bytes.is_empty() && index < bytes.len() => {
                    bytes.remove(index);
                }
                _ => {
                    bytes.truncate(index);
                }
            }
        }
        if let Ok(text) = std::str::from_utf8(&bytes)
            && let Ok(resources) = parse_manifests(text)
        {
            let _ = CompiledConfig::compile(resources);
        }
    }
}
