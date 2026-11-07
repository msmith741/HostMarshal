//! JSON Schema for versioned declarative resources, generated from typed Rust.
//! Editors may use this; semantic authorization validation remains in CompiledConfig.
use anyhow::Result;
use schemars;

/// Generate a Draft 2020-12 JSON Schema for HostMarshal v1alpha1 resources.
pub fn resource_schema_json() -> Result<String> {
    let schema = schemars::schema_for!(crate::declarative::Resource);
    Ok(serde_json::to_string_pretty(&schema)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn export_schema_is_machine_readable_and_covers_resource_types() {
        let schema: Value = serde_json::from_str(&resource_schema_json().unwrap()).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        let rendered = serde_json::to_string(&schema).unwrap();
        for name in ["Host", "Capability", "Grant", "apiVersion"] {
            assert!(rendered.contains(name), "schema is missing {name}");
        }
    }
}
