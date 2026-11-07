//! JSON Schema for versioned declarative resources, generated from typed Rust.
//! Editors may use this; semantic authorization validation remains in CompiledConfig.
use anyhow::{Context, Result};
use schemars;
use serde_json::{Value, json};

/// Generate a Draft 2020-12 JSON Schema for HostMarshal v1alpha1 resources.
/// Resource apiVersion is constrained here in addition to the runtime compiler.
pub fn resource_schema_json() -> Result<String> {
    let schema = schemars::schema_for!(crate::declarative::Resource);
    let mut document = serde_json::to_value(schema)?;
    document["$id"] = json!("urn:hostmarshal:schemas:v1alpha1:resource");
    let variants = document
        .get_mut("oneOf")
        .and_then(Value::as_array_mut)
        .context("resource schema generator must produce oneOf variants")?;
    for variant in variants {
        let property = variant
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .and_then(|properties| properties.get_mut("apiVersion"))
            .context("resource variant is missing apiVersion property")?;
        property["const"] = json!("hostmarshal.io/v1alpha1");
    }
    Ok(serde_json::to_string_pretty(&document)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_schema_is_machine_readable_and_versioned() {
        let schema: Value = serde_json::from_str(&resource_schema_json().unwrap()).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["$id"], "urn:hostmarshal:schemas:v1alpha1:resource");
        let variants = schema["oneOf"].as_array().unwrap();
        assert_eq!(variants.len(), 3);
        for variant in variants {
            assert_eq!(
                variant["properties"]["apiVersion"]["const"],
                "hostmarshal.io/v1alpha1"
            );
        }
        let rendered = serde_json::to_string(&schema).unwrap();
        for name in ["Host", "Capability", "Grant", "apiVersion"] {
            assert!(rendered.contains(name), "schema is missing {name}");
        }
    }
}
