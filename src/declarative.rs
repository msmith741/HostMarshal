//! Versioned, strictly typed YAML manifest loader (FR-001, FR-003, FR-005).
//! Only trusted local launchers supply this directory. This is not an MCP upload API.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, ensure};
#[cfg(test)]
use anyhow::bail;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_FILE_BYTES: u64 = 128 * 1024;
const MAX_FILES: usize = 128;
const MAX_RESOURCES: usize = 256;
const API_VERSION: &str = "hostmarshal.io/v1alpha1";
const OPERATION: &str = "builtin.inventory.inspect/v1";
const MAX_DEPTH: usize = 32;
const MAX_NODES_PER_FILE: usize = 10_000;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostSpec {
    pub address: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Exposure {
    pub mcp: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Limits {
    pub timeout: String,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapabilitySpec {
    pub operation_ref: String,
    pub target_kind: String,
    pub exposure: Exposure,
    pub input_schema: Value,
    pub output_schema: Value,
    pub limits: Limits,
}

#[derive(
    Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub issuer: String,
    pub subject: String,
}

#[derive(
    Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    pub kind: String,
    pub names: Vec<String>,
}

#[derive(
    Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct GrantSpec {
    pub subjects: Vec<Subject>,
    pub capabilities: Vec<String>,
    pub targets: Targets,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Resource {
    Host {
        #[serde(rename = "apiVersion")]
        api_version: String,
        metadata: Metadata,
        spec: HostSpec,
    },
    Capability {
        #[serde(rename = "apiVersion")]
        api_version: String,
        metadata: Metadata,
        spec: CapabilitySpec,
    },
    Grant {
        #[serde(rename = "apiVersion")]
        api_version: String,
        metadata: Metadata,
        spec: GrantSpec,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct HostRecord {
    pub metadata: Metadata,
    pub spec: HostSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublishedCapability {
    pub name: String,
    pub operation_ref: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct CompiledConfig {
    pub hosts: BTreeMap<String, HostRecord>,
    pub capabilities: BTreeMap<String, PublishedCapability>,
    pub grants: Vec<GrantSpec>,
    /// SHA-256 of effective validated configuration; not an authentication signature.
    pub snapshot_digest: String,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
}

pub fn input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
        "additionalProperties": false
    })
}

pub fn output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "hostname": {"type": "string"}
        },
        "required": ["id", "hostname"],
        "additionalProperties": false
    })
}

/// Parse a resource-budgeted YAML stream without aliases, anchors or custom tags.
pub fn parse_manifests(content: &str) -> Result<Vec<Resource>> {
    ensure!(
        content.len() as u64 <= MAX_FILE_BYTES,
        "YAML input exceeds size limit"
    );
    let options = serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_documents: MAX_RESOURCES,
            max_depth: MAX_DEPTH,
            max_nodes: MAX_NODES_PER_FILE,
            max_events: 30_000,
            max_aliases: 0,
            max_anchors: 0,
            max_merge_keys: 0,
        },
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        strict_booleans: true,
        reject_unsupported_tags: true,
    };
    serde_saphyr::from_multiple_with_options(content, options)
        .context("YAML parser rejected manifest")
}

impl CompiledConfig {
    /// Build an immutable registry from a trusted, local manifest directory.
    pub fn load(directory: &Path) -> Result<Self> {
        ensure!(directory.is_dir(), "config directory does not exist");
        let mut files = Vec::new();
        for entry in fs::read_dir(directory).context("cannot enumerate config directory")? {
            let entry = entry.context("invalid config directory entry")?;
            let path = entry.path();
            // Never follow symlinks from the trusted configuration directory.
            ensure!(
                entry.file_type()?.is_file(),
                "config directory must contain regular files only"
            );
            ensure!(
                matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("yaml" | "yml")
                ),
                "config directory contains unsupported file extension"
            );
            ensure!(
                entry.metadata()?.len() <= MAX_FILE_BYTES,
                "manifest file exceeds size limit"
            );
            files.push(path);
            ensure!(files.len() <= MAX_FILES, "too many manifest files");
        }
        files.sort();
        ensure!(!files.is_empty(), "no YAML manifests found");
        let mut resources = Vec::new();
        for path in files {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            ensure!(
                content.len() as u64 <= MAX_FILE_BYTES,
                "manifest exceeds size limit"
            );
            let parsed = parse_manifests(&content)
                .with_context(|| format!("invalid YAML in {}", path.display()))?;
            resources.extend(parsed);
            ensure!(resources.len() <= MAX_RESOURCES, "too many YAML resources");
        }
        Self::compile(resources)
    }

    /// Compile already parsed resources (the same validation path used in tests).
    pub fn compile(resources: Vec<Resource>) -> Result<Self> {
        let mut hosts = BTreeMap::new();
        let mut capabilities = BTreeMap::new();
        let mut grants = Vec::new();
        let mut used_names = BTreeSet::new();
        for resource in resources {
            match resource {
                Resource::Host {
                    api_version,
                    metadata,
                    spec,
                } => {
                    ensure!(api_version == API_VERSION, "unsupported Host apiVersion");
                    ensure!(valid_name(&metadata.name), "invalid host name");
                    ensure!(
                        used_names.insert(("Host", metadata.name.clone())),
                        "duplicate Host"
                    );
                    ensure!(!spec.address.trim().is_empty(), "empty host address");
                    hosts.insert(metadata.name.clone(), HostRecord { metadata, spec });
                }
                Resource::Capability {
                    api_version,
                    metadata,
                    spec,
                } => {
                    ensure!(
                        api_version == API_VERSION,
                        "unsupported Capability apiVersion"
                    );
                    ensure!(valid_name(&metadata.name), "invalid capability name");
                    ensure!(
                        used_names.insert(("Capability", metadata.name.clone())),
                        "duplicate Capability"
                    );
                    // In the initial release, the schema MUST equal the trusted descriptor.
                    // Subtyping / arbitrary schema narrowing will require a separate review.
                    ensure!(
                        spec.operation_ref == OPERATION,
                        "unknown/unapproved operationRef"
                    );
                    ensure!(spec.target_kind == "Host", "unsupported target kind");
                    ensure!(
                        spec.input_schema == input_schema(),
                        "input schema cannot override trusted operation"
                    );
                    ensure!(
                        spec.output_schema == output_schema(),
                        "output schema cannot override trusted operation"
                    );
                    ensure!(spec.limits.timeout == "2s", "unsupported operation timeout");
                    ensure!(
                        spec.limits.max_output_bytes > 0 && spec.limits.max_output_bytes <= 4096,
                        "invalid output limit"
                    );
                    if spec.exposure.mcp {
                        capabilities.insert(
                            metadata.name.clone(),
                            PublishedCapability {
                                name: metadata.name,
                                operation_ref: spec.operation_ref,
                                input_schema: spec.input_schema,
                                output_schema: spec.output_schema,
                                max_output_bytes: spec.limits.max_output_bytes,
                            },
                        );
                    }
                }
                Resource::Grant {
                    api_version,
                    metadata,
                    spec,
                } => {
                    ensure!(api_version == API_VERSION, "unsupported Grant apiVersion");
                    ensure!(valid_name(&metadata.name), "invalid grant name");
                    ensure!(
                        used_names.insert(("Grant", metadata.name)),
                        "duplicate Grant"
                    );
                    ensure!(spec.targets.kind == "Host", "unsupported grant target kind");
                    ensure!(
                        !spec.subjects.is_empty()
                            && !spec.capabilities.is_empty()
                            && !spec.targets.names.is_empty(),
                        "grant must have subjects, capabilities and targets"
                    );
                    for s in &spec.subjects {
                        ensure!(
                            s.issuer == "local://trusted-launcher" && valid_name(&s.subject),
                            "unsupported subject identity"
                        );
                    }
                    grants.push(spec);
                }
            }
        }
        for grant in &grants {
            for name in &grant.capabilities {
                ensure!(
                    capabilities.contains_key(name),
                    "grant references unknown capability"
                );
            }
            for name in &grant.targets.names {
                ensure!(hosts.contains_key(name), "grant references unknown host");
            }
        }
        // These collections are set-like: canonical ordering prevents a harmless
        // YAML file or grant-list reorder from changing the effective snapshot ID.
        for grant in &mut grants {
            grant.subjects.sort();
            grant.capabilities.sort();
            grant.targets.names.sort();
        }
        grants.sort();
        let canonical =
            serde_json::to_vec(&(API_VERSION, OPERATION, &hosts, &capabilities, &grants))?;
        let mut hash = Sha256::new();
        hash.update(b"hostmarshal-snapshot-v1\0");
        hash.update(canonical);
        let snapshot_digest = format!("sha256:{:x}", hash.finalize());
        Ok(Self {
            hosts,
            capabilities,
            grants,
            snapshot_digest,
        })
    }

    /// A verifier must authenticate the issuer and subject before this is called.
    pub fn authorized_identity(
        &self,
        issuer: &str,
        principal: &str,
        capability: &str,
        target: &str,
    ) -> bool {
        self.capabilities.contains_key(capability)
            && self.hosts.contains_key(target)
            && self.grants.iter().any(|g| {
                g.subjects
                    .iter()
                    .any(|s| s.subject == principal && s.issuer == issuer)
                    && g.capabilities.iter().any(|n| n == capability)
                    && g.targets.names.iter().any(|n| n == target)
            })
    }

    /// Compatibility check for the existing trusted local launcher configuration.
    pub fn authorized(&self, principal: &str, capability: &str, target: &str) -> bool {
        self.authorized_identity("local://trusted-launcher", principal, capability, target)
    }

    pub fn visible_capabilities(&self, principal: &str) -> Vec<&PublishedCapability> {
        self.capabilities
            .values()
            .filter(|cap| {
                self.hosts
                    .keys()
                    .any(|host| self.authorized(principal, &cap.name, host))
            })
            .collect()
    }

    #[cfg(test)]
    pub fn invoke(&self, principal: &str, capability: &str, args: Value) -> Result<Value> {
        let Some(cap) = self.capabilities.get(capability) else {
            bail!("capability not found or not authorized");
        };
        let Some(obj) = args.as_object() else {
            bail!("invalid input");
        };
        ensure!(
            obj.len() == 1 && obj.get("target").and_then(Value::as_str).is_some(),
            "invalid input"
        );
        let target = obj["target"].as_str().unwrap_or_default();
        ensure!(
            self.authorized(principal, capability, target),
            "target not found or not authorized"
        );
        ensure!(cap.operation_ref == OPERATION, "operation not available");
        let host = self.hosts.get(target).context("target unavailable")?;
        let result = json!({"id": host.metadata.name, "hostname": host.spec.address});
        ensure!(
            serde_json::to_vec(&result)?.len() <= cap.max_output_bytes,
            "output exceeds limit"
        );
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Vec<Resource> {
        serde_saphyr::from_multiple(yaml).expect("valid fixture")
    }

    fn fixture() -> String {
        format!(
            r#"apiVersion: hostmarshal.io/v1alpha1
kind: Host
metadata: {{name: alpha, labels: {{environment: staging}}}}
spec: {{address: alpha.example.invalid}}
---
apiVersion: hostmarshal.io/v1alpha1
kind: Capability
metadata: {{name: inventory.inspect}}
spec:
  operationRef: builtin.inventory.inspect/v1
  targetKind: Host
  exposure: {{mcp: true}}
  inputSchema: {}
  outputSchema: {}
  limits: {{timeout: 2s, maxOutputBytes: 4096}}
---
apiVersion: hostmarshal.io/v1alpha1
kind: Grant
metadata: {{name: reader}}
spec:
  subjects:
    - {{issuer: "local://trusted-launcher", subject: operator}}
  capabilities: [inventory.inspect]
  targets: {{kind: Host, names: [alpha]}}
"#,
            serde_json::to_string(&input_schema()).unwrap(),
            serde_json::to_string(&output_schema()).unwrap()
        )
    }

    #[test]
    fn declarative_capability_requires_matching_grant() {
        let config = CompiledConfig::compile(parse(&fixture())).unwrap();
        assert_eq!(config.visible_capabilities("operator").len(), 1);
        assert!(config.visible_capabilities("guest").is_empty());
        assert!(
            config
                .invoke("guest", "inventory.inspect", json!({"target":"alpha"}))
                .is_err()
        );
        assert_eq!(
            config
                .invoke("operator", "inventory.inspect", json!({"target":"alpha"}))
                .unwrap()["id"],
            "alpha"
        );
        assert!(
            config
                .invoke("operator", "inventory.inspect", json!({"target":"other"}))
                .is_err()
        );
        assert!(
            config
                .invoke(
                    "operator",
                    "inventory.inspect",
                    json!({"target":"alpha","command":"id"})
                )
                .is_err()
        );
    }

    #[test]
    fn no_grant_means_no_access() {
        let only_host = r#"apiVersion: hostmarshal.io/v1alpha1
kind: Host
metadata: {name: alpha}
spec: {address: alpha.example.invalid}
"#;
        let config = CompiledConfig::compile(parse(only_host)).unwrap();
        assert!(config.visible_capabilities("operator").is_empty());
    }

    #[test]
    fn override_attempts_are_rejected() {
        let unsafe_yaml = fixture().replace(
            "  targetKind: Host",
            "  targetKind: Host\n  command: whoami",
        );
        assert!(serde_saphyr::from_multiple::<Resource>(&unsafe_yaml).is_err());

        let unknown_op = fixture().replace(OPERATION, "builtin.shell.exec/v1");
        assert!(CompiledConfig::compile(parse(&unknown_op)).is_err());

        let loosen_schema = fixture().replace(
            "additionalProperties\":false",
            "additionalProperties\":true",
        );
        assert!(CompiledConfig::compile(parse(&loosen_schema)).is_err());
    }

    #[test]
    fn unknown_versions_and_duplicate_keys_fail() {
        assert!(
            CompiledConfig::compile(parse(&fixture().replace(API_VERSION, "hostmarshal.io/v9")))
                .is_err()
        );
        let duplicate_key = "kind: Host\nkind: Grant\n";
        assert!(serde_saphyr::from_multiple::<Resource>(duplicate_key).is_err());
    }

    #[test]
    fn snapshot_digest_is_stable_and_changes_with_authorization() {
        let yaml = fixture();
        let first = CompiledConfig::compile(parse(&yaml)).unwrap();
        let mut docs = yaml.split("\n---\n").collect::<Vec<_>>();
        docs.reverse();
        let reversed = docs.join("\n---\n");
        let second = CompiledConfig::compile(parse(&reversed)).unwrap();
        assert_eq!(first.snapshot_digest, second.snapshot_digest);
        assert!(first.snapshot_digest.starts_with("sha256:"));
        assert_eq!(first.snapshot_digest.len(), 71);
        let changed = yaml.replace("subject: operator", "subject: other");
        let third = CompiledConfig::compile(parse(&changed)).unwrap();
        assert_ne!(first.snapshot_digest, third.snapshot_digest);
    }

    #[test]
    fn hardened_yaml_parser_rejects_anchors_tags_and_excessive_depth() {
        let host = r#"apiVersion: hostmarshal.io/v1alpha1
kind: Host
metadata:
  name: alpha
  labels:
    environment: staging
spec:
  address: alpha.example.invalid
"#;
        assert!(parse_manifests(host).is_ok());
        let anchors = host.replace("name: alpha", "name: &id alpha");
        assert!(parse_manifests(&anchors).is_err());
        let aliases = host.replace(
            "environment: staging",
            "environment: &env staging\n    alternate: *env",
        );
        assert!(parse_manifests(&aliases).is_err());
        let tag = host.replace("name: alpha", "name: !custom alpha");
        assert!(parse_manifests(&tag).is_err());
        let merge = host.replace("environment: staging", "<<: {environment: staging}");
        assert!(parse_manifests(&merge).is_err());
        let duplicate = host.replace("name: alpha", "name: alpha\n  name: bravo");
        assert!(parse_manifests(&duplicate).is_err());

        // inputSchema is an untyped JSON value during parsing, so without
        // parser structural budgets this valid Capability envelope could parse.
        let deep = format!(
            "apiVersion: hostmarshal.io/v1alpha1\nkind: Capability\nmetadata: {{name: test}}\nspec:\n  operationRef: {OPERATION}\n  targetKind: Host\n  exposure: {{mcp: true}}\n  inputSchema: {}x{}\n  outputSchema: {{}}\n  limits: {{timeout: 2s, maxOutputBytes: 4096}}\n",
            "[".repeat(MAX_DEPTH + 2),
            "]".repeat(MAX_DEPTH + 2)
        );
        assert!(parse_manifests(&deep).is_err());
    }

    #[test]
    fn two_capabilities_can_share_one_trusted_operation() {
        let second = format!(
            r#"---
apiVersion: hostmarshal.io/v1alpha1
kind: Capability
metadata: {{name: inventory.staging}}
spec:
  operationRef: builtin.inventory.inspect/v1
  targetKind: Host
  exposure: {{mcp: true}}
  inputSchema: {}
  outputSchema: {}
  limits: {{timeout: 2s, maxOutputBytes: 4096}}
---
apiVersion: hostmarshal.io/v1alpha1
kind: Grant
metadata: {{name: another-reader}}
spec:
  subjects:
    - {{issuer: "local://trusted-launcher", subject: operator}}
  capabilities: [inventory.staging]
  targets: {{kind: Host, names: [alpha]}}
"#,
            serde_json::to_string(&input_schema()).unwrap(),
            serde_json::to_string(&output_schema()).unwrap()
        );
        let c = CompiledConfig::compile(parse(&(fixture() + &second))).unwrap();
        assert_eq!(c.visible_capabilities("operator").len(), 2);
    }
}
