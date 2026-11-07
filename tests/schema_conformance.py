"""Independent JSON Schema Draft 2020-12 conformance checks (FR-001).

This is intentionally separate from the Rust Serde loader and uses PyYAML and
python-jsonschema. Structural validation does not confer execution authority.
"""
import copy
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/v1alpha1/resources.schema.json"
FIXTURES = ROOT / "config/v1alpha1"


def main():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert schema["$id"] == "urn:hostmarshal:schemas:v1alpha1:resource"
    assert schema["$schema"].endswith("/2020-12/schema")

    # Schema distribution must be self-contained: never resolve HTTP refs.
    def refs(obj):
        if isinstance(obj, dict):
            if "$ref" in obj:
                yield obj["$ref"]
            for value in obj.values():
                yield from refs(value)
        elif isinstance(obj, list):
            for value in obj:
                yield from refs(value)
    assert all(ref.startswith("#/") for ref in refs(schema))

    validator = Draft202012Validator(schema)
    documents = []
    for path in sorted(FIXTURES.glob("*.yaml")):
        documents.extend(x for x in yaml.safe_load_all(path.read_text()) if x is not None)
    assert len(documents) == 3
    for resource in documents:
        validator.validate(resource)
    by_kind = {item["kind"]: item for item in documents}
    assert set(by_kind) == {"Host", "Capability", "Grant"}

    invalid = []
    invalid.append({**by_kind["Host"], "apiVersion": "hostmarshal.io/v999"})
    invalid.append({**by_kind["Host"], "kind": "Unknown"})
    missing_kind = copy.deepcopy(by_kind["Host"])
    del missing_kind["kind"]
    invalid.append(missing_kind)
    extra_spec = copy.deepcopy(by_kind["Host"])
    extra_spec["spec"]["unsafeCommand"] = "whoami"
    invalid.append(extra_spec)
    wrong_metadata = copy.deepcopy(by_kind["Host"])
    wrong_metadata["metadata"]["name"] = 123
    invalid.append(wrong_metadata)
    wrong_targets = copy.deepcopy(by_kind["Grant"])
    wrong_targets["spec"]["targets"]["names"] = "sample-linux"
    invalid.append(wrong_targets)
    for index, resource in enumerate(invalid):
        assert not validator.is_valid(resource), f"invalid fixture {index} was accepted"
    print(f"Schema conformance: {len(documents)} valid, {len(invalid)} invalid fixtures verified")


if __name__ == "__main__":
    main()
