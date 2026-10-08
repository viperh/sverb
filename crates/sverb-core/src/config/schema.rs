//! JSON Schema for `config.toml`, for editor completion (`sverb config --schema`).
//!
//! The committed copy is `docs/config.schema.json`; a test fails when it is stale.
//! Regenerate it with `SVERB_BLESS_SCHEMA=1 cargo test -p sverb-core config::schema`.

use super::Config;

/// The schema as a `serde_json` value.
pub fn json_schema_value() -> serde_json::Value {
    schemars::schema_for!(Config).to_value()
}

/// The schema as pretty-printed JSON with a trailing newline.
pub fn json_schema() -> String {
    // Serializing a `serde_json::Value` can't fail.
    let mut out = serde_json::to_string_pretty(&json_schema_value()).unwrap_or_default();
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use serde_json::Value;

    use super::*;

    fn committed_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/config.schema.json")
    }

    /// T-21: `docs/config.schema.json` matches the model.
    #[test]
    fn t21_schema_is_fresh() {
        let generated = json_schema();
        if std::env::var_os("SVERB_BLESS_SCHEMA").is_some() {
            std::fs::write(committed_path(), &generated).unwrap();
        }
        let committed = std::fs::read_to_string(committed_path()).unwrap_or_default();
        assert!(
            committed == generated,
            "docs/config.schema.json is stale; run `SVERB_BLESS_SCHEMA=1 cargo test -p sverb-core config::schema`"
        );
    }

    /// Minimal structural JSON Schema check (the `jsonschema` crate isn't vendored):
    /// `type`, `properties`, `additionalProperties: false`, `enum`, `$ref`, `minimum`.
    fn check(schema: &Value, root: &Value, value: &Value, path: &str, errors: &mut Vec<String>) {
        if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
            let target = r
                .strip_prefix("#/")
                .map(|p| p.split('/').fold(root, |v, seg| &v[seg]))
                .unwrap_or(&Value::Null);
            return check(target, root, value, path, errors);
        }
        if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
            for s in all {
                check(s, root, value, path, errors);
            }
        }
        if let Some(any) = schema
            .get("oneOf")
            .or_else(|| schema.get("anyOf"))
            .and_then(Value::as_array)
        {
            let ok = any.iter().any(|s| {
                let mut e = Vec::new();
                check(s, root, value, path, &mut e);
                e.is_empty()
            });
            if !ok {
                errors.push(format!("{path}: matches none of the alternatives"));
            }
        }
        if let Some(c) = schema.get("const")
            && c != value
        {
            errors.push(format!("{path}: expected {c}"));
        }
        if let Some(e) = schema.get("enum").and_then(Value::as_array)
            && !e.contains(value)
        {
            errors.push(format!("{path}: {value} not in enum"));
        }
        if let Some(t) = schema.get("type") {
            let types: Vec<&str> = match t {
                Value::String(s) => vec![s.as_str()],
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            let ok = types.iter().any(|t| match *t {
                "object" => value.is_object(),
                "string" => value.is_string(),
                "boolean" => value.is_boolean(),
                "integer" => value.is_u64() || value.is_i64(),
                "number" => value.is_number(),
                "array" => value.is_array(),
                "null" => value.is_null(),
                _ => false,
            });
            if !ok {
                errors.push(format!("{path}: {value} is not of type {t}"));
            }
        }
        if let (Some(min), Some(v)) = (
            schema.get("minimum").and_then(Value::as_f64),
            value.as_f64(),
        ) && v < min
        {
            errors.push(format!("{path}: {v} < minimum {min}"));
        }
        if let Some(obj) = value.as_object() {
            let props = schema.get("properties").and_then(Value::as_object);
            for (k, v) in obj {
                let sub = props.and_then(|p| p.get(k));
                match (sub, schema.get("additionalProperties")) {
                    (Some(s), _) => check(s, root, v, &format!("{path}.{k}"), errors),
                    (None, Some(Value::Bool(false))) => {
                        errors.push(format!("{path}.{k}: additional property not allowed"));
                    }
                    (None, Some(ap @ Value::Object(_))) => {
                        check(ap, root, v, &format!("{path}.{k}"), errors);
                    }
                    _ => {}
                }
            }
        }
    }

    /// T-22: the schema accepts the defaults, and rejects a wrong type and an unknown key.
    #[test]
    fn t22_schema_accepts_defaults() {
        let schema = json_schema_value();
        let defaults = serde_json::to_value(Config::default()).unwrap();
        let mut errors = Vec::new();
        check(&schema, &schema, &defaults, "$", &mut errors);
        assert!(errors.is_empty(), "{errors:#?}");

        let mut bad = defaults.clone();
        bad["ssh"]["keepalive_secs"] = Value::String("x".into());
        bad["ssh"]["keepalive_sec"] = Value::from(1);
        bad["ssh"]["host_key_policy"] = Value::String("yolo".into());
        let mut errors = Vec::new();
        check(&schema, &schema, &bad, "$", &mut errors);
        assert_eq!(errors.len(), 3, "{errors:#?}");

        // Every top-level property documents its default.
        let props = schema["properties"].as_object().unwrap();
        for (k, v) in props {
            assert!(v.get("description").is_some(), "{k} has no description");
        }
    }
}
