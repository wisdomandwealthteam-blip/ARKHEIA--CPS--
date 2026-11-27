//! Closed-subset JSON Schema (draft 2020-12) interpreter.
//! Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//!
//! Interprets arkheia-receipt-schema-v1.json directly (embedded at build time).
//! Unknown keywords fail at load — a schema edit is never silently ignored.

use crate::jcs::canonicalize;
use crate::json::{parse_strict, Value};
use crate::pattern::Pattern;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::OnceLock;

pub const RECEIPT_SCHEMA_JSON: &str = include_str!("../schema/arkheia-receipt-schema-v1.json");

const ANNOTATIONS: &[&str] = &["$schema", "$id", "title", "description"];
const ASSERTIONS: &[&str] = &[
    "type", "const", "enum", "minLength", "maxLength", "pattern", "not", "$ref", "additionalProperties", "required",
    "properties", "allOf", "if", "then", "else", "minimum", "maximum", "maxItems", "uniqueItems", "items",
    "maxProperties", "propertyNames", "$defs",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDefinitionError(pub String);
impl fmt::Display for SchemaDefinitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "schema definition error: {}", self.0)
    }
}
impl std::error::Error for SchemaDefinitionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaViolation {
    pub path: String,
    pub keyword: &'static str,
}

pub struct CompiledSchema {
    root: Value,
    patterns: HashMap<String, Pattern>,
}

fn check_supported(node: &Value, path: &str, patterns: &mut HashMap<String, Pattern>) -> Result<(), SchemaDefinitionError> {
    let m = match node {
        Value::Bool(_) => return Ok(()),
        Value::Object(m) => m,
        _ => return Err(SchemaDefinitionError(format!("schema node at {path} must be object or boolean"))),
    };
    for (k, v) in m {
        if !ANNOTATIONS.contains(&k.as_str()) && !ASSERTIONS.contains(&k.as_str()) {
            return Err(SchemaDefinitionError(format!("unsupported schema keyword \"{k}\" at {path}")));
        }
        match k.as_str() {
            "not" | "if" | "then" | "else" | "items" | "propertyNames" | "additionalProperties" => {
                check_supported(v, &format!("{path}/{k}"), patterns)?
            }
            "properties" | "$defs" => {
                for (pk, pv) in v.as_object().ok_or_else(|| SchemaDefinitionError(format!("{path}/{k} must be object")))? {
                    check_supported(pv, &format!("{path}/{k}/{pk}"), patterns)?;
                }
            }
            "allOf" => {
                for (idx, sub) in v.as_array().ok_or_else(|| SchemaDefinitionError(format!("{path}/allOf must be array")))?.iter().enumerate() {
                    check_supported(sub, &format!("{path}/allOf/{idx}"), patterns)?;
                }
            }
            "pattern" => {
                let p = v.as_str().ok_or_else(|| SchemaDefinitionError(format!("{path}/pattern must be string")))?;
                let compiled = Pattern::compile(p).map_err(|e| SchemaDefinitionError(e.to_string()))?;
                patterns.insert(p.to_string(), compiled);
            }
            _ => {}
        }
    }
    Ok(())
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Int(_) => "integer",
        Value::Str(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn deep_equal(a: &Value, b: &Value) -> bool {
    match (canonicalize(a), canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

impl CompiledSchema {
    pub fn compile(root: Value) -> Result<CompiledSchema, SchemaDefinitionError> {
        let mut patterns = HashMap::new();
        check_supported(&root, "#", &mut patterns)?;
        Ok(CompiledSchema { root, patterns })
    }

    fn resolve(&self, r: &str) -> Option<&Value> {
        let rest = r.strip_prefix("#/")?;
        let mut node = &self.root;
        for part in rest.split('/') {
            node = node.get(part)?;
        }
        Some(node)
    }

    pub fn validate(&self, value: &Value) -> Vec<SchemaViolation> {
        let mut errors = Vec::new();
        self.walk(&self.root, value, "$", &mut errors);
        errors
    }

    fn walk(&self, schema: &Value, value: &Value, path: &str, errors: &mut Vec<SchemaViolation>) {
        let err = |errors: &mut Vec<SchemaViolation>, p: &str, k: &'static str| errors.push(SchemaViolation { path: p.to_string(), keyword: k });
        match schema {
            Value::Bool(true) => return,
            Value::Bool(false) => return err(errors, path, "false"),
            _ => {}
        }
        if let Some(Value::Str(r)) = schema.get("$ref") {
            match self.resolve(r) {
                Some(target) => self.walk(target, value, path, errors),
                None => err(errors, path, "$ref"),
            }
        }
        if let Some(Value::Str(t)) = schema.get("type") {
            let actual = json_type(value);
            let ok = actual == t || (t == "number" && actual == "integer");
            if !ok {
                return err(errors, path, "type");
            }
        }
        if let Some(c) = schema.get("const") {
            if !deep_equal(c, value) {
                err(errors, path, "const");
            }
        }
        if let Some(Value::Array(options)) = schema.get("enum") {
            if !options.iter().any(|o| deep_equal(o, value)) {
                err(errors, path, "enum");
            }
        }
        if let Some(n) = schema.get("not") {
            let mut sub = Vec::new();
            self.walk(n, value, path, &mut sub);
            if sub.is_empty() {
                err(errors, path, "not");
            }
        }
        if let Some(Value::Array(all)) = schema.get("allOf") {
            for s in all {
                self.walk(s, value, path, errors);
            }
        }
        if let Some(cond) = schema.get("if") {
            let mut sub = Vec::new();
            self.walk(cond, value, path, &mut sub);
            if sub.is_empty() {
                if let Some(t) = schema.get("then") {
                    self.walk(t, value, path, errors);
                }
            } else if let Some(e) = schema.get("else") {
                self.walk(e, value, path, errors);
            }
        }
        match value {
            Value::Str(st) => {
                let len = st.chars().count() as i64;
                let mut length_ok = true;
                if let Some(Value::Int(min)) = schema.get("minLength") {
                    if len < *min {
                        err(errors, path, "minLength");
                        length_ok = false;
                    }
                }
                if let Some(Value::Int(max)) = schema.get("maxLength") {
                    if len > *max {
                        err(errors, path, "maxLength");
                        length_ok = false;
                    }
                }
                if let Some(Value::Str(p)) = schema.get("pattern") {
                    // Skip matching (but still fail) on length violations: bounds backtracking cost.
                    let matched = length_ok && self.patterns.get(p).is_some_and(|pat| pat.is_match(st));
                    if !matched {
                        err(errors, path, "pattern");
                    }
                }
            }
            Value::Int(i) => {
                if let Some(Value::Int(min)) = schema.get("minimum") {
                    if i < min {
                        err(errors, path, "minimum");
                    }
                }
                if let Some(Value::Int(max)) = schema.get("maximum") {
                    if i > max {
                        err(errors, path, "maximum");
                    }
                }
            }
            Value::Array(a) => {
                if let Some(Value::Int(max)) = schema.get("maxItems") {
                    if a.len() as i64 > *max {
                        err(errors, path, "maxItems");
                    }
                }
                if let Some(Value::Bool(true)) = schema.get("uniqueItems") {
                    let mut seen = HashSet::new();
                    for item in a {
                        let fresh = match canonicalize(item) {
                            Ok(c) => seen.insert(c),
                            Err(_) => false,
                        };
                        if !fresh {
                            err(errors, path, "uniqueItems");
                            break;
                        }
                    }
                }
                if let Some(items) = schema.get("items") {
                    for (idx, item) in a.iter().enumerate() {
                        self.walk(items, item, &format!("{path}[{idx}]"), errors);
                    }
                }
            }
            Value::Object(m) => {
                if let Some(Value::Int(max)) = schema.get("maxProperties") {
                    if m.len() as i64 > *max {
                        err(errors, path, "maxProperties");
                    }
                }
                if let Some(Value::Array(req)) = schema.get("required") {
                    for r in req {
                        if let Value::Str(r) = r {
                            if value.get(r).is_none() {
                                err(errors, &format!("{path}.{r}"), "required");
                            }
                        }
                    }
                }
                if let Some(pn) = schema.get("propertyNames") {
                    for (k, _) in m {
                        self.walk(pn, &Value::Str(k.clone()), &format!("{path}{{{k}}}"), errors);
                    }
                }
                let props = schema.get("properties");
                for (k, v) in m {
                    match props.and_then(|p| p.get(k)) {
                        Some(ps) => self.walk(ps, v, &format!("{path}.{k}"), errors),
                        None => {
                            if let Some(ap) = schema.get("additionalProperties") {
                                self.walk(ap, v, &format!("{path}.{k}"), errors);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// The embedded, compiled receipt schema. Panics at first use if the embedded
/// schema is malformed (a build defect, caught by `cargo test`).
pub fn receipt_schema() -> &'static CompiledSchema {
    static S: OnceLock<CompiledSchema> = OnceLock::new();
    S.get_or_init(|| {
        let v = parse_strict(RECEIPT_SCHEMA_JSON).expect("embedded schema parses");
        CompiledSchema::compile(v).expect("embedded schema compiles")
    })
}

pub fn validate_receipt_schema(v: &Value) -> Vec<SchemaViolation> {
    receipt_schema().validate(v)
}
