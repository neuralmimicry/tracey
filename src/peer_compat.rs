use serde_json::{Map, Value};
use std::collections::HashMap;

const FIELD_MATCH_THRESHOLD: f64 = 0.72;

#[derive(Clone, Copy)]
pub(crate) struct SchemaField<'a> {
    pub aliases: &'a [&'a str],
    pub required: bool,
    pub weight: f64,
}

#[derive(Clone, Copy)]
pub(crate) struct ObjectMatch<'a> {
    pub map: &'a Map<String, Value>,
    pub score: f64,
}

pub(crate) fn parse_bytes(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(bytes)
}

pub(crate) fn parse_str(body: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str(body)
}

pub(crate) fn best_object<'a>(
    root: &'a Value,
    fields: &[SchemaField<'_>],
    min_score: f64,
    max_depth: usize,
) -> Option<ObjectMatch<'a>> {
    let mut best: Option<ObjectMatch<'a>> = None;
    visit_objects(root, 0, max_depth, &mut |map, depth| {
        let mut score = 0.0;
        let mut required_matches = 0usize;
        let required_fields = fields.iter().filter(|field| field.required).count();
        for field in fields {
            let key_score = best_key_score(map, field.aliases);
            if key_score >= FIELD_MATCH_THRESHOLD {
                score += field.weight * key_score;
                if field.required {
                    required_matches += 1;
                }
            } else if field.required {
                score -= field.weight * 0.75;
            }
        }
        score -= depth as f64 * 0.08;
        if required_fields > 0 && required_matches == 0 {
            return;
        }
        if score >= min_score && best.is_none_or(|current| score > current.score) {
            best = Some(ObjectMatch { map, score });
        }
    });
    best
}

pub(crate) fn value_for<'a>(map: &'a Map<String, Value>, aliases: &[&str]) -> Option<&'a Value> {
    let mut best: Option<(&'a Value, f64)> = None;
    for (key, value) in map {
        let score = aliases
            .iter()
            .map(|alias| key_similarity(key, alias))
            .fold(0.0, f64::max);
        if score >= FIELD_MATCH_THRESHOLD
            && best.is_none_or(|(_, best_score)| score > best_score)
        {
            best = Some((value, score));
        }
    }
    best.map(|(value, _)| value)
}

pub(crate) fn object_for(map: &Map<String, Value>, aliases: &[&str]) -> Option<Map<String, Value>> {
    let value = value_for(map, aliases)?;
    value_as_object(value)
}

pub(crate) fn array_for(map: &Map<String, Value>, aliases: &[&str]) -> Option<Vec<Value>> {
    let value = value_for(map, aliases)?;
    value_as_array(value)
}

pub(crate) fn value_as_object(value: &Value) -> Option<Map<String, Value>> {
    match value {
        Value::Object(map) => Some(map.clone()),
        Value::String(text) => parse_embedded_json(text)?.as_object().cloned(),
        _ => None,
    }
}

pub(crate) fn value_as_array(value: &Value) -> Option<Vec<Value>> {
    match value {
        Value::Array(items) => Some(items.clone()),
        Value::Object(_) => Some(vec![value.clone()]),
        Value::String(text) => match parse_embedded_json(text)? {
            Value::Array(items) => Some(items),
            Value::Object(map) => Some(vec![Value::Object(map)]),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn coerce_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(value) => Some(if *value { "true" } else { "false" }.to_string()),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().filter_map(coerce_string).collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(","))
            }
        }
        Value::Object(map) => map
            .values()
            .find_map(coerce_string)
            .filter(|value| !value.is_empty()),
        Value::Null => None,
    }
}

pub(crate) fn coerce_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(number) => number.as_i64().map(|value| value != 0),
        Value::String(text) => {
            let normalized = text.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "true" | "yes" | "y" | "1" | "on" | "ready" | "up" => Some(true),
                "false" | "no" | "n" | "0" | "off" | "down" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

pub(crate) fn coerce_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_i64().filter(|value| *value >= 0).map(|value| value as u64))
            .or_else(|| {
                number
                    .as_f64()
                    .filter(|value| value.is_finite() && *value >= 0.0)
                    .map(|value| value.round() as u64)
            }),
        Value::String(text) => {
            let trimmed = text.trim().trim_end_matches("ms");
            trimmed
                .parse::<u64>()
                .ok()
                .or_else(|| trimmed.parse::<f64>().ok().map(|value| value.round() as u64))
        }
        Value::Bool(value) => Some(u64::from(*value)),
        _ => None,
    }
}

pub(crate) fn coerce_usize(value: &Value) -> Option<usize> {
    coerce_u64(value).map(|value| value as usize)
}

pub(crate) fn coerce_u32(value: &Value) -> Option<u32> {
    coerce_u64(value)
        .filter(|value| *value <= u32::MAX as u64)
        .map(|value| value as u32)
}

pub(crate) fn coerce_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => {
            let trimmed = text.trim();
            if let Some(percent) = trimmed.strip_suffix('%') {
                percent.trim().parse::<f64>().ok().map(|value| value / 100.0)
            } else {
                trimmed.parse::<f64>().ok()
            }
        }
        Value::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
        _ => None,
    }
}

pub(crate) fn coerce_unit_interval(value: &Value) -> Option<f64> {
    let raw = coerce_f64(value)?;
    if !raw.is_finite() {
        return None;
    }
    if (0.0..=1.0).contains(&raw) {
        Some(raw)
    } else if (1.0..=100.0).contains(&raw) {
        Some(raw / 100.0)
    } else {
        Some(raw.clamp(0.0, 1.0))
    }
}

pub(crate) fn coerce_string_vec(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items.iter().filter_map(coerce_string).collect(),
        Value::String(text) => text
            .split(|ch: char| matches!(ch, ',' | ';' | '\n' | '\r'))
            .flat_map(|part| part.split_whitespace())
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        _ => coerce_string(value).into_iter().collect(),
    }
}

fn visit_objects<'a, F>(value: &'a Value, depth: usize, max_depth: usize, visit: &mut F)
where
    F: FnMut(&'a Map<String, Value>, usize),
{
    if depth > max_depth {
        return;
    }
    match value {
        Value::Object(map) => {
            visit(map, depth);
            for nested in map.values() {
                visit_objects(nested, depth + 1, max_depth, visit);
            }
        }
        Value::Array(items) => {
            for item in items {
                visit_objects(item, depth + 1, max_depth, visit);
            }
        }
        _ => {}
    }
}

fn best_key_score(map: &Map<String, Value>, aliases: &[&str]) -> f64 {
    map.keys()
        .map(|key| {
            aliases
                .iter()
                .map(|alias| key_similarity(key, alias))
                .fold(0.0, f64::max)
        })
        .fold(0.0, f64::max)
}

fn key_similarity(left: &str, right: &str) -> f64 {
    let left_norm = normalize_key(left);
    let right_norm = normalize_key(right);
    if left_norm.is_empty() || right_norm.is_empty() {
        return 0.0;
    }
    if left_norm == right_norm {
        return 1.0;
    }
    if left_norm.len() >= 4 && right_norm.len() >= 4 {
        if left_norm.contains(&right_norm) || right_norm.contains(&left_norm) {
            return 0.9;
        }
    }
    dice_coefficient(&left_norm, &right_norm)
}

fn normalize_key(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out
}

fn dice_coefficient(left: &str, right: &str) -> f64 {
    if left == right {
        return 1.0;
    }
    if left.len() < 2 || right.len() < 2 {
        return 0.0;
    }

    let mut counts = HashMap::new();
    for pair in bigrams(left) {
        *counts.entry(pair).or_insert(0usize) += 1;
    }

    let mut overlap = 0usize;
    for pair in bigrams(right) {
        if let Some(count) = counts.get_mut(&pair)
            && *count > 0
        {
            *count -= 1;
            overlap += 1;
        }
    }

    (2.0 * overlap as f64) / ((left.len() - 1 + right.len() - 1) as f64)
}

fn bigrams(value: &str) -> Vec<(u8, u8)> {
    let bytes = value.as_bytes();
    bytes.windows(2).map(|pair| (pair[0], pair[1])).collect()
}

fn parse_embedded_json(text: &str) -> Option<Value> {
    let trimmed = text.trim();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return None;
    }
    serde_json::from_str(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn best_object_finds_nested_payload() {
        let value = serde_json::json!({
            "wrapper": {
                "payload": {
                    "agentId": "peer-1",
                    "timestamp_ms": "42",
                    "sig": "abcd"
                }
            }
        });
        let fields = [
            SchemaField {
                aliases: &["agent_id", "agentId"],
                required: true,
                weight: 1.0,
            },
            SchemaField {
                aliases: &["ts_ms", "timestamp_ms"],
                required: true,
                weight: 1.0,
            },
            SchemaField {
                aliases: &["signature", "sig"],
                required: true,
                weight: 1.0,
            },
        ];
        let matched = best_object(&value, &fields, 1.0, 3).expect("object should match");
        assert_eq!(
            coerce_string(value_for(matched.map, &["agent_id", "agentId"]).unwrap()).as_deref(),
            Some("peer-1")
        );
    }

    #[test]
    fn coercion_handles_percentages_and_csv_lists() {
        assert_eq!(
            coerce_unit_interval(&Value::String("62%".to_string())),
            Some(0.62)
        );
        assert_eq!(
            coerce_string_vec(&Value::String("a, b; c".to_string())),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }
}
