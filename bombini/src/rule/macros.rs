use std::collections::HashMap;

use anyhow::{Result, bail};
use serde_yml::Value;

pub fn expand_config(value: &mut Value) -> Result<()> {
    let Value::Mapping(map) = value else {
        return Ok(());
    };

    let lists = match map.remove("lists") {
        Some(lists_val) => parse_list_defs(&lists_val)?,
        None => HashMap::new(),
    };
    let mut macros = match map.remove("macros") {
        Some(macros_val) => parse_macro_defs(&macros_val)?,
        None => HashMap::new(),
    };

    if lists.is_empty() && macros.is_empty() {
        return Ok(());
    }

    for condition in macros.values_mut() {
        *condition = substitute_lists(condition, &lists);
    }

    expand_value(value, &lists, &macros);
    Ok(())
}

fn parse_list_defs(lists_val: &Value) -> Result<HashMap<String, String>> {
    let Some(items) = lists_val.as_sequence() else {
        bail!("`lists` must be a list of `- list: <name>` / `items: [...]` entries");
    };

    let mut defs = HashMap::new();
    for item in items {
        let Value::Mapping(entry) = item else {
            bail!("each `lists` entry must be a mapping with `list` and `items` keys");
        };
        let Some(name) = entry.get("list").and_then(Value::as_str) else {
            bail!("`lists` entry is missing a string `list` name");
        };
        if !is_valid_name(name) {
            bail!("invalid list name `{name}`: expected an identifier like `shell_binaries`");
        }
        let Some(values) = entry.get("items").and_then(Value::as_sequence) else {
            bail!("list `{name}` is missing an `items` array");
        };
        if values.is_empty() {
            bail!("list `{name}` has no items");
        }
        let parts: Vec<String> = values
            .iter()
            .map(|value| {
                serde_json::to_string(value)
                    .expect("a YAML scalar always serializes to a JSON literal")
            })
            .collect();
        if defs.insert(name.to_string(), parts.join(", ")).is_some() {
            bail!("list `{name}` is defined more than once");
        }
    }
    Ok(defs)
}

fn parse_macro_defs(macros_val: &Value) -> Result<HashMap<String, String>> {
    let Some(items) = macros_val.as_sequence() else {
        bail!("`macros` must be a list of `- macro: <name>` / `condition: <expr>` entries");
    };

    let mut defs = HashMap::new();
    for item in items {
        let Value::Mapping(entry) = item else {
            bail!("each `macros` entry must be a mapping with `macro` and `condition` keys");
        };
        let Some(name) = entry.get("macro").and_then(Value::as_str) else {
            bail!("`macros` entry is missing a string `macro` name");
        };
        let Some(condition) = entry.get("condition").and_then(Value::as_str) else {
            bail!("macro `{name}` is missing a string `condition`");
        };
        if !is_valid_name(name) {
            bail!("invalid macro name `{name}`: expected an identifier like `shell_proc`");
        }
        if condition.trim().is_empty() {
            bail!("macro `{name}` has an empty `condition`");
        }
        if defs
            .insert(name.to_string(), condition.to_string())
            .is_some()
        {
            bail!("macro `{name}` is defined more than once");
        }
    }
    Ok(defs)
}

/// Scans `input` for identifiers, passing each one to `on_ident` (which appends
/// its replacement to the output). Text inside quoted `"..."` spans and all other
/// characters are copied through unchanged. An identifier starts with an ASCII
/// letter and continues over ASCII alphanumerics and `_`.
fn replace_idents(input: &str, mut on_ident: impl FnMut(&str, &mut String)) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            out.push(c);
            i += 1;
            while i < chars.len() {
                out.push(chars[i]);
                let closed = chars[i] == '"';
                i += 1;
                if closed {
                    break;
                }
            }
        } else if c.is_ascii_alphabetic() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            on_ident(&ident, &mut out);
        } else {
            out.push(c);
            i += 1;
        }
    }

    out
}

fn substitute_lists(input: &str, lists: &HashMap<String, String>) -> String {
    if lists.is_empty() {
        return input.to_string();
    }
    replace_idents(input, |ident, out| match lists.get(ident) {
        Some(items) => out.push_str(items),
        None => out.push_str(ident),
    })
}

fn expand_str(input: &str, macros: &HashMap<String, String>) -> String {
    replace_idents(input, |ident, out| match macros.get(ident) {
        Some(condition) => {
            out.push('(');
            out.push_str(condition);
            out.push(')');
        }
        None => out.push_str(ident),
    })
}

fn expand_value(
    value: &mut Value,
    lists: &HashMap<String, String>,
    macros: &HashMap<String, String>,
) {
    match value {
        Value::Mapping(map) => {
            for (key, val) in map.iter_mut() {
                if matches!(key.as_str(), "scope" | "event")
                    && let Some(pred) = val.as_str()
                {
                    let pred = substitute_lists(pred, lists);
                    let pred = expand_str(&pred, macros);
                    *val = Value::String(pred);
                    continue;
                }
                expand_value(val, lists, macros);
            }
        }
        Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                expand_value(item, lists, macros);
            }
        }
        _ => {}
    }
}

fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn substitute_lists_only_replaces_whole_idents() {
        let defs = lists(&[("shell", "\"bash\", \"sh\"")]);
        // exact identifier is replaced
        assert_eq!(
            substitute_lists("comm in (shell)", &defs),
            "comm in (\"bash\", \"sh\")"
        );
        // identifiers that merely contain the name are left alone
        assert_eq!(
            substitute_lists("comm == shell_binaries", &defs),
            "comm == shell_binaries"
        );
    }

    #[test]
    fn substitute_lists_skips_string_literals() {
        let defs = lists(&[("shell", "\"bash\"")]);
        assert_eq!(
            substitute_lists("comm == \"shell\"", &defs),
            "comm == \"shell\""
        );
    }

    #[test]
    fn expand_str_wraps_macro_in_parens() {
        let macros = lists(&[("is_shell", "comm in (\"bash\", \"sh\")")]);
        assert_eq!(
            expand_str("is_shell and uid == 0", &macros),
            "(comm in (\"bash\", \"sh\")) and uid == 0"
        );
        // unknown identifiers pass through untouched
        assert_eq!(expand_str("uid == 0", &macros), "uid == 0");
    }

    #[test]
    fn parse_list_defs_quotes_scalars() {
        let val: Value = serde_yml::from_str(
            "- list: ports\n  items: [22, 80]\n- list: names\n  items: [bash, sh]\n",
        )
        .unwrap();
        let defs = parse_list_defs(&val).unwrap();
        assert_eq!(defs["ports"], "22, 80");
        assert_eq!(defs["names"], "\"bash\", \"sh\"");
    }

    #[test]
    fn parse_list_defs_rejects_empty_items() {
        let val: Value = serde_yml::from_str("- list: empty\n  items: []\n").unwrap();
        assert!(parse_list_defs(&val).is_err());
    }

    #[test]
    fn parse_list_defs_rejects_duplicate() {
        let val: Value =
            serde_yml::from_str("- list: dup\n  items: [a]\n- list: dup\n  items: [b]\n").unwrap();
        assert!(parse_list_defs(&val).is_err());
    }

    #[test]
    fn parse_macro_defs_rejects_empty_condition() {
        let val: Value = serde_yml::from_str("- macro: m\n  condition: '   '\n").unwrap();
        assert!(parse_macro_defs(&val).is_err());
    }

    #[test]
    fn is_valid_name_checks() {
        assert!(is_valid_name("shell_proc"));
        assert!(is_valid_name("a1"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("1abc"));
        assert!(!is_valid_name("has space"));
        assert!(!is_valid_name("has-dash"));
    }

    #[test]
    fn expand_config_expands_scope_with_lists_and_macros() {
        let mut config: Value = serde_yml::from_str(
            r#"
lists:
  - list: shells
    items: [bash, sh]
macros:
  - macro: is_shell
    condition: comm in (shells)
procmon:
  scope: is_shell and uid == 0
"#,
        )
        .unwrap();

        expand_config(&mut config).unwrap();

        // `lists`/`macros` definitions are consumed
        let map = config.as_mapping().unwrap();
        assert!(!map.contains_key("lists"));
        assert!(!map.contains_key("macros"));

        let scope = config["procmon"]["scope"].as_str().unwrap();
        assert_eq!(scope, "(comm in (\"bash\", \"sh\")) and uid == 0");
    }

    #[test]
    fn expand_config_noop_without_defs() {
        let mut config: Value = serde_yml::from_str("procmon:\n  scope: comm == \"ls\"\n").unwrap();
        let before = config.clone();
        expand_config(&mut config).unwrap();
        assert_eq!(config, before);
    }
}
