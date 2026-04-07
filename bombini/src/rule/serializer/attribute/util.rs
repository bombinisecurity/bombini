use std::collections::HashMap;

use crate::rule::ast::Literal;

pub fn serialize_string_attr(
    map: &mut HashMap<String, u8>,
    values: &[Literal],
    in_idx: u8,
) -> Result<(), anyhow::Error> {
    let values: Result<Vec<String>, anyhow::Error> = values
        .iter()
        .map(|lit| match lit {
            Literal::String(s) => Ok(s.clone()),
            Literal::Uint(i) => Err(anyhow::anyhow!(
                "expected String literal, found Uint: {}",
                i
            )),
        })
        .collect();
    let values = values?;
    for key in values {
        map.entry(key)
            .and_modify(|value| *value |= 1 << in_idx)
            .or_insert(1 << in_idx);
    }
    Ok(())
}

pub fn serialize_u32_attr(
    map: &mut HashMap<u32, u8>,
    values: &[Literal],
    in_idx: u8,
) -> Result<(), anyhow::Error> {
    let values: Result<Vec<u32>, anyhow::Error> = values
        .iter()
        .map(|lit| match lit {
            Literal::Uint(i) => Ok(*i as u32),
            Literal::String(s) => Err(anyhow::anyhow!(
                "expected Uint literal, found String: {}",
                s
            )),
        })
        .collect();
    let values = values?;
    for key in values {
        map.entry(key)
            .and_modify(|value| *value |= 1 << in_idx)
            .or_insert(1 << in_idx);
    }
    Ok(())
}
