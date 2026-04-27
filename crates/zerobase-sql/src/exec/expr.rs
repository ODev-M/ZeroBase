//! Expression evaluator. Walks an `Expr` against a runtime row plus the
//! virtual schema (qualified columns from joins/single table), returning a
//! `Value`.

use crate::error::{SqlError, SqlResult};
use crate::parse::{BinaryOp, ColRef, Expr};
use crate::plan::VirtualSchema;
use crate::types::{Row, Value};

/// Evaluate `expr` against `row`. `schema` is the virtual schema of the row
/// so we can resolve column references (`ColRef { table, column }`) by slot.
pub fn eval(expr: &Expr, row: &Row, schema: &VirtualSchema) -> SqlResult<Value> {
    match expr {
        Expr::Lit(v) => Ok(v.clone()),
        Expr::Col(c) => {
            let idx = resolve(schema, c)?;
            Ok(row[idx].clone())
        }
        Expr::Not(inner) => Ok(invert_bool(&eval(inner, row, schema)?)),
        Expr::IsNull { operand, negated } => {
            let v = eval(operand, row, schema)?;
            Ok(Value::Bool(matches!(v, Value::Null) ^ *negated))
        }
        Expr::Binary { op, lhs, rhs } => {
            let l = eval(lhs, row, schema)?;
            let r = eval(rhs, row, schema)?;
            apply_binary(*op, l, r)
        }
    }
}

fn resolve(schema: &VirtualSchema, c: &ColRef) -> SqlResult<usize> {
    let mut found: Option<usize> = None;
    for (i, vc) in schema.columns.iter().enumerate() {
        if vc.meta.name != c.column {
            continue;
        }
        if let Some(q) = &c.table {
            if &vc.qualifier != q {
                continue;
            }
        }
        if found.is_some() {
            return Err(SqlError::Unsupported("ambiguous column reference"));
        }
        found = Some(i);
    }
    found.ok_or(SqlError::UnknownColumn)
}

/// True iff `eval` produced `Bool(true)`. NULL filters as false (SQL
/// three-valued logic collapses to "not selected").
pub fn truthy(v: &Value) -> bool {
    matches!(v, Value::Bool(true))
}

fn invert_bool(v: &Value) -> Value {
    match v {
        Value::Bool(b) => Value::Bool(!b),
        Value::Null => Value::Null,
        _ => Value::Null,
    }
}

fn apply_binary(op: BinaryOp, l: Value, r: Value) -> SqlResult<Value> {
    if matches!(l, Value::Null) || matches!(r, Value::Null) {
        return Ok(match op {
            BinaryOp::And => match (l, r) {
                (Value::Bool(false), _) | (_, Value::Bool(false)) => Value::Bool(false),
                _ => Value::Null,
            },
            BinaryOp::Or => match (l, r) {
                (Value::Bool(true), _) | (_, Value::Bool(true)) => Value::Bool(true),
                _ => Value::Null,
            },
            _ => Value::Null,
        });
    }

    Ok(match op {
        BinaryOp::And => Value::Bool(must_bool(&l)? && must_bool(&r)?),
        BinaryOp::Or => Value::Bool(must_bool(&l)? || must_bool(&r)?),
        BinaryOp::Eq => Value::Bool(cmp(&l, &r)? == std::cmp::Ordering::Equal),
        BinaryOp::Neq => Value::Bool(cmp(&l, &r)? != std::cmp::Ordering::Equal),
        BinaryOp::Lt => Value::Bool(cmp(&l, &r)? == std::cmp::Ordering::Less),
        BinaryOp::Lte => Value::Bool(cmp(&l, &r)? != std::cmp::Ordering::Greater),
        BinaryOp::Gt => Value::Bool(cmp(&l, &r)? == std::cmp::Ordering::Greater),
        BinaryOp::Gte => Value::Bool(cmp(&l, &r)? != std::cmp::Ordering::Less),
    })
}

fn must_bool(v: &Value) -> SqlResult<bool> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(SqlError::SchemaMismatch),
    }
}

fn cmp(l: &Value, r: &Value) -> SqlResult<std::cmp::Ordering> {
    use Value as V;
    Ok(match (l, r) {
        (V::Bool(a), V::Bool(b)) => a.cmp(b),
        (V::Int64(a), V::Int64(b)) => a.cmp(b),
        (V::Int64(a), V::F64(b)) => total_cmp_f64(*a as f64, *b),
        (V::F64(a), V::Int64(b)) => total_cmp_f64(*a, *b as f64),
        (V::F64(a), V::F64(b)) => total_cmp_f64(*a, *b),
        (V::Text(a), V::Text(b)) => a.cmp(b),
        (V::Blob(a), V::Blob(b)) => a.cmp(b),
        _ => return Err(SqlError::SchemaMismatch),
    })
}

fn total_cmp_f64(a: f64, b: f64) -> std::cmp::Ordering {
    a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal)
}
