//! SELECT execution. Drives a (possibly joined) row source through optional
//! WHERE filtering, optional aggregation, then ORDER BY / LIMIT, and finally
//! the user-visible projection.
//!
//! Joins are nested-loop: the driving table is scanned once, each joined
//! table is materialised once, and the executor iterates the cartesian
//! product applying the per-join `ON` predicate to short-circuit
//! mismatched pairs. Aggregation is a hash group-by keyed on the
//! `Vec<HashableValue>` of the GROUP BY slots.

use std::collections::HashMap;

use zerobase::Db;

use super::expr::{eval, truthy};
use crate::codec;
use crate::error::{SqlError, SqlResult};
use crate::plan::{AggExpr, AggregateSpec, Query};
use crate::types::{AggregateFn, ColumnMeta, Row, SqlOutput, SqlType, Value};

pub(super) fn run_select(q: Query, db: &Db) -> SqlResult<SqlOutput> {
    // Materialize each table once. For the driving table we scan rows
    // directly; joined tables are buffered up-front so the inner loops
    // can replay them per outer row.
    let driving_rows = scan_table(&q.from.name, db)?;
    let mut joined_buffers: Vec<Vec<Row>> = Vec::with_capacity(q.joins.len());
    for j in &q.joins {
        joined_buffers.push(scan_table(&j.table.name, db)?);
    }

    // Stage 1: produce the post-WHERE joined rows (one entry per `q.schema`
    // virtual row that survived all join predicates and the WHERE clause).
    let mut joined_rows: Vec<Row> = Vec::new();
    let combined_len = q.schema.columns.len();
    let mut combined: Row = vec![Value::Null; combined_len];

    for left in &driving_rows {
        for (i, v) in left.iter().enumerate() {
            combined[i] = v.clone();
        }
        join_recurse(
            &q,
            &joined_buffers,
            0,
            q.from.columns.len(),
            &mut combined,
            &mut joined_rows,
        )?;
    }

    // Stage 2: build pre-projection rows. Two flavours:
    //  - aggregation: group joined rows by the GROUP BY key and reduce.
    //  - pass-through: project each joined row through `pre_to_schema`.
    let mut pre_rows: Vec<Row> = if let Some(spec) = &q.aggregation {
        run_aggregate(spec, &joined_rows)?
    } else {
        let pre_to_schema = q.pre_to_schema.as_ref().ok_or(SqlError::Encoding)?;
        joined_rows
            .iter()
            .map(|jr| pre_to_schema.iter().map(|s| jr[*s].clone()).collect())
            .collect()
    };

    // HAVING: filter pre-projection rows.
    if let Some(having) = &q.having {
        let pre_schema = pre_project_schema(&q);
        pre_rows.retain(|row| match eval(having, row, &pre_schema) {
            Ok(v) => truthy(&v),
            Err(_) => false,
        });
    }

    // ORDER BY: sort by each (slot, asc) key in declaration order.
    if !q.order_by.is_empty() {
        let keys = q.order_by.clone();
        pre_rows.sort_by(|a, b| {
            for (slot, asc) in &keys {
                let ord = compare_values(&a[*slot], &b[*slot]);
                if ord != std::cmp::Ordering::Equal {
                    return if *asc { ord } else { ord.reverse() };
                }
            }
            std::cmp::Ordering::Equal
        });
    }

    if let Some(limit) = q.limit {
        pre_rows.truncate(limit as usize);
    }

    let rows: Vec<Row> = pre_rows
        .into_iter()
        .map(|pre| q.projection.iter().map(|p| pre[p.source].clone()).collect())
        .collect();

    let columns: Vec<ColumnMeta> = q
        .projection
        .iter()
        .map(|p| ColumnMeta {
            name: p.display_name.clone(),
            ty: q.pre_project_columns[p.source].ty,
            not_null: q.pre_project_columns[p.source].not_null,
        })
        .collect();

    Ok(SqlOutput::Rows { columns, rows })
}

/// Build a virtual schema mirroring the pre-projection layout, so HAVING
/// can resolve column references against pre-project slots.
fn pre_project_schema(q: &Query) -> crate::plan::VirtualSchema {
    use crate::plan::{VirtualColumn, VirtualSchema};
    VirtualSchema {
        columns: q
            .pre_project_columns
            .iter()
            .map(|m| VirtualColumn { qualifier: String::new(), meta: m.clone() })
            .collect(),
    }
}

/// Hash group-by reducer. Returns one pre-projection row per group, with
/// layout `[group_keys..., aggregate_outputs...]` matching the planner's
/// `pre_project_columns`.
fn run_aggregate(spec: &AggregateSpec, joined_rows: &[Row]) -> SqlResult<Vec<Row>> {
    // Hash key uses bincode for cross-Value hashability.
    type Key = Vec<u8>;
    fn key_of(row: &Row, slots: &[usize]) -> SqlResult<Key> {
        let key_vals: Vec<&Value> = slots.iter().map(|s| &row[*s]).collect();
        bincode::serialize(&key_vals).map_err(|_| SqlError::Encoding)
    }

    struct GroupState {
        key_values: Row,
        accs: Vec<AggAcc>,
    }

    let mut groups: HashMap<Key, GroupState> = HashMap::new();
    let mut order: Vec<Key> = Vec::new();

    for row in joined_rows {
        let k = key_of(row, &spec.group_by)?;
        let entry = groups.entry(k.clone()).or_insert_with(|| {
            order.push(k.clone());
            GroupState {
                key_values: spec.group_by.iter().map(|s| row[*s].clone()).collect(),
                accs: spec.aggregates.iter().map(AggAcc::new).collect(),
            }
        });
        for (acc, agg) in entry.accs.iter_mut().zip(spec.aggregates.iter()) {
            let input = match agg.input {
                Some(s) => &row[s],
                None => &Value::Null, // COUNT(*)
            };
            acc.update(agg, input)?;
        }
    }

    // Empty input + GROUP BY = no rows. Empty input + no GROUP BY but
    // aggregates present should yield a single row with seeded values
    // (e.g. COUNT(*) over empty table = 0). Detect that here.
    if joined_rows.is_empty() && spec.group_by.is_empty() {
        let mut accs: Vec<AggAcc> = spec.aggregates.iter().map(AggAcc::new).collect();
        let mut row = Vec::with_capacity(accs.len());
        for (acc, agg) in accs.iter_mut().zip(spec.aggregates.iter()) {
            row.push(acc.finish(agg));
        }
        return Ok(vec![row]);
    }

    let mut out = Vec::with_capacity(order.len());
    for k in &order {
        let mut state = groups.remove(k).expect("group present");
        let mut row = state.key_values;
        for (acc, agg) in state.accs.iter_mut().zip(spec.aggregates.iter()) {
            row.push(acc.finish(agg));
        }
        out.push(row);
    }
    Ok(out)
}

#[derive(Debug)]
enum AggAcc {
    CountStar { n: i64 },
    Count { n: i64 },
    SumI { sum: i128, any: bool },
    SumF { sum: f64, any: bool },
    AvgI { sum: i128, n: i64 },
    AvgF { sum: f64, n: i64 },
    MinMax { current: Option<Value> },
}

impl AggAcc {
    fn new(agg: &AggExpr) -> Self {
        match agg.func {
            AggregateFn::CountStar => AggAcc::CountStar { n: 0 },
            AggregateFn::Count => AggAcc::Count { n: 0 },
            AggregateFn::Sum => match agg.output_type {
                SqlType::Double => AggAcc::SumF { sum: 0.0, any: false },
                _ => AggAcc::SumI { sum: 0, any: false },
            },
            AggregateFn::Avg => match agg.output_type {
                SqlType::Double => AggAcc::AvgF { sum: 0.0, n: 0 },
                _ => AggAcc::AvgI { sum: 0, n: 0 },
            },
            AggregateFn::Min | AggregateFn::Max => AggAcc::MinMax { current: None },
        }
    }

    fn update(&mut self, agg: &AggExpr, v: &Value) -> SqlResult<()> {
        match (self, agg.func) {
            (AggAcc::CountStar { n }, _) => *n += 1,
            (AggAcc::Count { n }, _) => {
                if !matches!(v, Value::Null) {
                    *n += 1;
                }
            }
            (AggAcc::SumI { sum, any }, _) => match v {
                Value::Null => {}
                Value::Int64(i) => {
                    *sum += *i as i128;
                    *any = true;
                }
                _ => return Err(SqlError::SchemaMismatch),
            },
            (AggAcc::SumF { sum, any }, _) => match v {
                Value::Null => {}
                Value::Int64(i) => {
                    *sum += *i as f64;
                    *any = true;
                }
                Value::F64(f) => {
                    *sum += *f;
                    *any = true;
                }
                _ => return Err(SqlError::SchemaMismatch),
            },
            (AggAcc::AvgI { sum, n }, _) => match v {
                Value::Null => {}
                Value::Int64(i) => {
                    *sum += *i as i128;
                    *n += 1;
                }
                _ => return Err(SqlError::SchemaMismatch),
            },
            (AggAcc::AvgF { sum, n }, _) => match v {
                Value::Null => {}
                Value::Int64(i) => {
                    *sum += *i as f64;
                    *n += 1;
                }
                Value::F64(f) => {
                    *sum += *f;
                    *n += 1;
                }
                _ => return Err(SqlError::SchemaMismatch),
            },
            (AggAcc::MinMax { current }, func) => {
                if matches!(v, Value::Null) {
                    return Ok(());
                }
                match current {
                    None => *current = Some(v.clone()),
                    Some(cur) => {
                        let ord = compare_values(v, cur);
                        let take = match func {
                            AggregateFn::Min => ord == std::cmp::Ordering::Less,
                            AggregateFn::Max => ord == std::cmp::Ordering::Greater,
                            _ => false,
                        };
                        if take {
                            *current = Some(v.clone());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self, agg: &AggExpr) -> Value {
        let _ = agg;
        match self {
            AggAcc::CountStar { n } | AggAcc::Count { n } => Value::Int64(*n),
            AggAcc::SumI { sum, any } => {
                if *any {
                    Value::Int64(*sum as i64)
                } else {
                    Value::Null
                }
            }
            AggAcc::SumF { sum, any } => {
                if *any {
                    Value::F64(*sum)
                } else {
                    Value::Null
                }
            }
            AggAcc::AvgI { sum, n } => {
                if *n == 0 {
                    Value::Null
                } else {
                    Value::F64(*sum as f64 / *n as f64)
                }
            }
            AggAcc::AvgF { sum, n } => {
                if *n == 0 {
                    Value::Null
                } else {
                    Value::F64(*sum / *n as f64)
                }
            }
            AggAcc::MinMax { current } => current.clone().unwrap_or(Value::Null),
        }
    }
}

fn compare_values(a: &Value, b: &Value) -> std::cmp::Ordering {
    use Value as V;
    match (a, b) {
        (V::Null, V::Null) => std::cmp::Ordering::Equal,
        (V::Null, _) => std::cmp::Ordering::Less,
        (_, V::Null) => std::cmp::Ordering::Greater,
        (V::Bool(x), V::Bool(y)) => x.cmp(y),
        (V::Int64(x), V::Int64(y)) => x.cmp(y),
        (V::Int64(x), V::F64(y)) => total_cmp_f64(*x as f64, *y),
        (V::F64(x), V::Int64(y)) => total_cmp_f64(*x, *y as f64),
        (V::F64(x), V::F64(y)) => total_cmp_f64(*x, *y),
        (V::Text(x), V::Text(y)) => x.cmp(y),
        (V::Blob(x), V::Blob(y)) => x.cmp(y),
        _ => std::cmp::Ordering::Equal,
    }
}

fn total_cmp_f64(a: f64, b: f64) -> std::cmp::Ordering {
    a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal)
}

fn join_recurse(
    q: &Query,
    buffers: &[Vec<Row>],
    join_idx: usize,
    fill_offset: usize,
    combined: &mut Row,
    out: &mut Vec<Row>,
) -> SqlResult<()> {
    if join_idx == q.joins.len() {
        if let Some(filter) = &q.filter {
            let v = eval(filter, combined, &q.schema)?;
            if !truthy(&v) {
                return Ok(());
            }
        }
        out.push(combined.clone());
        return Ok(());
    }

    let join = &q.joins[join_idx];
    let width = join.table.columns.len();
    for right in &buffers[join_idx] {
        for (i, v) in right.iter().enumerate() {
            combined[fill_offset + i] = v.clone();
        }
        let v = eval(&join.on, combined, &q.schema)?;
        if !truthy(&v) {
            continue;
        }
        join_recurse(q, buffers, join_idx + 1, fill_offset + width, combined, out)?;
    }
    Ok(())
}

fn scan_table(name: &str, db: &Db) -> SqlResult<Vec<Row>> {
    let prefix = codec::row_prefix(name);
    let mut rows = Vec::new();
    for item in db.scan(&prefix) {
        let row: Row = bincode::deserialize(&item.value)?;
        rows.push(row);
    }
    Ok(rows)
}
