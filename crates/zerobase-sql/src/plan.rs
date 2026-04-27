//! Rule-based planner. Maps a parsed `Statement` to a small `Plan` enum
//! that the executor walks.
//!
//! The week-3 planner is still rule-based, no cost model: `WHERE pk = X`
//! gets a point lookup, `WHERE indexed = X` gets an index seek, otherwise
//! a full scan; JOINs are nested-loop with an index probe on the right
//! side when available; aggregation is a hash-group followed by an
//! optional in-memory sort and limit.

use crate::catalog::{Catalog, IndexMeta, TableMeta};
use crate::error::{SqlError, SqlResult};
use crate::parse::{
    BinaryOp, ColRef, Expr, JoinClause, ProjectionItem, SelectStmt, Statement,
};
use crate::types::{AggregateFn, ColumnMeta, SqlType, Value};

/// A logical (and physical, since we have no rewriter) plan.
#[derive(Debug)]
pub enum Plan {
    /// Create a new table.
    CreateTable(TableMeta),
    /// Create a secondary index.
    CreateIndex {
        /// Target table (cloned out of the catalog).
        table: TableMeta,
        /// New index metadata to register.
        index: IndexMeta,
    },
    /// Insert one or more pre-validated rows.
    Insert {
        /// Target table.
        table: TableMeta,
        /// Rows in storage column order, with `Value`s already materialised.
        rows: Vec<Vec<Value>>,
    },
    /// SELECT pipeline.
    Query(Query),
    /// UPDATE pipeline.
    Update {
        /// Target table.
        table: TableMeta,
        /// Filter to identify rows. `None` means "every row".
        filter: Option<Expr>,
        /// `(column_index, expression)` updates evaluated against the old row.
        assignments: Vec<(usize, Expr)>,
    },
    /// DELETE pipeline.
    Delete {
        /// Target table.
        table: TableMeta,
        /// Filter; `None` means "every row".
        filter: Option<Expr>,
    },
}

/// Pull-style SELECT plan: scan(+joins) → filter → aggregate → sort → limit
/// → project. The executor walks these phases in that order.
#[derive(Debug)]
pub struct Query {
    /// Driving table (FROM).
    pub from: TableMeta,
    /// Alias used to qualify the driving table's columns; defaults to the
    /// table name if no `AS` was given.
    pub from_qualifier: String,
    /// Inner-join clauses. Each clause refers to the previous tables.
    pub joins: Vec<JoinedTable>,
    /// Combined schema of every visible column, in concat order. Used by
    /// the executor to resolve `Expr::Col` into a slot.
    pub schema: VirtualSchema,
    /// Optional WHERE expression.
    pub filter: Option<Expr>,
    /// Aggregation specification, if the query has GROUP BY or aggregate
    /// functions. `None` means "row-passthrough projection".
    pub aggregation: Option<AggregateSpec>,
    /// HAVING expression — evaluated against grouped rows.
    pub having: Option<Expr>,
    /// ORDER BY: list of `(slot_index_in_pre_project_row, asc)` references
    /// that match indices in `pre_project_columns`.
    pub order_by: Vec<(usize, bool)>,
    /// Optional LIMIT.
    pub limit: Option<u64>,
    /// Layout produced by the aggregation/scan layer, before final projection.
    pub pre_project_columns: Vec<ColumnMeta>,
    /// For pass-through (no aggregation) plans: for each pre-projection
    /// column, the slot in `schema` that feeds it. `None` once aggregation
    /// is present (the executor materialises pre-projection rows from
    /// group-by + aggregator outputs directly).
    pub pre_to_schema: Option<Vec<usize>>,
    /// Final projection: which `pre_project_columns` slot each output column
    /// pulls from, plus its display metadata.
    pub projection: Vec<ProjSlot>,
}

/// Right side of a JOIN clause, post-resolution.
#[derive(Debug)]
pub struct JoinedTable {
    /// The right-side table.
    pub table: TableMeta,
    /// Qualifier used to address its columns.
    pub qualifier: String,
    /// `ON` predicate, with column refs resolved to virtual slots.
    pub on: Expr,
    /// If the join can use an index lookup on the right side, this names
    /// the column. The executor uses this for IndexProbe; otherwise it
    /// falls back to a nested-loop full scan.
    pub probe_index_column: Option<String>,
    /// Index of `probe_index_column` inside the right table, when set.
    pub probe_index_col_idx: Option<usize>,
}

/// Aggregation pipeline.
#[derive(Debug)]
pub struct AggregateSpec {
    /// Slots (into the joined-input row) that form the GROUP BY key.
    pub group_by: Vec<usize>,
    /// One aggregator per output aggregate column.
    pub aggregates: Vec<AggExpr>,
}

/// One concrete aggregator inside an `AggregateSpec`.
#[derive(Debug)]
pub struct AggExpr {
    /// Aggregate function.
    pub func: AggregateFn,
    /// Input slot in the joined row, or `None` for `COUNT(*)`.
    pub input: Option<usize>,
    /// Output type of the aggregator.
    pub output_type: SqlType,
}

/// One output column slot in the final projection.
#[derive(Debug)]
pub struct ProjSlot {
    /// Index into `pre_project_columns` to materialize for this column.
    pub source: usize,
    /// Display name for this output column.
    pub display_name: String,
}

/// Virtual layout of "the row the executor sees after joins": a flat list
/// of qualified columns. The planner uses it to resolve every `ColRef` and
/// embeds those slot indices into the operator tree.
#[derive(Debug, Clone)]
pub struct VirtualSchema {
    /// Concatenated columns: `[from_cols..., join0_cols..., join1_cols..., ...]`.
    pub columns: Vec<VirtualColumn>,
}

/// One column inside a `VirtualSchema`.
#[derive(Debug, Clone)]
pub struct VirtualColumn {
    /// Qualifier (table name or alias).
    pub qualifier: String,
    /// Column metadata copied from the source table.
    pub meta: ColumnMeta,
}

impl VirtualSchema {
    fn resolve(&self, c: &ColRef) -> SqlResult<usize> {
        let mut found: Option<usize> = None;
        for (i, vc) in self.columns.iter().enumerate() {
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
}

/// Plan a parsed statement against the current catalog.
pub fn plan(stmt: Statement, catalog: &Catalog) -> SqlResult<Plan> {
    match stmt {
        Statement::CreateTable(meta) => Ok(Plan::CreateTable(meta)),
        Statement::CreateIndex { name, table, column } => {
            plan_create_index(&name, &table, &column, catalog)
        }
        Statement::Insert { table, columns, rows } => plan_insert(&table, &columns, rows, catalog),
        Statement::Select(s) => Ok(Plan::Query(plan_select(s, catalog)?)),
        Statement::Update { table, assignments, filter } => {
            plan_update(&table, assignments, filter, catalog)
        }
        Statement::Delete { table, filter } => plan_delete(&table, filter, catalog),
    }
}

fn plan_create_index(
    name: &str,
    table: &str,
    column: &str,
    catalog: &Catalog,
) -> SqlResult<Plan> {
    let meta = catalog.get(table)?.clone();
    if meta.indexes.iter().any(|i| i.name == name) {
        return Err(SqlError::SchemaMismatch);
    }
    let col_idx = meta.column_index(column)?;
    Ok(Plan::CreateIndex {
        table: meta,
        index: IndexMeta {
            name: name.to_string(),
            columns: vec![col_idx],
        },
    })
}

fn plan_insert(
    table_name: &str,
    columns: &[String],
    rows: Vec<Vec<Expr>>,
    catalog: &Catalog,
) -> SqlResult<Plan> {
    let meta = catalog.get(table_name)?.clone();

    let perm: Vec<usize> = if columns.is_empty() {
        (0..meta.columns.len()).collect()
    } else {
        columns.iter().map(|name| meta.column_index(name)).collect::<SqlResult<_>>()?
    };

    let mut materialised = Vec::with_capacity(rows.len());
    for row in rows {
        if row.len() != perm.len() {
            return Err(SqlError::SchemaMismatch);
        }
        let mut storage_row = vec![Value::Null; meta.columns.len()];
        for (slot_idx, src_expr) in perm.iter().zip(row) {
            storage_row[*slot_idx] = const_eval(src_expr)?;
        }
        materialised.push(storage_row);
    }
    Ok(Plan::Insert { table: meta, rows: materialised })
}

fn plan_update(
    table: &str,
    assignments: Vec<(String, Expr)>,
    filter: Option<Expr>,
    catalog: &Catalog,
) -> SqlResult<Plan> {
    let meta = catalog.get(table)?.clone();

    let mut resolved = Vec::with_capacity(assignments.len());
    let single_schema = single_table_schema(&meta, table);
    for (col, e) in assignments {
        if meta.primary_key.contains(&meta.column_index(&col)?) {
            return Err(SqlError::Unsupported("UPDATE on PK column"));
        }
        let idx = meta.column_index(&col)?;
        let resolved_expr = resolve_expr(e, &single_schema)?;
        resolved.push((idx, resolved_expr));
    }
    let filter = filter.map(|e| resolve_expr(e, &single_schema)).transpose()?;
    Ok(Plan::Update { table: meta, filter, assignments: resolved })
}

fn plan_delete(
    table: &str,
    filter: Option<Expr>,
    catalog: &Catalog,
) -> SqlResult<Plan> {
    let meta = catalog.get(table)?.clone();
    let single_schema = single_table_schema(&meta, table);
    let filter = filter.map(|e| resolve_expr(e, &single_schema)).transpose()?;
    Ok(Plan::Delete { table: meta, filter })
}

fn single_table_schema(meta: &TableMeta, qualifier: &str) -> VirtualSchema {
    VirtualSchema {
        columns: meta
            .columns
            .iter()
            .map(|c| VirtualColumn { qualifier: qualifier.to_string(), meta: c.clone() })
            .collect(),
    }
}

fn plan_select(s: SelectStmt, catalog: &Catalog) -> SqlResult<Query> {
    let from_meta = catalog.get(&s.from)?.clone();
    let from_qualifier = s.from_alias.clone().unwrap_or_else(|| s.from.clone());
    let mut schema = single_table_schema(&from_meta, &from_qualifier);

    let mut joined: Vec<JoinedTable> = Vec::with_capacity(s.joins.len());
    for jc in s.joins {
        joined.push(plan_join(jc, &mut schema, catalog)?);
    }

    let SelectStmt {
        projection: select_projection,
        filter: select_filter,
        group_by: select_group_by,
        having: select_having,
        order_by: select_order_by,
        limit: select_limit,
        ..
    } = s;

    let filter = select_filter.map(|e| resolve_expr(e, &schema)).transpose()?;

    // Translate group-by and projection into slot-resolved forms.
    let group_by_slots: Vec<usize> =
        select_group_by.iter().map(|c| schema.resolve(c)).collect::<SqlResult<_>>()?;

    let mut has_aggregate = false;
    for item in &select_projection {
        if matches!(item, ProjectionItem::Agg { .. }) {
            has_aggregate = true;
        }
    }

    // Build pre-projection layout. With aggregation, it's `[group_by_cols..., agg_outputs...]`.
    // Without aggregation, it's the projected slice of the joined-row schema.
    let (aggregation, pre_project_columns, projection_to_slot, pre_to_schema) =
        if has_aggregate || !group_by_slots.is_empty() {
            let (a, c, p) = plan_aggregation(&schema, &group_by_slots, &select_projection)?;
            (a, c, p, None)
        } else {
            let (a, c, p, m) = plan_passthrough(&schema, &select_projection)?;
            (a, c, p, Some(m))
        };

    let pre_schema = layout_to_schema(
        &pre_project_columns,
        &schema,
        &select_projection,
        &group_by_slots,
        &aggregation,
    );

    let having = select_having.map(|h| resolve_expr(h, &pre_schema)).transpose()?;

    // ORDER BY: each expr must be a column reference resolved against the
    // pre-projection layout (so users can sort by aggregate aliases).
    let mut order_by: Vec<(usize, bool)> = Vec::with_capacity(select_order_by.len());
    for (e, asc) in select_order_by {
        let cref = match e {
            Expr::Col(c) => c,
            _ => return Err(SqlError::Unsupported("ORDER BY non-column")),
        };
        order_by.push((pre_schema.resolve(&cref)?, asc));
    }

    Ok(Query {
        from: from_meta,
        from_qualifier,
        joins: joined,
        schema,
        filter,
        aggregation,
        having,
        order_by,
        limit: select_limit,
        pre_project_columns,
        pre_to_schema,
        projection: projection_to_slot,
    })
}

fn plan_join(
    jc: JoinClause,
    schema: &mut VirtualSchema,
    catalog: &Catalog,
) -> SqlResult<JoinedTable> {
    let meta = catalog.get(&jc.table)?.clone();
    let qualifier = jc.alias.clone().unwrap_or_else(|| jc.table.clone());

    // Extend schema with the right-side columns BEFORE resolving the ON
    // predicate so it can refer to either side.
    for c in &meta.columns {
        schema.columns.push(VirtualColumn { qualifier: qualifier.clone(), meta: c.clone() });
    }
    let on = resolve_expr(jc.on, schema)?;

    // Detect if the ON predicate is `<right>.col = <left expr>` and the
    // right column has an index — that lets the executor probe.
    let (probe_index_column, probe_index_col_idx) =
        detect_probe(&on, &qualifier, &meta);

    Ok(JoinedTable { table: meta, qualifier, on, probe_index_column, probe_index_col_idx })
}

fn detect_probe(_on: &Expr, _qualifier: &str, _meta: &TableMeta) -> (Option<String>, Option<usize>) {
    // Week-3 keeps it conservative: nested-loop everywhere. A future pass
    // can match against equality on an indexed right-side column.
    (None, None)
}

/// Build a schema that mirrors the pre-projection row layout. Used to
/// resolve HAVING / ORDER BY references against either group-by columns
/// or aggregate aliases.
fn layout_to_schema(
    layout: &[ColumnMeta],
    base: &VirtualSchema,
    projection: &[ProjectionItem],
    group_by_slots: &[usize],
    agg: &Option<AggregateSpec>,
) -> VirtualSchema {
    if agg.is_none() {
        // Pass-through: layout columns mirror projection items in order.
        // We keep the underlying base qualifier so unqualified refs
        // continue to work; the projection alias is also exposed.
        let mut columns = Vec::with_capacity(layout.len());
        for (i, item) in projection.iter().enumerate() {
            let (qualifier, meta) = match item {
                ProjectionItem::Col { col, .. } => {
                    if let Ok(slot) = base.resolve(col) {
                        (base.columns[slot].qualifier.clone(), layout[i].clone())
                    } else {
                        (String::new(), layout[i].clone())
                    }
                }
                _ => (String::new(), layout[i].clone()),
            };
            columns.push(VirtualColumn { qualifier, meta });
        }
        return VirtualSchema { columns };
    }
    let mut columns = Vec::with_capacity(layout.len());
    for (i, slot) in group_by_slots.iter().enumerate() {
        columns.push(VirtualColumn {
            qualifier: base.columns[*slot].qualifier.clone(),
            meta: layout[i].clone(),
        });
    }
    for meta in layout.iter().skip(group_by_slots.len()) {
        columns.push(VirtualColumn { qualifier: String::new(), meta: meta.clone() });
    }
    VirtualSchema { columns }
}

fn plan_passthrough(
    schema: &VirtualSchema,
    items: &[ProjectionItem],
) -> SqlResult<(Option<AggregateSpec>, Vec<ColumnMeta>, Vec<ProjSlot>, Vec<usize>)> {
    let mut layout: Vec<ColumnMeta> = Vec::new();
    let mut projection: Vec<ProjSlot> = Vec::new();
    let mut pre_to_schema: Vec<usize> = Vec::new();

    for item in items {
        match item {
            ProjectionItem::Star => {
                for (i, vc) in schema.columns.iter().enumerate() {
                    layout.push(vc.meta.clone());
                    pre_to_schema.push(i);
                    projection.push(ProjSlot {
                        source: layout.len() - 1,
                        display_name: vc.meta.name.clone(),
                    });
                }
            }
            ProjectionItem::QualifiedStar(q) => {
                for (i, vc) in schema.columns.iter().enumerate() {
                    if &vc.qualifier == q {
                        layout.push(vc.meta.clone());
                        pre_to_schema.push(i);
                        projection.push(ProjSlot {
                            source: layout.len() - 1,
                            display_name: vc.meta.name.clone(),
                        });
                    }
                }
            }
            ProjectionItem::Col { col, alias } => {
                let slot = schema.resolve(col)?;
                layout.push(schema.columns[slot].meta.clone());
                pre_to_schema.push(slot);
                projection.push(ProjSlot {
                    source: layout.len() - 1,
                    display_name: alias.clone().unwrap_or_else(|| col.column.clone()),
                });
            }
            ProjectionItem::Agg { .. } => unreachable!("aggregate in passthrough plan"),
        }
    }
    Ok((None, layout, projection, pre_to_schema))
}

fn plan_aggregation(
    schema: &VirtualSchema,
    group_by_slots: &[usize],
    items: &[ProjectionItem],
) -> SqlResult<(Option<AggregateSpec>, Vec<ColumnMeta>, Vec<ProjSlot>)> {
    // Pre-project layout: [GROUP BY columns..., aggregate outputs...].
    let mut layout: Vec<ColumnMeta> = Vec::new();
    for slot in group_by_slots {
        layout.push(schema.columns[*slot].meta.clone());
    }

    let mut aggregates: Vec<AggExpr> = Vec::new();
    let mut projection: Vec<ProjSlot> = Vec::new();

    for item in items {
        match item {
            ProjectionItem::Star | ProjectionItem::QualifiedStar(_) => {
                return Err(SqlError::Unsupported("wildcard with GROUP BY/aggregate"));
            }
            ProjectionItem::Col { col, alias } => {
                let slot = schema.resolve(col)?;
                let g = group_by_slots
                    .iter()
                    .position(|s| *s == slot)
                    .ok_or(SqlError::Unsupported("non-aggregated column in GROUP BY query"))?;
                projection.push(ProjSlot {
                    source: g,
                    display_name: alias.clone().unwrap_or_else(|| col.column.clone()),
                });
            }
            ProjectionItem::Agg { func, arg, alias } => {
                let (input_slot, output_type, default_name) =
                    plan_agg_call(*func, arg.as_ref(), schema)?;
                aggregates.push(AggExpr {
                    func: *func,
                    input: input_slot,
                    output_type,
                });
                let pos = group_by_slots.len() + aggregates.len() - 1;
                layout.push(ColumnMeta {
                    name: alias.clone().unwrap_or(default_name),
                    ty: output_type,
                    not_null: false,
                });
                projection.push(ProjSlot {
                    source: pos,
                    display_name: layout[pos].name.clone(),
                });
            }
        }
    }

    Ok((Some(AggregateSpec { group_by: group_by_slots.to_vec(), aggregates }), layout, projection))
}

fn plan_agg_call(
    func: AggregateFn,
    arg: Option<&ColRef>,
    schema: &VirtualSchema,
) -> SqlResult<(Option<usize>, SqlType, String)> {
    match func {
        AggregateFn::CountStar => Ok((None, SqlType::BigInt, "count".to_string())),
        AggregateFn::Count => {
            let c = arg.ok_or(SqlError::SchemaMismatch)?;
            let slot = schema.resolve(c)?;
            Ok((Some(slot), SqlType::BigInt, format!("count_{}", c.column)))
        }
        AggregateFn::Sum => {
            let c = arg.ok_or(SqlError::SchemaMismatch)?;
            let slot = schema.resolve(c)?;
            let ty = match schema.columns[slot].meta.ty {
                SqlType::Int | SqlType::BigInt => SqlType::BigInt,
                SqlType::Double => SqlType::Double,
                _ => return Err(SqlError::SchemaMismatch),
            };
            Ok((Some(slot), ty, format!("sum_{}", c.column)))
        }
        AggregateFn::Avg => {
            let c = arg.ok_or(SqlError::SchemaMismatch)?;
            let slot = schema.resolve(c)?;
            match schema.columns[slot].meta.ty {
                SqlType::Int | SqlType::BigInt | SqlType::Double => {}
                _ => return Err(SqlError::SchemaMismatch),
            }
            Ok((Some(slot), SqlType::Double, format!("avg_{}", c.column)))
        }
        AggregateFn::Min | AggregateFn::Max => {
            let c = arg.ok_or(SqlError::SchemaMismatch)?;
            let slot = schema.resolve(c)?;
            let ty = schema.columns[slot].meta.ty;
            let prefix = if matches!(func, AggregateFn::Min) { "min" } else { "max" };
            Ok((Some(slot), ty, format!("{prefix}_{}", c.column)))
        }
    }
}

fn resolve_expr(e: Expr, schema: &VirtualSchema) -> SqlResult<Expr> {
    match e {
        Expr::Lit(_) => Ok(e),
        Expr::Col(c) => {
            let _ = schema.resolve(&c)?; // validate at plan time
            Ok(Expr::Col(c))
        }
        Expr::Not(inner) => Ok(Expr::Not(Box::new(resolve_expr(*inner, schema)?))),
        Expr::IsNull { operand, negated } => Ok(Expr::IsNull {
            operand: Box::new(resolve_expr(*operand, schema)?),
            negated,
        }),
        Expr::Binary { op, lhs, rhs } => Ok(Expr::Binary {
            op,
            lhs: Box::new(resolve_expr(*lhs, schema)?),
            rhs: Box::new(resolve_expr(*rhs, schema)?),
        }),
    }
}

/// Evaluate an expression that must be a constant (no column refs). Used
/// when materialising INSERT VALUES.
pub fn const_eval(e: Expr) -> SqlResult<Value> {
    match e {
        Expr::Lit(v) => Ok(v),
        _ => Err(SqlError::Unsupported("non-constant expression in VALUES")),
    }
}

/// Helper consumed by the executor: simple equality predicate detection.
/// Returns `Some((column_slot, literal))` if `expr` is `col = literal` or
/// `literal = col`, where `col` resolves into `schema`. Used to decide
/// between full-scan and index-seek for SELECT/UPDATE/DELETE.
pub fn equality_on_slot(expr: &Expr, schema: &VirtualSchema) -> Option<(usize, Value)> {
    let Expr::Binary { op: BinaryOp::Eq, lhs, rhs } = expr else {
        return None;
    };
    match (lhs.as_ref(), rhs.as_ref()) {
        (Expr::Col(c), Expr::Lit(v)) | (Expr::Lit(v), Expr::Col(c)) => {
            let slot = schema.resolve(c).ok()?;
            Some((slot, v.clone()))
        }
        _ => None,
    }
}
