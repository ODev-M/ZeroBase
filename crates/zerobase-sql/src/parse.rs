//! Thin wrapper over `sqlparser`. The parser walks the AST with an
//! explicit allow-list — every variant we accept is matched by name; the
//! `_` arm returns `SqlError::Unsupported`, so adding new SQL features is
//! always a deliberate decision.
//!
//! Week 3 surface: `CREATE TABLE`, `CREATE INDEX`, `INSERT`, `SELECT
//! [JOIN]* [WHERE] [GROUP BY] [HAVING] [ORDER BY] [LIMIT]`, `UPDATE`,
//! `DELETE`. Aggregates: COUNT/COUNT(*)/SUM/AVG/MIN/MAX.

use sqlparser::ast::{
    self as ast, BinaryOperator as AstBin, ColumnDef, ColumnOption, DataType, Expr as AstExpr,
    FromTable, FunctionArg, FunctionArgExpr, FunctionArguments, Ident, JoinConstraint,
    JoinOperator, ObjectName, Query, Select, SelectItem, SetExpr, Statement as Stmt, TableFactor,
    TableObject, TableWithJoins, UnaryOperator as AstUn, Value as AstValue,
};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

use crate::catalog::{validate_table_name, IndexMeta, TableMeta};
use crate::error::{SqlError, SqlResult};
use crate::types::{AggregateFn, ColumnMeta, SqlType, Value};

/// A parsed, validated SQL statement ready to plan.
#[derive(Debug, Clone)]
pub enum Statement {
    /// `CREATE TABLE ...`.
    CreateTable(TableMeta),
    /// `CREATE INDEX <name> ON <table>(<col>)`.
    CreateIndex {
        /// Index name. Must be unique on the table.
        name: String,
        /// Target table.
        table: String,
        /// Single column the index keys on (multi-column indexes are
        /// reserved for a later milestone).
        column: String,
    },
    /// `INSERT INTO t (cols...) VALUES (...), (...)`.
    Insert {
        /// Target table name.
        table: String,
        /// Column names in the order the user wrote them.
        columns: Vec<String>,
        /// One row per `VALUES (...)`.
        rows: Vec<Vec<Expr>>,
    },
    /// `SELECT ...`.
    Select(SelectStmt),
    /// `UPDATE t SET col = expr [, ...] [WHERE expr]`.
    Update {
        /// Target table.
        table: String,
        /// Column-name → value-expression assignments.
        assignments: Vec<(String, Expr)>,
        /// Optional WHERE filter.
        filter: Option<Expr>,
    },
    /// `DELETE FROM t [WHERE expr]`.
    Delete {
        /// Target table.
        table: String,
        /// Optional WHERE filter.
        filter: Option<Expr>,
    },
}

/// Parsed SELECT body — the planner turns this into a `Query` plan.
#[derive(Debug, Clone)]
pub struct SelectStmt {
    /// Driving table (FROM).
    pub from: String,
    /// Optional alias for the driving table (for `t.col` resolution).
    pub from_alias: Option<String>,
    /// Zero or more INNER JOINs against the driving table.
    pub joins: Vec<JoinClause>,
    /// Projection list.
    pub projection: Vec<ProjectionItem>,
    /// Optional WHERE expression.
    pub filter: Option<Expr>,
    /// GROUP BY column references (qualified or bare names).
    pub group_by: Vec<ColRef>,
    /// HAVING expression — evaluated against grouped rows.
    pub having: Option<Expr>,
    /// ORDER BY: list of `(expr, asc)`.
    pub order_by: Vec<(Expr, bool)>,
    /// LIMIT (post-ORDER BY truncation).
    pub limit: Option<u64>,
}

/// One INNER JOIN clause.
#[derive(Debug, Clone)]
pub struct JoinClause {
    /// Right-hand table name.
    pub table: String,
    /// Optional alias.
    pub alias: Option<String>,
    /// `ON` predicate.
    pub on: Expr,
}

/// A SELECT projection item.
#[derive(Debug, Clone)]
pub enum ProjectionItem {
    /// `*` — expand to every column of every visible table in declaration order.
    Star,
    /// `t.*` — expand to every column of the named table/alias.
    QualifiedStar(String),
    /// A scalar column reference, possibly aliased.
    Col {
        /// Column reference.
        col: ColRef,
        /// Optional `AS alias` name.
        alias: Option<String>,
    },
    /// An aggregate function call, possibly aliased.
    Agg {
        /// Aggregate kind.
        func: AggregateFn,
        /// Argument; `None` means `COUNT(*)`.
        arg: Option<ColRef>,
        /// Optional `AS alias` name.
        alias: Option<String>,
    },
}

/// A reference to a column, optionally qualified by table name or alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColRef {
    /// Table or alias prefix (e.g. `u` in `u.id`). `None` for unqualified.
    pub table: Option<String>,
    /// Column name.
    pub column: String,
}

/// Expression sub-AST kept intentionally small. The planner walks this and
/// the executor evaluates it against runtime rows.
#[derive(Debug, Clone)]
pub enum Expr {
    /// Literal value.
    Lit(Value),
    /// Column reference (resolved against the source table at plan time).
    Col(ColRef),
    /// Binary operation (comparison or boolean).
    Binary {
        /// Operator kind.
        op: BinaryOp,
        /// Left operand.
        lhs: Box<Expr>,
        /// Right operand.
        rhs: Box<Expr>,
    },
    /// `NOT` of a sub-expression.
    Not(Box<Expr>),
    /// `IS NULL` / `IS NOT NULL`.
    IsNull {
        /// Operand.
        operand: Box<Expr>,
        /// `true` for `IS NOT NULL`.
        negated: bool,
    },
}

/// Binary operators we evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    /// `=`.
    Eq,
    /// `<>` / `!=`.
    Neq,
    /// `<`.
    Lt,
    /// `<=`.
    Lte,
    /// `>`.
    Gt,
    /// `>=`.
    Gte,
    /// `AND`.
    And,
    /// `OR`.
    Or,
}

/// Parse a SQL statement string. Multi-statement input is rejected.
pub fn parse(sql: &str) -> SqlResult<Statement> {
    let dialect = GenericDialect {};
    let mut stmts = Parser::parse_sql(&dialect, sql).map_err(|_| SqlError::Parse)?;
    if stmts.len() != 1 {
        return Err(SqlError::Unsupported("multiple statements"));
    }
    statement(stmts.remove(0))
}

fn statement(stmt: Stmt) -> SqlResult<Statement> {
    match stmt {
        Stmt::CreateTable(create) => create_table(&create),
        Stmt::CreateIndex(idx) => create_index(&idx),
        Stmt::Insert(insert) => insert_stmt(insert),
        Stmt::Query(q) => Ok(Statement::Select(select_query(*q)?)),
        Stmt::Update { table, assignments, from, selection, returning, or } => {
            update_stmt(table, assignments, from, selection, returning, or)
        }
        Stmt::Delete(d) => delete_stmt(d),
        _ => Err(SqlError::Unsupported("statement kind")),
    }
}

fn create_table(create: &ast::CreateTable) -> SqlResult<Statement> {
    let name = single_name(&create.name)?;
    validate_table_name(&name)?;
    if !create.constraints.is_empty() {
        return Err(SqlError::Unsupported("table-level constraints"));
    }
    if create.if_not_exists {
        return Err(SqlError::Unsupported("IF NOT EXISTS"));
    }
    if create.or_replace || create.temporary || create.external {
        return Err(SqlError::Unsupported("CREATE TABLE modifier"));
    }

    let mut columns = Vec::with_capacity(create.columns.len());
    let mut primary_key: Vec<usize> = Vec::new();
    for (idx, col) in create.columns.iter().enumerate() {
        columns.push(column_def(col, idx, &mut primary_key)?);
    }
    if primary_key.is_empty() {
        return Err(SqlError::Unsupported("table without PRIMARY KEY"));
    }

    Ok(Statement::CreateTable(TableMeta {
        name,
        columns,
        primary_key,
        indexes: Vec::<IndexMeta>::new(),
    }))
}

fn create_index(idx: &ast::CreateIndex) -> SqlResult<Statement> {
    if idx.unique || idx.concurrently || idx.if_not_exists || idx.using.is_some() {
        return Err(SqlError::Unsupported("CREATE INDEX modifier"));
    }
    if !idx.include.is_empty() || !idx.with.is_empty() || idx.predicate.is_some() {
        return Err(SqlError::Unsupported("CREATE INDEX clause"));
    }
    let name = idx
        .name
        .as_ref()
        .ok_or(SqlError::Unsupported("CREATE INDEX without explicit name"))
        .and_then(single_name)?;
    let table = single_name(&idx.table_name)?;
    if idx.columns.len() != 1 {
        return Err(SqlError::Unsupported("multi-column index"));
    }
    let order = &idx.columns[0];
    if order.asc.is_some() || order.nulls_first.is_some() || order.with_fill.is_some() {
        return Err(SqlError::Unsupported("CREATE INDEX column option"));
    }
    let column = match &order.expr {
        AstExpr::Identifier(id) => id.value.clone(),
        _ => return Err(SqlError::Unsupported("non-ident index column")),
    };
    Ok(Statement::CreateIndex { name, table, column })
}

fn column_def(col: &ColumnDef, idx: usize, pk: &mut Vec<usize>) -> SqlResult<ColumnMeta> {
    let mut not_null = false;
    for opt in &col.options {
        match &opt.option {
            ColumnOption::NotNull => not_null = true,
            ColumnOption::Unique { is_primary: true, .. } => {
                pk.push(idx);
                not_null = true;
            }
            ColumnOption::Null => {}
            _ => return Err(SqlError::Unsupported("column option")),
        }
    }
    Ok(ColumnMeta { name: col.name.value.clone(), ty: sql_type(&col.data_type)?, not_null })
}

fn sql_type(ty: &DataType) -> SqlResult<SqlType> {
    use DataType as D;
    Ok(match ty {
        D::Boolean | D::Bool => SqlType::Bool,
        D::Int(_) | D::Integer(_) | D::SmallInt(_) | D::TinyInt(_) => SqlType::Int,
        D::BigInt(_) => SqlType::BigInt,
        D::Double(_) | D::DoublePrecision | D::Float(_) | D::Real => SqlType::Double,
        D::Text | D::String(_) | D::Varchar(_) | D::Char(_) | D::CharVarying(_) => SqlType::Text,
        D::Bytea | D::Blob(_) | D::Binary(_) | D::Varbinary(_) => SqlType::Blob,
        _ => return Err(SqlError::Unsupported("data type")),
    })
}

fn single_name(name: &ObjectName) -> SqlResult<String> {
    if name.0.len() != 1 {
        return Err(SqlError::Unsupported("qualified name"));
    }
    Ok(name.0[0].value.clone())
}

fn insert_stmt(insert: ast::Insert) -> SqlResult<Statement> {
    if insert.or.is_some()
        || insert.overwrite
        || insert.partitioned.is_some()
        || !insert.after_columns.is_empty()
        || insert.on.is_some()
        || insert.returning.is_some()
        || insert.replace_into
    {
        return Err(SqlError::Unsupported("INSERT modifier"));
    }
    let table_name = match &insert.table {
        TableObject::TableName(n) => n,
        TableObject::TableFunction(_) => return Err(SqlError::Unsupported("INSERT INTO function")),
    };
    let table = single_name(table_name)?;
    let columns: Vec<String> = insert.columns.iter().map(|i| i.value.clone()).collect();
    let source = insert.source.ok_or(SqlError::Unsupported("INSERT without VALUES"))?;
    let rows = values_from_query(*source)?;
    Ok(Statement::Insert { table, columns, rows })
}

fn values_from_query(q: Query) -> SqlResult<Vec<Vec<Expr>>> {
    if q.with.is_some() || q.order_by.is_some() || q.limit.is_some() || q.offset.is_some() {
        return Err(SqlError::Unsupported("INSERT with clauses"));
    }
    let SetExpr::Values(values) = *q.body else {
        return Err(SqlError::Unsupported("INSERT source"));
    };
    let mut out = Vec::with_capacity(values.rows.len());
    for row in values.rows {
        let mut evald = Vec::with_capacity(row.len());
        for cell in row {
            evald.push(expr(cell)?);
        }
        out.push(evald);
    }
    Ok(out)
}

fn select_query(q: Query) -> SqlResult<SelectStmt> {
    if q.with.is_some() {
        return Err(SqlError::Unsupported("CTE"));
    }
    if q.offset.is_some() || q.fetch.is_some() {
        return Err(SqlError::Unsupported("OFFSET/FETCH"));
    }
    if !q.locks.is_empty() || q.for_clause.is_some() || q.format_clause.is_some() {
        return Err(SqlError::Unsupported("SELECT trailing clause"));
    }

    let order_by = match q.order_by {
        Some(ob) => {
            if ob.interpolate.is_some() {
                return Err(SqlError::Unsupported("ORDER BY INTERPOLATE"));
            }
            let mut out = Vec::with_capacity(ob.exprs.len());
            for o in ob.exprs {
                if o.nulls_first.is_some() || o.with_fill.is_some() {
                    return Err(SqlError::Unsupported("ORDER BY modifier"));
                }
                let asc = o.asc.unwrap_or(true);
                out.push((expr(o.expr)?, asc));
            }
            out
        }
        None => Vec::new(),
    };

    let limit = match q.limit {
        Some(AstExpr::Value(AstValue::Number(n, _))) => {
            Some(n.parse::<u64>().map_err(|_| SqlError::Parse)?)
        }
        Some(_) => return Err(SqlError::Unsupported("LIMIT non-literal")),
        None => None,
    };

    let SetExpr::Select(select) = *q.body else {
        return Err(SqlError::Unsupported("SELECT body"));
    };
    let mut s = select_stmt(*select)?;
    s.order_by = order_by;
    s.limit = limit;
    Ok(s)
}

fn select_stmt(s: Select) -> SqlResult<SelectStmt> {
    if s.from.len() != 1 {
        return Err(SqlError::Unsupported("comma-separated FROM"));
    }
    if !s.lateral_views.is_empty()
        || !s.cluster_by.is_empty()
        || !s.distribute_by.is_empty()
        || !s.sort_by.is_empty()
        || s.distinct.is_some()
        || s.top.is_some()
    {
        return Err(SqlError::Unsupported("SELECT clause"));
    }

    let (from, from_alias, joins) = drive_and_joins(&s.from[0])?;

    let mut projection = Vec::with_capacity(s.projection.len());
    for item in s.projection {
        projection.push(projection_item(item)?);
    }

    let filter = s.selection.map(expr).transpose()?;

    let group_by = match s.group_by {
        ast::GroupByExpr::Expressions(exprs, modifiers) => {
            if !modifiers.is_empty() {
                return Err(SqlError::Unsupported("GROUP BY modifier"));
            }
            let mut cols = Vec::with_capacity(exprs.len());
            for e in exprs {
                cols.push(col_ref_from_expr(&e)?);
            }
            cols
        }
        ast::GroupByExpr::All(_) => return Err(SqlError::Unsupported("GROUP BY ALL")),
    };

    let having = s.having.map(expr).transpose()?;

    Ok(SelectStmt {
        from,
        from_alias,
        joins,
        projection,
        filter,
        group_by,
        having,
        order_by: Vec::new(),
        limit: None,
    })
}

fn drive_and_joins(t: &TableWithJoins) -> SqlResult<(String, Option<String>, Vec<JoinClause>)> {
    let (from, from_alias) = table_factor(&t.relation)?;
    let mut joins = Vec::with_capacity(t.joins.len());
    for j in &t.joins {
        if j.global {
            return Err(SqlError::Unsupported("GLOBAL JOIN"));
        }
        let on = match &j.join_operator {
            JoinOperator::Inner(JoinConstraint::On(e)) => e.clone(),
            _ => return Err(SqlError::Unsupported("JOIN kind")),
        };
        let (table, alias) = table_factor(&j.relation)?;
        joins.push(JoinClause { table, alias, on: expr(on)? });
    }
    Ok((from, from_alias, joins))
}

fn table_factor(tf: &TableFactor) -> SqlResult<(String, Option<String>)> {
    match tf {
        TableFactor::Table { name, alias, with_hints, version, .. } => {
            if !with_hints.is_empty() || version.is_some() {
                return Err(SqlError::Unsupported("table modifier"));
            }
            let alias_name = alias.as_ref().map(|a| a.name.value.clone());
            Ok((single_name(name)?, alias_name))
        }
        _ => Err(SqlError::Unsupported("table source")),
    }
}

fn projection_item(item: SelectItem) -> SqlResult<ProjectionItem> {
    match item {
        SelectItem::Wildcard(_) => Ok(ProjectionItem::Star),
        SelectItem::QualifiedWildcard(name, _) => Ok(ProjectionItem::QualifiedStar(single_name(&name)?)),
        SelectItem::UnnamedExpr(e) => projection_from_expr(e, None),
        SelectItem::ExprWithAlias { expr: e, alias } => projection_from_expr(e, Some(alias.value)),
    }
}

fn projection_from_expr(e: AstExpr, alias: Option<String>) -> SqlResult<ProjectionItem> {
    if let Some((func, arg)) = aggregate_call(&e)? {
        return Ok(ProjectionItem::Agg { func, arg, alias });
    }
    let col = col_ref_from_expr(&e)?;
    Ok(ProjectionItem::Col { col, alias })
}

fn aggregate_call(e: &AstExpr) -> SqlResult<Option<(AggregateFn, Option<ColRef>)>> {
    let AstExpr::Function(f) = e else {
        return Ok(None);
    };
    if f.over.is_some() || f.filter.is_some() || f.null_treatment.is_some() || !f.within_group.is_empty() {
        return Err(SqlError::Unsupported("aggregate clause"));
    }
    let name = match f.name.0.as_slice() {
        [single] => single.value.to_ascii_uppercase(),
        _ => return Err(SqlError::Unsupported("qualified function name")),
    };
    let func = match name.as_str() {
        "COUNT" => AggregateFn::Count,
        "SUM" => AggregateFn::Sum,
        "AVG" => AggregateFn::Avg,
        "MIN" => AggregateFn::Min,
        "MAX" => AggregateFn::Max,
        _ => return Ok(None),
    };
    let args = match &f.args {
        FunctionArguments::List(list) => list,
        _ => return Err(SqlError::Unsupported("function call shape")),
    };
    if args.duplicate_treatment.is_some() {
        return Err(SqlError::Unsupported("DISTINCT in aggregate"));
    }
    if !args.clauses.is_empty() {
        return Err(SqlError::Unsupported("aggregate argument clause"));
    }
    if args.args.len() != 1 {
        return Err(SqlError::Unsupported("aggregate arity"));
    }
    let arg_expr = match &args.args[0] {
        FunctionArg::Unnamed(a) => a,
        _ => return Err(SqlError::Unsupported("named aggregate argument")),
    };
    match (func, arg_expr) {
        (AggregateFn::Count, FunctionArgExpr::Wildcard) => Ok(Some((AggregateFn::CountStar, None))),
        (_, FunctionArgExpr::Wildcard | FunctionArgExpr::QualifiedWildcard(_)) => {
            Err(SqlError::Unsupported("wildcard in aggregate"))
        }
        (_, FunctionArgExpr::Expr(arg)) => Ok(Some((func, Some(col_ref_from_expr(arg)?)))),
    }
}

fn col_ref_from_expr(e: &AstExpr) -> SqlResult<ColRef> {
    match e {
        AstExpr::Identifier(id) => Ok(ColRef { table: None, column: id.value.clone() }),
        AstExpr::CompoundIdentifier(parts) if parts.len() == 2 => Ok(ColRef {
            table: Some(parts[0].value.clone()),
            column: parts[1].value.clone(),
        }),
        _ => Err(SqlError::Unsupported("expected column reference")),
    }
}

fn update_stmt(
    table: TableWithJoins,
    assignments: Vec<ast::Assignment>,
    from: Option<ast::UpdateTableFromKind>,
    selection: Option<AstExpr>,
    returning: Option<Vec<SelectItem>>,
    or: Option<ast::SqliteOnConflict>,
) -> SqlResult<Statement> {
    if from.is_some() || returning.is_some() || or.is_some() {
        return Err(SqlError::Unsupported("UPDATE clause"));
    }
    if !table.joins.is_empty() {
        return Err(SqlError::Unsupported("UPDATE with JOIN"));
    }
    let (target, _alias) = table_factor(&table.relation)?;

    let mut assigns = Vec::with_capacity(assignments.len());
    for a in assignments {
        let col = match &a.target {
            ast::AssignmentTarget::ColumnName(name) => single_name(name)?,
            ast::AssignmentTarget::Tuple(_) => {
                return Err(SqlError::Unsupported("tuple assignment"))
            }
        };
        assigns.push((col, expr(a.value)?));
    }
    let filter = selection.map(expr).transpose()?;
    Ok(Statement::Update { table: target, assignments: assigns, filter })
}

fn delete_stmt(d: ast::Delete) -> SqlResult<Statement> {
    if !d.tables.is_empty()
        || d.using.is_some()
        || d.returning.is_some()
        || !d.order_by.is_empty()
        || d.limit.is_some()
    {
        return Err(SqlError::Unsupported("DELETE clause"));
    }
    let from = match d.from {
        FromTable::WithFromKeyword(v) | FromTable::WithoutKeyword(v) => v,
    };
    if from.len() != 1 {
        return Err(SqlError::Unsupported("multi-table DELETE"));
    }
    if !from[0].joins.is_empty() {
        return Err(SqlError::Unsupported("DELETE with JOIN"));
    }
    let (table, _alias) = table_factor(&from[0].relation)?;
    let filter = d.selection.map(expr).transpose()?;
    Ok(Statement::Delete { table, filter })
}

fn expr(e: AstExpr) -> SqlResult<Expr> {
    match e {
        AstExpr::Identifier(Ident { value, .. }) => {
            Ok(Expr::Col(ColRef { table: None, column: value }))
        }
        AstExpr::CompoundIdentifier(parts) if parts.len() == 2 => Ok(Expr::Col(ColRef {
            table: Some(parts[0].value.clone()),
            column: parts[1].value.clone(),
        })),
        AstExpr::Value(v) => Ok(Expr::Lit(value_lit(v)?)),
        AstExpr::Nested(inner) => expr(*inner),
        AstExpr::IsNull(inner) => {
            Ok(Expr::IsNull { operand: Box::new(expr(*inner)?), negated: false })
        }
        AstExpr::IsNotNull(inner) => {
            Ok(Expr::IsNull { operand: Box::new(expr(*inner)?), negated: true })
        }
        AstExpr::UnaryOp { op: AstUn::Not, expr: inner } => Ok(Expr::Not(Box::new(expr(*inner)?))),
        AstExpr::UnaryOp { op: AstUn::Minus, expr: inner } => match expr(*inner)? {
            Expr::Lit(Value::Int64(i)) => Ok(Expr::Lit(Value::Int64(-i))),
            Expr::Lit(Value::F64(f)) => Ok(Expr::Lit(Value::F64(-f))),
            _ => Err(SqlError::Unsupported("unary minus on non-literal")),
        },
        AstExpr::BinaryOp { left, op, right } => {
            let bop = match op {
                AstBin::Eq => BinaryOp::Eq,
                AstBin::NotEq => BinaryOp::Neq,
                AstBin::Lt => BinaryOp::Lt,
                AstBin::LtEq => BinaryOp::Lte,
                AstBin::Gt => BinaryOp::Gt,
                AstBin::GtEq => BinaryOp::Gte,
                AstBin::And => BinaryOp::And,
                AstBin::Or => BinaryOp::Or,
                _ => return Err(SqlError::Unsupported("binary operator")),
            };
            Ok(Expr::Binary { op: bop, lhs: Box::new(expr(*left)?), rhs: Box::new(expr(*right)?) })
        }
        _ => Err(SqlError::Unsupported("expression kind")),
    }
}

fn value_lit(v: AstValue) -> SqlResult<Value> {
    match v {
        AstValue::Null => Ok(Value::Null),
        AstValue::Boolean(b) => Ok(Value::Bool(b)),
        AstValue::Number(n, _) => {
            if let Ok(i) = n.parse::<i64>() {
                Ok(Value::Int64(i))
            } else if let Ok(f) = n.parse::<f64>() {
                Ok(Value::F64(f))
            } else {
                Err(SqlError::Parse)
            }
        }
        AstValue::SingleQuotedString(s)
        | AstValue::DoubleQuotedString(s)
        | AstValue::EscapedStringLiteral(s) => Ok(Value::Text(s)),
        AstValue::HexStringLiteral(s) => {
            let bytes = (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| SqlError::Parse))
                .collect::<SqlResult<Vec<u8>>>()?;
            Ok(Value::Blob(bytes))
        }
        _ => Err(SqlError::Unsupported("literal kind")),
    }
}
