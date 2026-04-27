//! End-to-end integration tests for the Week 2 SQL surface:
//! CREATE TABLE / INSERT / SELECT [WHERE].

use secrecy::SecretString;
use tempfile::TempDir;
use zerobase::keyring::Argon2Params;
use zerobase::Db;
use zerobase_sql::{SqlEngine, SqlError, SqlOutput, Value};

fn fresh_engine() -> (TempDir, SqlEngine, Db) {
    let dir = tempfile::tempdir().unwrap();
    let pass = SecretString::new("test-pw".into());
    let params = Argon2Params { m_cost_kib: 8 * 1024, t_cost: 1, parallelism: 1, _reserved: 0 };
    let db = Db::create_with(dir.path(), &pass, params, 64 * 1024).unwrap();
    let engine = SqlEngine::open(&db).unwrap();
    (dir, engine, db)
}

#[test]
fn create_insert_select_roundtrip() {
    let (_dir, mut eng, mut db) = fresh_engine();

    let out =
        eng.execute("CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT)", &mut db).unwrap();
    assert!(matches!(out, SqlOutput::DdlOk));

    let out = eng
        .execute("INSERT INTO users (id, email) VALUES (1, 'a@b.c'), (2, 'd@e.f')", &mut db)
        .unwrap();
    match out {
        SqlOutput::Affected(n) => assert_eq!(n, 2),
        _ => panic!("expected Affected(2)"),
    }

    let out = eng.execute("SELECT id, email FROM users", &mut db).unwrap();
    let SqlOutput::Rows { columns, rows } = out else {
        panic!("expected rows");
    };
    assert_eq!(columns.len(), 2);
    assert_eq!(rows.len(), 2);
}

#[test]
fn select_with_where_filters() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE k (id BIGINT PRIMARY KEY, n BIGINT)", &mut db).unwrap();
    eng.execute("INSERT INTO k VALUES (1, 10), (2, 20), (3, 30)", &mut db).unwrap();

    let out = eng.execute("SELECT n FROM k WHERE id = 2", &mut db).unwrap();
    let SqlOutput::Rows { rows, .. } = out else { panic!() };
    assert_eq!(rows.len(), 1);
    assert!(matches!(rows[0][0], Value::Int64(20)));
}

#[test]
fn pk_uniqueness_rejected() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE u (id BIGINT PRIMARY KEY, x BIGINT)", &mut db).unwrap();
    eng.execute("INSERT INTO u VALUES (1, 1)", &mut db).unwrap();
    let err = eng.execute("INSERT INTO u VALUES (1, 2)", &mut db).unwrap_err();
    assert!(matches!(err, SqlError::Constraint));
}

#[test]
fn null_in_pk_rejected() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE p (id BIGINT PRIMARY KEY, x BIGINT)", &mut db).unwrap();
    let err = eng.execute("INSERT INTO p (id, x) VALUES (NULL, 1)", &mut db).unwrap_err();
    assert!(matches!(err, SqlError::Constraint));
}

#[test]
fn reserved_table_name_rejected() {
    let (_dir, mut eng, mut db) = fresh_engine();
    let err =
        eng.execute("CREATE TABLE sys_internal (id BIGINT PRIMARY KEY)", &mut db).unwrap_err();
    assert!(matches!(err, SqlError::ReservedIdent));
}

#[test]
fn unknown_table_rejected() {
    let (_dir, mut eng, mut db) = fresh_engine();
    let err = eng.execute("SELECT * FROM ghost", &mut db).unwrap_err();
    assert!(matches!(err, SqlError::UnknownTable));
}

#[test]
fn count_star_over_empty_table_yields_zero() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE t (id BIGINT PRIMARY KEY)", &mut db).unwrap();

    let out = eng.execute("SELECT COUNT(*) FROM t", &mut db).unwrap();
    let SqlOutput::Rows { rows, .. } = out else { panic!() };
    assert_eq!(rows.len(), 1);
    assert!(matches!(rows[0][0], Value::Int64(0)));
}

#[test]
fn count_sum_avg_min_max() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE s (id BIGINT PRIMARY KEY, n BIGINT)", &mut db).unwrap();
    eng.execute("INSERT INTO s VALUES (1, 10), (2, 20), (3, 30), (4, 40)", &mut db).unwrap();

    let out = eng
        .execute("SELECT COUNT(*), SUM(n), AVG(n), MIN(n), MAX(n) FROM s", &mut db)
        .unwrap();
    let SqlOutput::Rows { rows, .. } = out else { panic!() };
    assert_eq!(rows.len(), 1);
    assert!(matches!(rows[0][0], Value::Int64(4)));
    assert!(matches!(rows[0][1], Value::Int64(100)));
    assert!(matches!(rows[0][2], Value::F64(v) if (v - 25.0).abs() < 1e-9));
    assert!(matches!(rows[0][3], Value::Int64(10)));
    assert!(matches!(rows[0][4], Value::Int64(40)));
}

#[test]
fn group_by_with_having() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute(
        "CREATE TABLE sales (id BIGINT PRIMARY KEY, category TEXT, amount BIGINT)",
        &mut db,
    )
    .unwrap();
    eng.execute(
        "INSERT INTO sales VALUES \
         (1, 'a', 10), (2, 'a', 20), (3, 'b', 5), (4, 'c', 100), (5, 'c', 200)",
        &mut db,
    )
    .unwrap();

    let out = eng
        .execute(
            "SELECT category, SUM(amount) FROM sales GROUP BY category \
             HAVING category <> 'b' ORDER BY category ASC",
            &mut db,
        )
        .unwrap();
    let SqlOutput::Rows { rows, .. } = out else { panic!() };
    assert_eq!(rows.len(), 2);
    assert!(matches!(&rows[0][0], Value::Text(s) if s == "a"));
    assert!(matches!(rows[0][1], Value::Int64(30)));
    assert!(matches!(&rows[1][0], Value::Text(s) if s == "c"));
    assert!(matches!(rows[1][1], Value::Int64(300)));
}

#[test]
fn order_by_and_limit() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE n (id BIGINT PRIMARY KEY, v BIGINT)", &mut db).unwrap();
    eng.execute("INSERT INTO n VALUES (1, 30), (2, 10), (3, 20)", &mut db).unwrap();

    let out = eng.execute("SELECT v FROM n ORDER BY v ASC", &mut db).unwrap();
    let SqlOutput::Rows { rows, .. } = out else {
        panic!();
    };
    assert_eq!(rows.len(), 3);
    assert!(matches!(rows[0][0], Value::Int64(10)));
    assert!(matches!(rows[1][0], Value::Int64(20)));
    assert!(matches!(rows[2][0], Value::Int64(30)));

    let out = eng.execute("SELECT v FROM n ORDER BY v DESC LIMIT 2", &mut db).unwrap();
    let SqlOutput::Rows { rows, .. } = out else {
        panic!();
    };
    assert_eq!(rows.len(), 2);
    assert!(matches!(rows[0][0], Value::Int64(30)));
    assert!(matches!(rows[1][0], Value::Int64(20)));
}

#[test]
fn inner_join_two_tables() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute(
        "CREATE TABLE u (id BIGINT PRIMARY KEY, name TEXT)",
        &mut db,
    )
    .unwrap();
    eng.execute(
        "CREATE TABLE p (uid BIGINT PRIMARY KEY, title TEXT)",
        &mut db,
    )
    .unwrap();
    eng.execute("INSERT INTO u VALUES (1, 'ana'), (2, 'bob'), (3, 'cid')", &mut db).unwrap();
    eng.execute("INSERT INTO p VALUES (1, 'engineer'), (3, 'painter')", &mut db).unwrap();

    let out = eng
        .execute(
            "SELECT u.name, p.title FROM u JOIN p ON p.uid = u.id WHERE u.id > 1",
            &mut db,
        )
        .unwrap();
    let SqlOutput::Rows { rows, columns } = out else {
        panic!("expected rows");
    };
    assert_eq!(columns.len(), 2);
    assert_eq!(columns[0].name, "name");
    assert_eq!(columns[1].name, "title");

    // Only u.id=3 (cid/painter) survives the predicate (id=1 filtered, id=2 has no match).
    assert_eq!(rows.len(), 1);
    assert!(matches!(&rows[0][0], Value::Text(s) if s == "cid"));
    assert!(matches!(&rows[0][1], Value::Text(s) if s == "painter"));
}

#[test]
fn three_way_join() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE a (id BIGINT PRIMARY KEY, x BIGINT)", &mut db).unwrap();
    eng.execute("CREATE TABLE b (id BIGINT PRIMARY KEY, y BIGINT)", &mut db).unwrap();
    eng.execute("CREATE TABLE c (id BIGINT PRIMARY KEY, z BIGINT)", &mut db).unwrap();
    eng.execute("INSERT INTO a VALUES (1, 10), (2, 20)", &mut db).unwrap();
    eng.execute("INSERT INTO b VALUES (1, 100), (2, 200)", &mut db).unwrap();
    eng.execute("INSERT INTO c VALUES (1, 1000), (2, 2000)", &mut db).unwrap();

    let out = eng
        .execute(
            "SELECT a.x, b.y, c.z FROM a JOIN b ON b.id = a.id JOIN c ON c.id = a.id",
            &mut db,
        )
        .unwrap();
    let SqlOutput::Rows { rows, .. } = out else {
        panic!();
    };
    assert_eq!(rows.len(), 2);
}

#[test]
fn schema_persists_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let pass = SecretString::new("pw".into());
    let params = Argon2Params { m_cost_kib: 8 * 1024, t_cost: 1, parallelism: 1, _reserved: 0 };

    {
        let mut db = Db::create_with(dir.path(), &pass, params, 64 * 1024).unwrap();
        let mut eng = SqlEngine::open(&db).unwrap();
        eng.execute("CREATE TABLE pets (id BIGINT PRIMARY KEY, name TEXT)", &mut db).unwrap();
        eng.execute("INSERT INTO pets VALUES (1, 'fido')", &mut db).unwrap();
        db.flush().unwrap();
    }

    let mut db = Db::open(dir.path(), &pass).unwrap();
    let mut eng = SqlEngine::open(&db).unwrap();
    let out = eng.execute("SELECT name FROM pets WHERE id = 1", &mut db).unwrap();
    let SqlOutput::Rows { rows, .. } = out else { panic!() };
    assert_eq!(rows.len(), 1);
    assert!(matches!(&rows[0][0], Value::Text(s) if s == "fido"));
}

#[test]
fn delete_with_where() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE t (id BIGINT PRIMARY KEY, n BIGINT)", &mut db).unwrap();
    eng.execute("INSERT INTO t VALUES (1, 10), (2, 20), (3, 30)", &mut db).unwrap();

    let out = eng.execute("DELETE FROM t WHERE n > 15", &mut db).unwrap();
    assert!(matches!(out, SqlOutput::Affected(2)));

    let out = eng.execute("SELECT id FROM t", &mut db).unwrap();
    let SqlOutput::Rows { rows, .. } = out else { panic!() };
    assert_eq!(rows.len(), 1);
    assert!(matches!(rows[0][0], Value::Int64(1)));
}

#[test]
fn update_with_where() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE t (id BIGINT PRIMARY KEY, n BIGINT)", &mut db).unwrap();
    eng.execute("INSERT INTO t VALUES (1, 10), (2, 20), (3, 30)", &mut db).unwrap();

    let out = eng.execute("UPDATE t SET n = 99 WHERE id = 2", &mut db).unwrap();
    assert!(matches!(out, SqlOutput::Affected(1)));

    let out = eng.execute("SELECT n FROM t WHERE id = 2", &mut db).unwrap();
    let SqlOutput::Rows { rows, .. } = out else { panic!() };
    assert_eq!(rows.len(), 1);
    assert!(matches!(rows[0][0], Value::Int64(99)));
}

#[test]
fn create_index_backfills_existing_rows() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE u (id BIGINT PRIMARY KEY, email TEXT)", &mut db).unwrap();
    eng.execute("INSERT INTO u VALUES (1, 'a@x'), (2, 'b@x'), (3, 'c@x')", &mut db).unwrap();

    let out = eng.execute("CREATE INDEX u_email ON u(email)", &mut db).unwrap();
    assert!(matches!(out, SqlOutput::DdlOk));

    // Direct KV introspection: each pre-existing row must have an index entry.
    let prefix = b"tbl/u/idx/email/".to_vec();
    let mut count = 0;
    for _ in db.scan(&prefix) {
        count += 1;
    }
    assert_eq!(count, 3, "back-fill should produce 1 index entry per row");
}

#[test]
fn index_maintained_on_insert_update_delete() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE u (id BIGINT PRIMARY KEY, email TEXT)", &mut db).unwrap();
    eng.execute("CREATE INDEX u_email ON u(email)", &mut db).unwrap();

    eng.execute("INSERT INTO u VALUES (1, 'a@x'), (2, 'b@x')", &mut db).unwrap();
    let prefix = b"tbl/u/idx/email/".to_vec();
    assert_eq!(db.scan(&prefix).len(), 2);

    eng.execute("UPDATE u SET email = 'a2@x' WHERE id = 1", &mut db).unwrap();
    assert_eq!(db.scan(&prefix).len(), 2, "update keeps the count, swaps the entry");

    eng.execute("DELETE FROM u WHERE id = 2", &mut db).unwrap();
    assert_eq!(db.scan(&prefix).len(), 1);
}

#[test]
fn duplicate_index_name_rejected() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE u (id BIGINT PRIMARY KEY, email TEXT)", &mut db).unwrap();
    eng.execute("CREATE INDEX u_email ON u(email)", &mut db).unwrap();
    let err = eng.execute("CREATE INDEX u_email ON u(email)", &mut db).unwrap_err();
    assert!(matches!(err, SqlError::SchemaMismatch));
}

#[test]
fn update_pk_column_rejected() {
    let (_dir, mut eng, mut db) = fresh_engine();
    eng.execute("CREATE TABLE t (id BIGINT PRIMARY KEY, n BIGINT)", &mut db).unwrap();
    eng.execute("INSERT INTO t VALUES (1, 10)", &mut db).unwrap();
    let err = eng.execute("UPDATE t SET id = 2 WHERE id = 1", &mut db).unwrap_err();
    assert!(matches!(err, SqlError::Unsupported(_)));
}
