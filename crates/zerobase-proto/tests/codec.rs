//! Round-trip tests for the wire codec.

use std::io::Cursor;

use zerobase_proto::{
    read_frame, write_frame, KvCmd, KvResult, MAX_FRAME_BYTES, ProtoError, Request, Response,
    SqlCmd, SqlResult,
};

#[test]
fn kv_get_roundtrip() {
    let req = Request::Kv(KvCmd::Get { key: b"users/42".to_vec() });
    let mut buf = Vec::new();
    write_frame(&mut buf, &req).unwrap();
    let mut r = Cursor::new(buf);
    let got: Request = read_frame(&mut r).unwrap();
    match got {
        Request::Kv(KvCmd::Get { key }) => assert_eq!(key, b"users/42"),
        _ => panic!("variant changed across the wire"),
    }
}

#[test]
fn sql_rows_response_roundtrip() {
    let resp = Response::Sql(SqlResult::Rows {
        columns: vec!["id".into(), "name".into()],
        rows: vec![vec![1, 2, 3], vec![4, 5, 6]],
    });
    let mut buf = Vec::new();
    write_frame(&mut buf, &resp).unwrap();
    let mut r = Cursor::new(buf);
    let got: Response = read_frame(&mut r).unwrap();
    match got {
        Response::Sql(SqlResult::Rows { columns, rows }) => {
            assert_eq!(columns, vec!["id", "name"]);
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0], vec![1, 2, 3]);
        }
        _ => panic!("variant changed"),
    }
}

#[test]
fn multiple_frames_in_a_stream() {
    let mut buf = Vec::new();
    write_frame(&mut buf, &Request::Kv(KvCmd::Get { key: b"a".to_vec() })).unwrap();
    write_frame(&mut buf, &Request::Kv(KvCmd::Put { key: b"b".to_vec(), value: b"v".to_vec() })).unwrap();
    write_frame(&mut buf, &Request::Sql(SqlCmd::Execute { sql: "SELECT 1".into() })).unwrap();
    write_frame(&mut buf, &Request::Bye).unwrap();

    let mut r = Cursor::new(buf);
    let mut count = 0;
    loop {
        match read_frame::<_, Request>(&mut r) {
            Ok(Request::Bye) => {
                count += 1;
                break;
            }
            Ok(_) => count += 1,
            Err(_) => break,
        }
    }
    assert_eq!(count, 4, "should have read all four framed requests");
}

#[test]
fn oversized_frame_is_rejected() {
    // Forge a header that claims 16 MiB > MAX_FRAME_BYTES (8 MiB).
    let mut buf = Vec::new();
    let bogus_len = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
    buf.extend_from_slice(&bogus_len);
    let mut r = Cursor::new(buf);
    let res: Result<Request, _> = read_frame(&mut r);
    assert!(matches!(res, Err(ProtoError::FrameTooLarge(_))));
}

#[test]
fn truncated_frame_is_io_error() {
    // Length prefix says 100 bytes, payload is 0 bytes.
    let mut buf = Vec::new();
    buf.extend_from_slice(&100u32.to_be_bytes());
    let mut r = Cursor::new(buf);
    let res: Result<Request, _> = read_frame(&mut r);
    assert!(matches!(res, Err(ProtoError::Io(_))));
}

#[test]
fn kv_result_items_roundtrip() {
    let resp = Response::Kv(KvResult::Items(vec![
        (b"k1".to_vec(), b"v1".to_vec()),
        (b"k2".to_vec(), b"v2".to_vec()),
    ]));
    let mut buf = Vec::new();
    write_frame(&mut buf, &resp).unwrap();
    let mut r = Cursor::new(buf);
    let got: Response = read_frame(&mut r).unwrap();
    match got {
        Response::Kv(KvResult::Items(items)) => assert_eq!(items.len(), 2),
        _ => panic!("variant changed"),
    }
}
