# ZeroBase Key-Space Layout

The KV engine is byte-opaque. Higher layers (SQL, auth) reserve key prefixes
inside the same `Db` so that everything they store inherits the engine's
encryption-at-rest, tamper-evidence, and durability without a second
storage subsystem.

## Reserved prefixes

| Prefix | Owner | Purpose |
|---|---|---|
| `sys/schema/<table>` | `zerobase-sql` | Serialized `TableMeta` (columns, types, PK, indexes). |
| `sys/schema-list` | `zerobase-sql` | `Vec<String>` of table names — fast catalog enumeration. |
| `tbl/<table>/row/<pk>` | `zerobase-sql` | Serialized row (`Vec<Value>`) keyed by encoded primary key. |
| `tbl/<table>/idx/<col>/<v>/<pk>` | `zerobase-sql` | Empty marker: presence means the row at `<pk>` has `<col> = <v>`. |
| `sys/auth/client/<pubkey-hex>` | `zerobase-auth` | `ClientRecord` (display name, roles, last session hash). |
| `sys/auth/cap/<token-id-hex>` | `zerobase-auth` | `CapRecord { used, expires_at, scope, subject }`. |
| `sys/auth/nonce/<pubkey-hex>` | `zerobase-auth` | Pending challenge nonces — short-lived. |
| `sys/audit/<ts-be-u128>/<tag>` | `zerobase-server` | Append-only audit entries. |

User-defined table names cannot start with `sys`, cannot contain `/`, and
cannot equal any reserved word. The SQL parser enforces this in `parse.rs`.

## Encoding rules

### Primary keys

Composite keys are encoded as a sequence of length-prefixed columns:

```
be_u32(column_count)
foreach column in pk:
    be_u32(byte_len)
    bytes
```

This makes prefix-scan correct (a shorter PK never accidentally matches a
longer one's prefix) and lets `Db::range` / `Db::scan` iterate rows in PK
order without any in-engine sort.

### Integers

Big-endian two's-complement with the sign bit flipped:

```
encoded = be_bytes(value as i64) with byte 0 XORed with 0x80
```

The flip swaps the lex-order of negative and positive ranges so that
`range(min..max)` over an `i64` column iterates in numeric order.

### Floats (`f64`)

IEEE-754 big-endian, then transform: if the sign bit is 0, XOR byte 0 with
`0x80`; if the sign bit is 1, complement all bytes. This gives a total
order under byte comparison, with NaN sorting last.

### Text and blobs

Length-prefixed bytes (`be_u32(len) || bytes`). Text is UTF-8 with no
normalization in the MVP.

### Index keys

`tbl/<t>/idx/<col>/<v>/<pk>` — `<v>` is encoded as in PKs above, then a
`0x00` separator, then the row's PK bytes. The separator prevents
ambiguity when a short value is a prefix of a longer one (e.g.,
`"abc"` and `"abcd"`).

## Why this enables the SQL ops we need

| SQL | Lookup |
|---|---|
| `SELECT … WHERE pk = X` | `Db::get("tbl/<t>/row/<X>")` — point lookup. |
| `SELECT * FROM t` | `Db::scan("tbl/<t>/row/")`. |
| `SELECT … WHERE pk BETWEEN A AND B` | `Db::range(A, B)`. |
| `SELECT … WHERE indexed = V` | `Db::scan("tbl/<t>/idx/<col>/<V>/")` → fetch each PK. |
| `JOIN a ON b WHERE b.indexed = a.col` | TableScan(a) × IndexScan(b) (nested loop). |
| `ORDER BY pk` | Already sorted from `Db::range`. |
| `ORDER BY non-pk` | Collect + in-memory sort. |
| `GROUP BY` | Hash-aggregate over scan stream. |

## Reserved-name enforcement

The SQL parser rejects table names matching `^sys` (case-insensitive) or
containing `/`. The auth layer never accepts a user-provided string for
its keys — pubkey hex and token-id hex are produced server-side.

## Future-proofing

If a new layer needs its own prefix, allocate it under `sys/<layer>/…`
and add a row to the table above. The two invariants are:

1. Prefixes never overlap.
2. User table names cannot collide with any prefix above.

The CI workflow greps for new top-level prefixes and fails if they're not
documented here.
