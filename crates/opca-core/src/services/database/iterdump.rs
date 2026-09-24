use rusqlite::Connection;

use crate::error::OpcaError;

/// Export the database as SQL text, matching Python's `sqlite3.Connection.iterdump()` output.
///
/// The output format is:
/// ```sql
/// BEGIN TRANSACTION;
/// CREATE TABLE ...;
/// INSERT INTO "table" VALUES(...);
/// CREATE INDEX ...;
/// COMMIT;
/// ```
pub fn iterdump(conn: &Connection) -> Result<String, OpcaError> {
    let mut output = String::new();
    output.push_str("BEGIN TRANSACTION;\n");

    // Collect CREATE TABLE statements and table names
    let mut stmt = conn.prepare(
        "SELECT type, name, sql FROM sqlite_master
         WHERE sql IS NOT NULL AND type IN ('table', 'index')
         ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END, name",
    )?;

    let entries: Vec<(String, String, String)> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Emit CREATE TABLE + INSERT statements, then CREATE INDEX statements
    let mut index_stmts = Vec::new();

    for (obj_type, name, sql) in &entries {
        if obj_type == "table" {
            // Skip internal SQLite tables
            if name.starts_with("sqlite_") {
                continue;
            }

            output.push_str(sql);
            output.push_str(";\n");

            // Emit INSERT statements for this table's rows
            emit_inserts(conn, name, &mut output)?;
        } else if obj_type == "index" {
            index_stmts.push(sql.clone());
        }
    }

    for idx_sql in &index_stmts {
        output.push_str(idx_sql);
        output.push_str(";\n");
    }

    output.push_str("COMMIT;\n");
    Ok(output)
}

/// Emit `INSERT INTO "table" VALUES(...)` for every row in the given table.
fn emit_inserts(conn: &Connection, table_name: &str, output: &mut String) -> Result<(), OpcaError> {
    let sql = format!("SELECT * FROM \"{}\"", table_name.replace('"', "\"\""));
    let mut stmt = conn.prepare(&sql)?;
    let col_count = stmt.column_count();

    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        output.push_str(&format!("INSERT INTO \"{}\" VALUES(", table_name));

        for i in 0..col_count {
            if i > 0 {
                output.push(',');
            }
            format_value(row, i, output);
        }

        output.push_str(");\n");
    }

    Ok(())
}

/// Format a single column value for SQL output.
///
/// Matches Python's `iterdump()` conventions:
/// - `NULL` for null values
/// - Bare integers for integer types
/// - Single-quoted strings with internal `'` doubled to `''`
fn format_value(row: &rusqlite::Row<'_>, idx: usize, output: &mut String) {
    use rusqlite::types::ValueRef;

    match row.get_ref_unwrap(idx) {
        ValueRef::Null => output.push_str("NULL"),
        ValueRef::Integer(i) => output.push_str(&i.to_string()),
        ValueRef::Real(f) => output.push_str(&f.to_string()),
        ValueRef::Text(bytes) => {
            let s = String::from_utf8_lossy(bytes);
            output.push('\'');
            for ch in s.chars() {
                if ch == '\'' {
                    output.push_str("''");
                } else {
                    output.push(ch);
                }
            }
            output.push('\'');
        }
        ValueRef::Blob(bytes) => {
            output.push_str("X'");
            for b in bytes {
                output.push_str(&format!("{b:02X}"));
            }
            output.push('\'');
        }
    }
}
