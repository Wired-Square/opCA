use std::io::{self, Write};

/// Print a section title.
pub fn title(text: &str) {
    println!();
    println!("{text}");
    println!("{}", "=".repeat(text.len().min(72)));
}

/// Print a subsection heading.
pub fn subtitle(text: &str) {
    println!();
    println!("{text}");
    println!("{}", "-".repeat(text.len().min(72)));
}

/// Print a labelled result line.
pub fn print_result(label: &str, ok: bool) {
    if ok {
        println!("  {label}: OK");
    } else {
        println!("  {label}: FAILED");
    }
}

/// Print an error message to stderr.
pub fn error(msg: &str) {
    eprintln!("Error: {msg}");
}

/// Print a warning message to stderr.
pub fn warning(msg: &str) {
    eprintln!("Warning: {msg}");
}

/// Print an informational key-value pair.
pub fn info(key: &str, value: &str) {
    println!("  {key}: {value}");
}

/// Print a simple aligned table.
///
/// `headers` is a list of column names.
/// `rows` is a list of rows, each row a list of cell values.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("  (no entries)");
        return;
    }

    // Calculate column widths
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    // Print header
    let header_line: String = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:width$}", h, width = widths[i]))
        .collect::<Vec<_>>()
        .join("  ");
    println!("  {header_line}");
    let separator: String = widths
        .iter()
        .map(|w| "-".repeat(*w))
        .collect::<Vec<_>>()
        .join("  ");
    println!("  {separator}");

    // Print rows
    for row in rows {
        let line: String = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let w = widths.get(i).copied().unwrap_or(cell.len());
                format!("{:width$}", cell, width = w)
            })
            .collect::<Vec<_>>()
            .join("  ");
        println!("  {line}");
    }
}

/// Write raw bytes to stdout (for binary export).
pub fn write_stdout(data: &[u8]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(data)?;
    out.flush()
}
