//! CSV export (§9.13): the import columns `label,address,port,username,group,tags`;
//! `group` is the path `a/b/c`, tags are joined with `;`.

use crate::importers::csv::COLUMNS;

/// One exported row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CsvRow {
    /// `label`
    pub label: String,
    /// `address`
    pub address: String,
    /// `port`
    pub port: Option<u16>,
    /// `username`
    pub username: Option<String>,
    /// Group path `a/b/c`.
    pub group: Option<String>,
    /// Tag names.
    pub tags: Vec<String>,
}

/// The CSV text (RFC 4180, header row first).
///
/// # Errors
/// Only on an internal writer failure.
pub fn export(rows: &[CsvRow]) -> Result<String, String> {
    let mut w = ::csv::Writer::from_writer(Vec::new());
    w.write_record(COLUMNS).map_err(|e| e.to_string())?;
    for r in rows {
        let port = r.port.map(|p| p.to_string()).unwrap_or_default();
        w.write_record([
            r.label.as_str(),
            r.address.as_str(),
            port.as_str(),
            r.username.as_deref().unwrap_or(""),
            r.group.as_deref().unwrap_or(""),
            r.tags.join(";").as_str(),
        ])
        .map_err(|e| e.to_string())?;
    }
    let bytes = w.into_inner().map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}
