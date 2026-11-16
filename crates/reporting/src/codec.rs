//! Length-prefixed binary codec shared by every canonical wire type in
//! this module. `write_*` append big-endian, length-prefixed fields;
//! `Decoder` reads them back, tagging each field for error messages.

use crate::error::{ReportingError, Result};

pub fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

pub fn write_bytes(out: &mut Vec<u8>, value: &[u8]) {
    write_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

/// Unlike [`write_bytes`], the length is fixed and implicit — used for
/// digests, which are always exactly 32 bytes, so no length prefix is
/// needed to disambiguate field boundaries.
pub(super) fn write_fixed_32(out: &mut Vec<u8>, value: &[u8; 32]) {
    out.extend_from_slice(value);
}

pub fn write_string(out: &mut Vec<u8>, value: &str) {
    write_bytes(out, value.as_bytes());
}

pub fn write_string_vec(out: &mut Vec<u8>, values: &[String]) {
    write_u32(out, values.len() as u32);
    for value in values {
        write_string(out, value);
    }
}

pub fn write_optional_string(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            write_string(out, value);
        }
        None => out.push(0),
    }
}

pub fn write_optional_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            out.push(1);
            write_bytes(out, value);
        }
        None => out.push(0),
    }
}

pub fn write_optional_string_vec(out: &mut Vec<u8>, value: Option<&[String]>) {
    match value {
        Some(value) => {
            out.push(1);
            write_string_vec(out, value);
        }
        None => out.push(0),
    }
}

pub fn write_optional_u32(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            out.push(1);
            write_u32(out, value);
        }
        None => out.push(0),
    }
}

pub fn write_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            write_u64(out, value);
        }
        None => out.push(0),
    }
}

pub struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub fn read_u8(&mut self, label: &str) -> Result<u8> {
        let value = *self
            .bytes
            .get(self.cursor)
            .ok_or_else(|| ReportingError::InvalidReport(format!("missing {label}")))?;
        self.cursor += 1;
        Ok(value)
    }

    pub fn read_bool(&mut self, label: &str) -> Result<bool> {
        match self.read_u8(label)? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(ReportingError::InvalidReport(format!(
                "invalid bool {label} tag {value}"
            ))),
        }
    }

    pub fn read_u32(&mut self, label: &str) -> Result<u32> {
        let end = self.cursor.saturating_add(4);
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ReportingError::InvalidReport(format!("missing {label}")))?;
        self.cursor = end;
        Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
            ReportingError::InvalidReport(format!("invalid {label}"))
        })?))
    }

    pub fn read_u64(&mut self, label: &str) -> Result<u64> {
        let end = self.cursor.saturating_add(8);
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ReportingError::InvalidReport(format!("missing {label}")))?;
        self.cursor = end;
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
            ReportingError::InvalidReport(format!("invalid {label}"))
        })?))
    }

    pub fn read_string(&mut self, label: &str) -> Result<String> {
        let len = self.read_u32(&format!("{label}_length"))? as usize;
        let end = self.cursor.saturating_add(len);
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ReportingError::InvalidReport(format!("truncated {label}")))?;
        self.cursor = end;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| ReportingError::InvalidReport(format!("{label} is not utf-8")))
    }

    pub fn read_bytes(&mut self, label: &str) -> Result<Vec<u8>> {
        let len = self.read_u32(&format!("{label}_length"))? as usize;
        let end = self.cursor.saturating_add(len);
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ReportingError::InvalidReport(format!("truncated {label}")))?;
        self.cursor = end;
        Ok(bytes.to_vec())
    }

    pub(super) fn read_fixed_32(&mut self, label: &str) -> Result<[u8; 32]> {
        let end = self.cursor.saturating_add(32);
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ReportingError::InvalidReport(format!("truncated {label}")))?;
        self.cursor = end;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    pub fn read_optional_bytes(&mut self, label: &str) -> Result<Option<Vec<u8>>> {
        match self.read_u8(&format!("{label}_present"))? {
            0 => Ok(None),
            1 => self.read_bytes(label).map(Some),
            value => Err(ReportingError::InvalidReport(format!(
                "invalid optional {label} tag {value}"
            ))),
        }
    }

    pub fn read_optional_u64(&mut self, label: &str) -> Result<Option<u64>> {
        match self.read_u8(&format!("{label}_present"))? {
            0 => Ok(None),
            1 => self.read_u64(label).map(Some),
            value => Err(ReportingError::InvalidReport(format!(
                "invalid optional {label} tag {value}"
            ))),
        }
    }

    pub(super) fn read_release_scope(
        &mut self,
    ) -> Result<Option<common::blockchain::orbis::ReleaseScope>> {
        use common::blockchain::orbis::ReleaseScope;
        let scope = if self.is_empty() {
            None
        } else {
            if self.read_string("release scope domain")? != "shieldd-release-scope-v1" {
                return Err(crate::error::ReportingError::InvalidReport(
                    "invalid release scope domain".into(),
                ));
            }
            Some(match self.read_u8("release scope")? {
                0 => ReleaseScope::AssetWide,
                1 => ReleaseScope::NamedPerson {
                    target: self.read_string("target")?,
                },
                2 => ReleaseScope::NoteRecovery {
                    target: self.read_string("target")?,
                },
                _ => {
                    return Err(crate::error::ReportingError::InvalidReport(
                        "invalid release scope".into(),
                    ))
                }
            })
        };
        Ok(scope)
    }

    pub fn is_empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }

    pub fn finish(&self) -> Result<()> {
        if self.cursor != self.bytes.len() {
            return Err(ReportingError::InvalidReport(
                "trailing payload bytes".to_string(),
            ));
        }
        Ok(())
    }
}

/// External-only suffix; native statement encodings remain unchanged.
pub(super) fn write_release_scope(
    out: &mut Vec<u8>,
    scope: Option<&common::blockchain::orbis::ReleaseScope>,
) {
    use common::blockchain::orbis::ReleaseScope;
    if let Some(scope) = scope {
        write_string(out, "shieldd-release-scope-v1");
        match scope {
            ReleaseScope::AssetWide => out.push(0),
            ReleaseScope::NamedPerson { target } => {
                out.push(1);
                write_string(out, target);
            }
            ReleaseScope::NoteRecovery { target } => {
                out.push(2);
                write_string(out, target);
            }
        }
    }
}
