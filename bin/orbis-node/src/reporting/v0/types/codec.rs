//! Length-prefixed binary codec shared by every canonical wire type in
//! this module. `write_*` append big-endian, length-prefixed fields;
//! `Decoder` reads them back, tagging each field for error messages.

use crate::reporting::v0::error::{ReportingError, Result};

pub(super) fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

pub(super) fn write_bytes(out: &mut Vec<u8>, value: &[u8]) {
    write_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

pub(super) fn write_string(out: &mut Vec<u8>, value: &str) {
    write_bytes(out, value.as_bytes());
}

pub(super) fn write_string_vec(out: &mut Vec<u8>, values: &[String]) {
    write_u32(out, values.len() as u32);
    for value in values {
        write_string(out, value);
    }
}

/// Field order matches the proto declaration order and is the canonical
/// wire contract — the chain-side (Go) decoder must read fields in
/// exactly this order.
pub(super) fn write_demerit_config(out: &mut Vec<u8>, value: &bulletin::r#trait::DemeritConfig) {
    write_u64(out, value.node_offline_demerits);
    write_u64(out, value.reset_interval_seconds);
    write_u64(out, value.invalid_crypto_response_demerits);
    write_u64(out, value.unauthorized_request_demerits);
}

pub(super) fn write_reporting_config(
    out: &mut Vec<u8>,
    value: &bulletin::r#trait::ReportingConfig,
) {
    write_demerit_config(out, &value.demerit_config);
    write_string_vec(out, &value.backup_node_keys);
    write_u64(out, value.kick_threshold);
}

pub(super) fn write_optional_string(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            write_string(out, value);
        }
        None => out.push(0),
    }
}

pub(super) fn write_optional_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            out.push(1);
            write_bytes(out, value);
        }
        None => out.push(0),
    }
}

pub(super) fn write_optional_string_vec(out: &mut Vec<u8>, value: Option<&[String]>) {
    match value {
        Some(value) => {
            out.push(1);
            write_string_vec(out, value);
        }
        None => out.push(0),
    }
}

pub(super) fn write_optional_u32(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            out.push(1);
            write_u32(out, value);
        }
        None => out.push(0),
    }
}

pub(super) fn write_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            write_u64(out, value);
        }
        None => out.push(0),
    }
}

pub(super) struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(super) fn read_u8(&mut self, label: &str) -> Result<u8> {
        let value = *self
            .bytes
            .get(self.cursor)
            .ok_or_else(|| ReportingError::InvalidReport(format!("missing {label}")))?;
        self.cursor += 1;
        Ok(value)
    }

    pub(super) fn read_bool(&mut self, label: &str) -> Result<bool> {
        match self.read_u8(label)? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(ReportingError::InvalidReport(format!(
                "invalid bool {label} tag {value}"
            ))),
        }
    }

    pub(super) fn read_u32(&mut self, label: &str) -> Result<u32> {
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

    pub(super) fn read_u64(&mut self, label: &str) -> Result<u64> {
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

    pub(super) fn read_string(&mut self, label: &str) -> Result<String> {
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

    pub(super) fn read_bytes(&mut self, label: &str) -> Result<Vec<u8>> {
        let len = self.read_u32(&format!("{label}_length"))? as usize;
        let end = self.cursor.saturating_add(len);
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ReportingError::InvalidReport(format!("truncated {label}")))?;
        self.cursor = end;
        Ok(bytes.to_vec())
    }

    pub(super) fn read_optional_bytes(&mut self, label: &str) -> Result<Option<Vec<u8>>> {
        match self.read_u8(&format!("{label}_present"))? {
            0 => Ok(None),
            1 => self.read_bytes(label).map(Some),
            value => Err(ReportingError::InvalidReport(format!(
                "invalid optional {label} tag {value}"
            ))),
        }
    }

    pub(super) fn read_optional_u64(&mut self, label: &str) -> Result<Option<u64>> {
        match self.read_u8(&format!("{label}_present"))? {
            0 => Ok(None),
            1 => self.read_u64(label).map(Some),
            value => Err(ReportingError::InvalidReport(format!(
                "invalid optional {label} tag {value}"
            ))),
        }
    }

    pub(super) fn finish(&self) -> Result<()> {
        if self.cursor != self.bytes.len() {
            return Err(ReportingError::InvalidReport(
                "trailing payload bytes".to_string(),
            ));
        }
        Ok(())
    }
}
