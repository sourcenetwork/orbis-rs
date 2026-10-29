use std::net::SocketAddr;

pub const MAX_PEER_ID_LENGTH: usize = 256;
pub const EXPECTED_HEX_NODE_ID_LENGTH: usize = 64;

#[derive(Debug, Clone)]
pub enum PeerIdValidationError {
    Empty,
    TooLong { length: usize, max: usize },
    InvalidFormat(String),
    InvalidSocketAddr(String),
    InvalidNodeIdLength { length: usize, expected: usize },
    InvalidCharacters(String),
}

impl std::fmt::Display for PeerIdValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Peer ID cannot be empty"),
            Self::TooLong { length, max } => {
                write!(f, "Peer ID too long: {length} bytes, maximum is {max}")
            }
            Self::InvalidFormat(message) => write!(f, "Invalid peer ID format: {message}"),
            Self::InvalidSocketAddr(message) => {
                write!(f, "Invalid socket address in peer ID: {message}")
            }
            Self::InvalidNodeIdLength { length, expected } => {
                write!(
                    f,
                    "Invalid node ID length: {length} chars, expected {expected}"
                )
            }
            Self::InvalidCharacters(message) => {
                write!(f, "Node ID contains invalid characters: {message}")
            }
        }
    }
}

impl std::error::Error for PeerIdValidationError {}

fn is_valid_address(address: &str) -> bool {
    if address.parse::<SocketAddr>().is_ok() {
        return true;
    }
    let Some(colon) = address.rfind(':') else {
        return false;
    };
    let host = &address[..colon];
    let port = &address[colon + 1..];
    port.parse::<u16>().is_ok_and(|port| port != 0)
        && !host.is_empty()
        && host.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '.'
        })
        && !host.starts_with('-')
        && !host.ends_with('-')
}

pub fn validate_peer_id(peer_id: &str) -> Result<(), PeerIdValidationError> {
    if peer_id.is_empty() {
        return Err(PeerIdValidationError::Empty);
    }
    if peer_id.len() > MAX_PEER_ID_LENGTH {
        return Err(PeerIdValidationError::TooLong {
            length: peer_id.len(),
            max: MAX_PEER_ID_LENGTH,
        });
    }

    let mut parts = peer_id.splitn(2, '@');
    let node_id = parts.next().unwrap_or_default();
    if node_id.len() != EXPECTED_HEX_NODE_ID_LENGTH {
        return Err(PeerIdValidationError::InvalidNodeIdLength {
            length: node_id.len(),
            expected: EXPECTED_HEX_NODE_ID_LENGTH,
        });
    }
    if !node_id
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        return Err(PeerIdValidationError::InvalidCharacters(format!(
            "Node ID must contain only hexadecimal characters (0-9, a-f, A-F), got: {}",
            &node_id[..node_id.len().min(20)]
        )));
    }

    if let Some(address) = parts.next() {
        if address.is_empty() {
            return Err(PeerIdValidationError::InvalidFormat(
                "Socket address after '@' cannot be empty".to_owned(),
            ));
        }
        if !is_valid_address(address) {
            return Err(PeerIdValidationError::InvalidSocketAddr(format!(
                "Cannot parse '{address}' as a valid address (expected ip:port or hostname:port)"
            )));
        }
    }
    Ok(())
}

pub fn canonicalize_peer_id(peer_id: &str) -> Result<String, PeerIdValidationError> {
    validate_peer_id(peer_id)?;
    let mut parts = peer_id.splitn(2, '@');
    let node_id = parts.next().unwrap_or_default().to_lowercase();
    Ok(match parts.next() {
        Some(address) => format!("{node_id}@{address}"),
        None => node_id,
    })
}

pub fn peer_identity_matches(
    existing_peer_id: &str,
    expected_peer_id: &str,
) -> Result<bool, PeerIdValidationError> {
    validate_peer_id(existing_peer_id)?;
    validate_peer_id(expected_peer_id)?;
    Ok(node_part(existing_peer_id).eq_ignore_ascii_case(node_part(expected_peer_id)))
}

pub fn node_part(peer_id: &str) -> &str {
    peer_id.split('@').next().unwrap_or(peer_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_comparison_rejects_a_malformed_route() {
        let node_id = "ab".repeat(32);
        assert!(peer_identity_matches(&format!("{node_id}@garbage"), &node_id).is_err());
    }
}
