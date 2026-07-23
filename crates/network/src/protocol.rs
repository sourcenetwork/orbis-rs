//! Installed protocol route descriptors.

/// The gRPC and Iroh routes installed for one protocol version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolRoutes {
    pub version: u64,
    pub dkg_control_alpn: &'static [u8],
    pub dkg_private_alpn: &'static [u8],
    pub reencrypt_alpn: &'static [u8],
    pub sign_alpn: &'static [u8],
    pub reporting_health_alpn: &'static [u8],
}

/// Version 0 routes.
///
/// DKG deliberately has no catch-all route: only the typed control and private
/// planes are accepted. Public DKG traffic is carried by Iroh Gossip.
pub const V0: ProtocolRoutes = ProtocolRoutes {
    version: 0,
    dkg_control_alpn: b"orbis/dkg-control/0",
    dkg_private_alpn: b"orbis/dkg-private/0",
    reencrypt_alpn: b"orbis/reencrypt/0",
    sign_alpn: b"orbis/sign/0",
    reporting_health_alpn: b"orbis/reporting/health/0",
};

/// Protocol versions served by this binary.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[u64] = &[V0.version];

/// Resolve the installed route descriptor for a protocol version.
pub fn routes_for_version(version: u64) -> Option<&'static ProtocolRoutes> {
    match version {
        0 => Some(&V0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v0_alpns_are_stable() {
        assert_eq!(V0.dkg_control_alpn, b"orbis/dkg-control/0");
        assert_eq!(V0.dkg_private_alpn, b"orbis/dkg-private/0");
        assert_eq!(V0.reencrypt_alpn, b"orbis/reencrypt/0");
        assert_eq!(V0.sign_alpn, b"orbis/sign/0");
        assert_eq!(V0.reporting_health_alpn, b"orbis/reporting/health/0");
        let installed = [
            V0.dkg_control_alpn,
            V0.dkg_private_alpn,
            V0.reencrypt_alpn,
            V0.sign_alpn,
            V0.reporting_health_alpn,
        ];
        let removed_dkg_route = [b"orbis/dkg".as_slice(), b"/0"].concat();
        assert!(!installed.contains(&removed_dkg_route.as_slice()));
    }

    #[test]
    fn registry_contains_only_v0() {
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS, &[0]);
        assert_eq!(routes_for_version(0), Some(&V0));
        assert_eq!(routes_for_version(1), None);
    }
}
