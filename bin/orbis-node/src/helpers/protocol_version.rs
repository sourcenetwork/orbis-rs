use crate::helpers::auth::current_unix_time;

pub(crate) fn effective_protocol_version(
    upgrade_info: &bulletin::r#trait::UpgradeInfo,
    current_time: u64,
) -> Result<u64, String> {
    upgrade_info
        .effective_version(current_time)
        .map_err(|error| error.to_string())
}

fn activation_time_label(upgrade_info: &bulletin::r#trait::UpgradeInfo) -> String {
    upgrade_info
        .activation_time
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

pub fn installed_versions_label() -> String {
    format!("{:?}", network::SUPPORTED_PROTOCOL_VERSIONS)
}

pub fn resolve_ring_protocol_decision(
    ring_id: &str,
    ring_payload: &bulletin::r#trait::RingPayload,
) -> Result<(&'static network::ProtocolRoutes, u64, String), String> {
    let activation_time = activation_time_label(&ring_payload.upgrade_info);
    let current_time = current_unix_time().map_err(|error| {
        format!(
            "failed to read system clock for ring {ring_id}: effective_version=unknown installed_versions={} current_time=unknown activation_time={activation_time}: {error}",
            installed_versions_label()
        )
    })?;
    let effective_version = effective_protocol_version(&ring_payload.upgrade_info, current_time)
        .map_err(|error| {
            format!(
                "malformed protocol upgrade state for ring {ring_id}: effective_version=invalid installed_versions={} current_time={current_time} activation_time={activation_time}: {error}",
                installed_versions_label()
            )
        })?;
    let routes = network::routes_for_version(effective_version).ok_or_else(|| {
        format!(
            "protocol version for ring {ring_id} is not installed: effective_version={effective_version} installed_versions={} current_time={current_time} activation_time={activation_time}",
            installed_versions_label()
        )
    })?;
    Ok((routes, current_time, activation_time))
}

pub fn ensure_ring_protocol_route(
    ring_id: &str,
    ring_payload: &bulletin::r#trait::RingPayload,
    route_version: u64,
) -> Result<u64, String> {
    let (routes, current_time, activation_time) =
        resolve_ring_protocol_decision(ring_id, ring_payload)
            .map_err(|error| format!("{error} route_version={route_version}"))?;
    if routes.version != route_version {
        return Err(format!(
            "protocol route mismatch for ring {ring_id}: route_version={route_version} effective_version={} installed_versions={} current_time={current_time} activation_time={activation_time}",
            routes.version,
            installed_versions_label()
        ));
    }
    Ok(routes.version)
}

pub async fn read_ring_for_protocol(
    bulletin: &(dyn bulletin::r#trait::Bulletin + Send + Sync),
    ring_id: &str,
) -> Result<
    (
        bulletin::r#trait::RingPayload,
        &'static network::ProtocolRoutes,
    ),
    String,
> {
    let ring_payload = read_ring_payload(bulletin, ring_id).await?;
    let routes = resolve_ring_protocol_decision(ring_id, &ring_payload)?;
    Ok((ring_payload, routes.0))
}

// A transient chain-read hiccup here is otherwise a single point of failure
// for every caller (DKG prepare/session-init, PRE, SIGN all read the ring
// through this one function): one node hitting one momentary network blip
// fails immediately with no retry, which for DKG prepare specifically can
// cascade into aborting the whole committee's ceremony over a blip that
// would have cleared on its own within a second or two. Bounded and short
// (not the many-minute budget `with_signer`'s balance check uses) so it
// stays well inside callers' own deadlines (e.g. DKG's ~120s prepare
// window) while still absorbing a brief transient failure.
const MAX_RING_READ_ATTEMPTS: u32 = 3;
const RING_READ_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

async fn read_ring_payload(
    bulletin: &(dyn bulletin::r#trait::Bulletin + Send + Sync),
    ring_id: &str,
) -> Result<bulletin::r#trait::RingPayload, String> {
    let mut attempt = 0u32;
    let ring_post = loop {
        attempt += 1;
        match bulletin
            .read(
                ring_id.to_string(),
                bulletin::r#trait::BulletinKind::Ring,
            )
            .await
        {
            Ok(ring_post) => break ring_post,
            Err(error) if attempt < MAX_RING_READ_ATTEMPTS => {
                tracing::warn!(
                    ring_id,
                    attempt,
                    %error,
                    "transient failure reading ring for protocol state; retrying"
                );
                tokio::time::sleep(RING_READ_RETRY_DELAY).await;
            }
            Err(error) => {
                return Err(format!(
                    "failed to read protocol state for ring {ring_id} after {MAX_RING_READ_ATTEMPTS} attempts: effective_version=unknown installed_versions={} current_time=unknown activation_time=unknown: {error}",
                    installed_versions_label()
                ));
            }
        }
    };
    bulletin::r#trait::RingPayload::try_from(ring_post).map_err(|error| {
        format!(
            "malformed ring payload for ring {ring_id}: effective_version=invalid installed_versions={} current_time=unknown activation_time=unknown: {error}",
            installed_versions_label()
        )
    })
}

pub async fn read_ring_for_route(
    bulletin: &(dyn bulletin::r#trait::Bulletin + Send + Sync),
    ring_id: &str,
    route_version: u64,
) -> Result<bulletin::r#trait::RingPayload, String> {
    let ring_payload = read_ring_payload(bulletin, ring_id).await?;
    ensure_ring_protocol_route(ring_id, &ring_payload, route_version)?;
    Ok(ring_payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_version_changes_at_activation() {
        let info = bulletin::r#trait::UpgradeInfo {
            current_version: 0,
            next_version: Some(1),
            activation_time: Some(50),
        };
        assert_eq!(effective_protocol_version(&info, 49), Ok(0));
        assert_eq!(effective_protocol_version(&info, 50), Ok(1));
    }

    #[test]
    fn malformed_upgrade_state_is_rejected() {
        let info = bulletin::r#trait::UpgradeInfo {
            current_version: 0,
            next_version: Some(1),
            activation_time: None,
        };
        assert!(effective_protocol_version(&info, 50).is_err());
    }

    #[test]
    fn route_errors_include_decision_context() {
        let payload = bulletin::r#trait::RingPayload {
            upgrade_info: bulletin::r#trait::UpgradeInfo {
                current_version: 1,
                next_version: None,
                activation_time: None,
            },
            ..Default::default()
        };
        let error = resolve_ring_protocol_decision("ring-1", &payload).unwrap_err();
        assert!(error.contains("ring-1"));
        assert!(error.contains("effective_version=1"));
        assert!(error.contains("installed_versions=[0]"));
    }
}
