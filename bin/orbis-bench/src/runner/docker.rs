//! Docker backend: real orbis-node containers behind Docker Compose, a real Vera
//! chain, Prometheus metric scraping, container-failure detection, and
//! host-resource sampling. Counterpart to `in_process.rs` — see that module's docs
//! for what's different (and why) on the in-process side.

use super::*;

impl BenchmarkRunner {
    pub(super) async fn run_stack_docker(
        &self,
        store: &mut ResultStore,
        manifest: &mut RunManifest,
        stack: &StackPlan,
        stack_id: &str,
        completed: &HashSet<TrialKey>,
        interrupt_rx: &mut watch::Receiver<bool>,
    ) -> Result<StackRunOutcome> {
        let stack_dir = store.root().join("stacks").join(stack_id);
        let run_id = manifest.run_id.clone();
        let input = ComposeInput {
            repository_root: &self.repository_root,
            run_id: &run_id,
            stack_id,
            stack,
            crypto: self.experiment.crypto,
            vera_ref: &self.experiment.vera_ref,
            vera_replicas: self.experiment.vera_replicas,
            resources: &self.experiment.resources,
            scheduler_poll_secs: self.experiment.pss_poll_interval_secs,
        };
        let artifacts = write_stack_files(&stack_dir, &input)?;
        let compose = DockerCompose::new(stack_id.to_string(), artifacts.compose_file.clone())?;

        let mut resource_sampler = None;
        let stack_work = async {
            if self.options.resume.is_some() {
                // Resume replays setup on clean volumes while keeping committed
                // trial records. This avoids coupling correctness to whatever
                // partial protocol state happened to survive the interruption.
                compose.down().await.ok();
            }
            eprintln!(
                "[{stack_id}] building Vera and production node images (the first build can take several minutes)"
            );
            compose.build().await?;
            manifest.node_image = image_digest(&format!(
                "orbis-bench-node:{}",
                self.experiment.crypto.feature_name()
            ))
            .await
            .ok();
            manifest.vera_image =
                image_digest(&crate::compose::vera_image_tag(&self.experiment.vera_ref))
                    .await
                    .ok();
            store.update_manifest(manifest)?;

            eprintln!(
                "[{stack_id}] starting Vera and {} nodes",
                stack.network_size
            );
            compose.up_vera(self.experiment.vera_replicas).await?;
            compose.up_nodes().await?;
            let endpoints = discover_endpoints(&compose, stack.network_size).await?;
            let identities = discover_identities(
                &endpoints,
                Duration::from_secs(self.experiment.timeouts.setup_secs),
            )
            .await?;
            eprintln!(
                "[{stack_id}] discovered {} persistent node identities",
                identities.len()
            );

            let mut case_rings = plan_rings(stack, &identities, &self.experiment)?;

            let chain_config = discover_chain_config(&compose).await?;
            let controller = controller_client(chain_config.clone()).await?;
            let funding =
                fund_nodes(&controller, &identities, self.experiment.setup_batch_size).await?;
            manifest.setup_batch_evidence.insert(
                format!("{stack_id}/funding"),
                serde_json::to_value(funding)?,
            );
            store.update_manifest(manifest)?;

            // Nodes block in NodeStatus::WaitingForFunding until they notice their
            // own on-chain balance, then self-register their NodeInfo record before
            // reaching NodeStatus::Ready. update_peer_addresses references that
            // NodeInfo, so it must wait for readiness rather than firing right after
            // the funding broadcast returns.
            wait_nodes_ready(
                &endpoints,
                Duration::from_secs(self.experiment.timeouts.setup_secs),
            )
            .await?;

            let peer_updates =
                update_peer_addresses(&controller, &identities, self.experiment.setup_batch_size)
                    .await?;
            manifest.setup_batch_evidence.insert(
                format!("{stack_id}/peer-addresses"),
                serde_json::to_value(peer_updates)?,
            );
            store.update_manifest(manifest)?;
            eprintln!("[{stack_id}] funded nodes and registered peer addresses");

            // The governance policy must exist on-chain before any ring can
            // reference it: MsgCreateRing rejects a policy_id that doesn't
            // exist yet.
            create_ring_governance_policy(&controller).await?;

            for case in &mut case_rings {
                create_rings_on_chain(
                    &controller,
                    case.all_mut().map(|planned| &mut planned.definition),
                    RING_PROTOCOL_VERSION,
                )
                .await?;
            }
            let definitions: Vec<RingDefinition> = case_rings
                .iter()
                .flat_map(CaseRings::all)
                .map(|ring| ring.definition.clone())
                .collect();
            eprintln!("[{stack_id}] created {} rings on-chain", definitions.len());
            let governance = register_ring_governance(
                &controller,
                &definitions,
                self.experiment.setup_batch_size,
            )
            .await?;
            manifest.setup_batch_evidence.insert(
                format!("{stack_id}/ring-governance"),
                serde_json::to_value(governance)?,
            );
            store.update_manifest(manifest)?;
            eprintln!("[{stack_id}] registered ring permissions");

            let calibration = compose
                .apply_network_profile(&stack.profile, stack.network_size)
                .await?;
            manifest.profile_calibration.insert(
                format!("{stack_id}/{}", stack.profile.name),
                serde_json::to_value(calibration)?,
            );
            store.update_manifest(manifest)?;

            resource_sampler = Some(start_resource_sampler(
                compose.clone(),
                manifest.run_id.clone(),
                stack_id.to_string(),
            ));
            let sampler = resource_sampler
                .as_mut()
                .expect("resource sampler was just started");
            let mut clients = DirectClients::connect(&endpoints).await?;
            let mut rng = StdRng::seed_from_u64(
                self.experiment.seed ^ (stack.stack_index as u64).rotate_left(17),
            );
            case_rings.shuffle(&mut rng);
            let mut all_cases_viable = true;
            for case_rings in &case_rings {
                eprintln!(
                    "[{stack_id}] measuring ring={} threshold={} ({})",
                    case_rings.case.ring_size, case_rings.case.threshold, stack.profile.name
                );
                let viable = self
                    .run_case(
                        &mut TrialContext {
                            store: &mut *store,
                            manifest: &*manifest,
                            stack,
                            stack_id,
                            clients: &mut clients,
                            completed,
                            rng: &mut rng,
                        },
                        &compose,
                        &controller,
                        &endpoints,
                        case_rings,
                        &mut sampler.sample_rx,
                    )
                    .await;
                if let Err(error) = &viable {
                    compose
                        .write_failure_logs(
                            &store.root().join("logs"),
                            &format!("{}-{}", stack.profile.name, case_rings.case.ring_size),
                        )
                        .await
                        .ok();
                    manifest.warnings.push(format!(
                        "case ring={} threshold={} failed: {error:#}",
                        case_rings.case.ring_size, case_rings.case.threshold
                    ));
                }
                all_cases_viable &= viable.unwrap_or(false);
                drain_resource_samples(store, &mut sampler.sample_rx)?;
            }
            Ok::<_, anyhow::Error>(all_cases_viable)
        };

        let stack_result = tokio::select! {
            biased;
            _ = wait_for_interrupt(interrupt_rx) => None,
            result = stack_work => Some(result),
        };
        let sampler_result = stop_resource_sampler(resource_sampler.take(), store).await;
        if let Err(error) = &sampler_result {
            manifest.warnings.push(format!(
                "resource sampler shutdown failed for {stack_id}: {error:#}"
            ));
        }

        if stack_result.as_ref().is_some_and(Result::is_err) {
            compose
                .write_failure_logs(&store.root().join("logs"), "setup")
                .await
                .ok();
        }
        if stack_result.is_none() {
            eprintln!(
                "[{stack_id}] Ctrl-C received; stopping exact Compose project before exiting"
            );
        }
        if !self.options.keep_network {
            if let Err(error) = compose.down().await {
                manifest.warnings.push(format!(
                    "cleanup failed for exact project {stack_id}: {error:#}"
                ));
            }
        } else if stack_result.is_none() {
            eprintln!(
                "[{stack_id}] --keep-network is set; leaving the exact Compose project running"
            );
        }
        match stack_result {
            Some(Ok(viable)) => sampler_result.map(|()| StackRunOutcome::Completed(viable)),
            Some(Err(error)) => Err(error),
            None => Ok(StackRunOutcome::Interrupted),
        }
    }

    async fn run_case(
        &self,
        ctx: &mut TrialContext<'_>,
        compose: &DockerCompose,
        controller: &VeraClient,
        endpoints: &[NodeEndpoint],
        rings: &CaseRings,
        resource_rx: &mut mpsc::Receiver<crate::results::ResourceSample>,
    ) -> Result<bool> {
        let mut viable = true;
        if self.experiment.operations.contains(&Operation::Dkg) {
            let initiator_offset = (ctx.rng.next_u64() as usize) % rings.case.ring_size;
            for (trial_index, ring) in rings.dkg.iter().enumerate() {
                let warmup = trial_index < self.experiment.warmups;
                let measured_index = trial_index.saturating_sub(self.experiment.warmups);
                let key = TrialKey::serial(
                    ctx.stack_id,
                    &ctx.stack.profile.name,
                    &rings.case,
                    Operation::Dkg,
                    measured_index,
                    warmup,
                );
                if ctx.completed.contains(&key) {
                    continue;
                }
                let initiator = (initiator_offset + trial_index) % ring.members.len();
                let committee = committee_endpoints(ring, endpoints);
                let before = scrape_committee(&committee).await;
                let started_at = unix_ms();
                let started = Instant::now();
                let result = timeout(
                    Duration::from_secs(self.experiment.timeouts.dkg_secs),
                    async {
                        let acknowledgement = ctx
                            .clients
                            .start_dkg(ring.members[initiator] - 1, &ring.definition.id)
                            .await?;
                        let ring_pk = ctx
                            .clients
                            .wait_ring_finalized_everywhere(
                                controller,
                                &ring.definition.id,
                                &ring.members,
                                Duration::from_secs(self.experiment.timeouts.dkg_secs),
                            )
                            .await?;
                        Ok::<_, anyhow::Error>((acknowledgement, ring_pk))
                    },
                )
                .await;
                let after = scrape_committee(&committee).await;
                let metric_deltas = metric_delta(&before, &after);
                let failures = compose.container_failures().await.unwrap_or_default();
                let (success, error_class, error, acknowledgement_ms, ring_pk) = match result {
                    Ok(Ok((ack, ring_pk))) if failures.is_empty() => (
                        true,
                        None,
                        None,
                        Some(ack.acknowledgement_ms),
                        Some(ring_pk),
                    ),
                    Ok(Ok(_)) => (
                        false,
                        Some("container_failure".into()),
                        Some(format!("{failures:?}")),
                        None,
                        None,
                    ),
                    Ok(Err(error)) => (
                        false,
                        Some("protocol_failure".into()),
                        Some(format!("{error:#}")),
                        None,
                        None,
                    ),
                    Err(_) => (
                        false,
                        Some("timeout".into()),
                        Some("DKG deadline exceeded".into()),
                        None,
                        None,
                    ),
                };
                viable &= success || warmup;
                ctx.store.append_trial(&TrialRecord {
                    run_id: ctx.manifest.run_id.clone(),
                    stack_id: ctx.stack_id.into(),
                    profile: ctx.stack.profile.name.clone(),
                    network_size: ctx.stack.network_size,
                    case: rings.case.clone(),
                    operation: Operation::Dkg,
                    trial_index: measured_index,
                    warmup,
                    concurrency: None,
                    started_at_unix_ms: started_at,
                    duration_ms: started.elapsed().as_secs_f64() * 1000.0,
                    client_total_ms: None,
                    acknowledgement_ms,
                    verification_ms: None,
                    scheduler_delay_ms: None,
                    throughput_per_sec: None,
                    successful_requests: None,
                    failed_requests: None,
                    latency_p50_ms: None,
                    latency_p95_ms: None,
                    latency_p99_ms: None,
                    success,
                    error_class,
                    error,
                    ring_id: Some(ring.definition.id.clone()),
                    ring_pk,
                    metric_deltas,
                })?;
                drain_resource_samples(ctx.store, resource_rx)?;
            }
        }

        let mut online = None;
        if let Some(ring) = &rings.online {
            let ring_pk = establish_ring(
                ctx.clients,
                controller,
                ring,
                ctx.rng,
                Duration::from_secs(self.experiment.timeouts.dkg_secs),
            )
            .await?;
            online = Some(
                prepare_online_fixtures(
                    &endpoints[ring.members[0] - 1],
                    &ring.definition.id,
                    &ring_pk,
                    controller.config().clone(),
                    rings.case.ring_size,
                )
                .await?,
            );
        }

        if self.experiment.operations.contains(&Operation::Pre) {
            let fixtures = online
                .as_ref()
                .context("PRE requires an online fixture ring")?;
            let ring = rings
                .online
                .as_ref()
                .context("PRE requires an online fixture ring")?;
            viable &= self
                .run_pre_trials(ctx, compose, endpoints, rings, ring, &fixtures.pre)
                .await?;
        }
        if self.experiment.operations.contains(&Operation::Sign) {
            let fixtures = online
                .as_ref()
                .context("SIGN requires an online fixture ring")?;
            let ring = rings
                .online
                .as_ref()
                .context("SIGN requires an online fixture ring")?;
            viable &= self
                .run_sign_trials(ctx, compose, endpoints, rings, ring, &fixtures.sign)
                .await?;
        }
        if self.experiment.operations.contains(&Operation::PssRefresh) {
            let ring = rings.refresh.as_ref().context("PSS ring was not planned")?;
            viable &= self
                .run_pss_trials(ctx, compose, controller, endpoints, rings, ring)
                .await?;
        }
        if self.experiment.operations.contains(&Operation::PssReshare) {
            viable &= self
                .run_reshare_trials(ctx, compose, controller, endpoints, rings)
                .await?;
        }
        Ok(viable)
    }

    async fn run_pre_trials(
        &self,
        ctx: &mut TrialContext<'_>,
        compose: &DockerCompose,
        endpoints: &[NodeEndpoint],
        rings: &CaseRings,
        ring: &PlannedRing,
        fixture: &PreFixture,
    ) -> Result<bool> {
        let mut viable = true;
        let committee = committee_endpoints(ring, endpoints);
        let initiator_offset = (ctx.rng.next_u64() as usize) % rings.case.ring_size;
        for trial in 0..self.experiment.warmups + self.experiment.repetitions {
            let warmup = trial < self.experiment.warmups;
            let trial_index = trial.saturating_sub(self.experiment.warmups);
            let key = TrialKey::serial(
                ctx.stack_id,
                &ctx.stack.profile.name,
                &rings.case,
                Operation::Pre,
                trial_index,
                warmup,
            );
            if ctx.completed.contains(&key) {
                continue;
            }
            let initiator_position = (initiator_offset + trial) % rings.case.ring_size;
            let initiator = ring.members[initiator_position] - 1;
            let before = scrape_committee(&committee).await;
            let started = Instant::now();
            let result = timeout(
                Duration::from_secs(self.experiment.timeouts.pre_secs),
                ctx.clients.pre(initiator, fixture),
            )
            .await;
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            let after = scrape_committee(&committee).await;
            let failures = compose.container_failures().await.unwrap_or_default();
            let (success, duration_ms, client_total_ms, verification_ms, class, error) =
                match result {
                    Ok(Ok(result)) if failures.is_empty() => (
                        true,
                        result.rpc_ms,
                        Some(result.total_ms),
                        Some(result.decrypt_ms),
                        None,
                        None,
                    ),
                    Ok(Ok(_)) => (
                        false,
                        elapsed_ms,
                        None,
                        None,
                        Some("container_failure".into()),
                        Some(format!("{failures:?}")),
                    ),
                    Ok(Err(error)) => (
                        false,
                        elapsed_ms,
                        None,
                        None,
                        Some("correctness_or_protocol_failure".into()),
                        Some(format!("{error:#}")),
                    ),
                    Err(_) => (
                        false,
                        elapsed_ms,
                        None,
                        None,
                        Some("timeout".into()),
                        Some("PRE deadline exceeded".into()),
                    ),
                };
            viable &= success || warmup;
            let mut record = base_trial(
                ctx.manifest,
                ctx.stack,
                ctx.stack_id,
                rings,
                Operation::Pre,
                trial_index,
                warmup,
                duration_ms,
                verification_ms,
                success,
                class,
                error,
            );
            record.client_total_ms = client_total_ms;
            record.metric_deltas = metric_delta(&before, &after);
            ctx.store.append_trial(&record)?;
        }
        for (stage_index, &concurrency) in self.experiment.load.concurrency.iter().enumerate() {
            let key = TrialKey::load(
                ctx.stack_id,
                &ctx.stack.profile.name,
                &rings.case,
                Operation::Pre,
                concurrency,
            );
            if ctx.completed.contains(&key) {
                continue;
            }
            let initiator =
                ring.members[(initiator_offset + stage_index) % rings.case.ring_size] - 1;
            let client = ctx.clients.pre_client(initiator)?;
            run_pre_load(
                client.clone(),
                fixture.clone(),
                concurrency,
                Duration::from_secs(self.experiment.load.warmup_secs),
            )
            .await;
            let before = scrape_committee(&committee).await;
            let measurement = run_pre_load(
                client,
                fixture.clone(),
                concurrency,
                Duration::from_secs(self.experiment.load.measure_secs),
            )
            .await;
            let after = scrape_committee(&committee).await;
            let failures = compose.container_failures().await.unwrap_or_default();
            viable &= measurement.failures == 0 && measurement.successes > 0 && failures.is_empty();
            let mut record = load_trial(
                ctx.manifest,
                ctx.stack,
                ctx.stack_id,
                rings,
                Operation::Pre,
                concurrency,
                measurement,
            );
            if !failures.is_empty() {
                record.success = false;
                record.error_class = Some("container_failure".into());
                record.error = Some(format!("{failures:?}"));
            }
            record.metric_deltas = metric_delta(&before, &after);
            ctx.store.append_trial(&record)?;
        }
        Ok(viable)
    }

    async fn run_sign_trials(
        &self,
        ctx: &mut TrialContext<'_>,
        compose: &DockerCompose,
        endpoints: &[NodeEndpoint],
        rings: &CaseRings,
        ring: &PlannedRing,
        fixture: &SignFixture,
    ) -> Result<bool> {
        let mut viable = true;
        let committee = committee_endpoints(ring, endpoints);
        let initiator_offset = (ctx.rng.next_u64() as usize) % rings.case.ring_size;
        for trial in 0..self.experiment.warmups + self.experiment.repetitions {
            let warmup = trial < self.experiment.warmups;
            let trial_index = trial.saturating_sub(self.experiment.warmups);
            let key = TrialKey::serial(
                ctx.stack_id,
                &ctx.stack.profile.name,
                &rings.case,
                Operation::Sign,
                trial_index,
                warmup,
            );
            if ctx.completed.contains(&key) {
                continue;
            }
            let initiator_position = (initiator_offset + trial) % rings.case.ring_size;
            let initiator = ring.members[initiator_position] - 1;
            let message = format!("orbis-bench-sign-{}-{trial}", ctx.manifest.run_id).into_bytes();
            let before = scrape_committee(&committee).await;
            let started = Instant::now();
            let result = timeout(
                Duration::from_secs(self.experiment.timeouts.sign_secs),
                ctx.clients.sign(initiator, fixture, message),
            )
            .await;
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            let after = scrape_committee(&committee).await;
            let failures = compose.container_failures().await.unwrap_or_default();
            let (success, duration_ms, client_total_ms, verification_ms, class, error) =
                match result {
                    Ok(Ok(result)) if failures.is_empty() => (
                        true,
                        result.rpc_ms,
                        Some(result.total_ms),
                        Some(result.verification_ms),
                        None,
                        None,
                    ),
                    Ok(Ok(_)) => (
                        false,
                        elapsed_ms,
                        None,
                        None,
                        Some("container_failure".into()),
                        Some(format!("{failures:?}")),
                    ),
                    Ok(Err(error)) => (
                        false,
                        elapsed_ms,
                        None,
                        None,
                        Some("correctness_or_protocol_failure".into()),
                        Some(format!("{error:#}")),
                    ),
                    Err(_) => (
                        false,
                        elapsed_ms,
                        None,
                        None,
                        Some("timeout".into()),
                        Some("SIGN deadline exceeded".into()),
                    ),
                };
            viable &= success || warmup;
            let mut record = base_trial(
                ctx.manifest,
                ctx.stack,
                ctx.stack_id,
                rings,
                Operation::Sign,
                trial_index,
                warmup,
                duration_ms,
                verification_ms,
                success,
                class,
                error,
            );
            record.client_total_ms = client_total_ms;
            record.metric_deltas = metric_delta(&before, &after);
            ctx.store.append_trial(&record)?;
        }
        for (stage_index, &concurrency) in self.experiment.load.concurrency.iter().enumerate() {
            let key = TrialKey::load(
                ctx.stack_id,
                &ctx.stack.profile.name,
                &rings.case,
                Operation::Sign,
                concurrency,
            );
            if ctx.completed.contains(&key) {
                continue;
            }
            let initiator =
                ring.members[(initiator_offset + stage_index) % rings.case.ring_size] - 1;
            let client = ctx.clients.sign_client(initiator)?;
            run_sign_load(
                client.clone(),
                fixture.clone(),
                concurrency,
                Duration::from_secs(self.experiment.load.warmup_secs),
            )
            .await;
            let before = scrape_committee(&committee).await;
            let measurement = run_sign_load(
                client,
                fixture.clone(),
                concurrency,
                Duration::from_secs(self.experiment.load.measure_secs),
            )
            .await;
            let after = scrape_committee(&committee).await;
            let failures = compose.container_failures().await.unwrap_or_default();
            viable &= measurement.failures == 0 && measurement.successes > 0 && failures.is_empty();
            let mut record = load_trial(
                ctx.manifest,
                ctx.stack,
                ctx.stack_id,
                rings,
                Operation::Sign,
                concurrency,
                measurement,
            );
            if !failures.is_empty() {
                record.success = false;
                record.error_class = Some("container_failure".into());
                record.error = Some(format!("{failures:?}"));
            }
            record.metric_deltas = metric_delta(&before, &after);
            ctx.store.append_trial(&record)?;
        }
        Ok(viable)
    }

    async fn run_pss_trials(
        &self,
        ctx: &mut TrialContext<'_>,
        compose: &DockerCompose,
        controller: &VeraClient,
        endpoints: &[NodeEndpoint],
        rings: &CaseRings,
        ring: &PlannedRing,
    ) -> Result<bool> {
        let committee = committee_endpoints(ring, endpoints);
        let ring_pk = establish_ring(
            ctx.clients,
            controller,
            ring,
            ctx.rng,
            Duration::from_secs(self.experiment.timeouts.dkg_secs),
        )
        .await?;
        let original_chain_pk = read_ring_with_retry(controller, &ring.definition.id)
            .await?
            .context("PSS ring missing")?
            .ring_pk;
        let mut viable = true;
        for trial in 0..self.experiment.warmups + self.experiment.repetitions {
            let warmup = trial < self.experiment.warmups;
            let trial_index = trial.saturating_sub(self.experiment.warmups);
            let key = TrialKey::serial(
                ctx.stack_id,
                &ctx.stack.profile.name,
                &rings.case,
                Operation::PssRefresh,
                trial_index,
                warmup,
            );
            if ctx.completed.contains(&key) {
                continue;
            }
            let baseline = ctx.clients.ring_states(&ring.members, &ring_pk).await?;
            let due = baseline
                .iter()
                .map(|state| state.last_pss)
                .max()
                .unwrap_or(0)
                .saturating_add(
                    ring.definition
                        .pss_interval_secs
                        .saturating_sub(PSS_GRACE_PERIOD_SECS),
                );
            let before = scrape_committee(&committee).await;
            let started = Instant::now();
            let result = ctx
                .clients
                .wait_pss_refresh(
                    &ring.members,
                    &ring_pk,
                    &baseline,
                    due,
                    Duration::from_secs(self.experiment.timeouts.pss_refresh_secs),
                )
                .await;
            if result.is_ok() {
                wait_refresh_metrics_settle(&committee, &before, Duration::from_secs(5)).await;
            }
            let after = scrape_committee(&committee).await;
            let metric_deltas = metric_delta(&before, &after);
            let chain_pk = read_ring_with_retry(controller, &ring.definition.id)
                .await?
                .map(|ring| ring.ring_pk);
            let failures = compose.container_failures().await.unwrap_or_default();
            let (success, duration_ms, scheduler_delay_ms, class, error) = match result {
                Ok(measurement)
                    if failures.is_empty()
                        && chain_pk.as_deref() == Some(original_chain_pk.as_str()) =>
                {
                    let (ceremony_ms, scheduler_delay_ms) = pss_timing(
                        measurement.ceremony_ms,
                        measurement.scheduler_delay_ms,
                        histogram_average_ms(&metric_deltas, "pss_scheduler_delay_seconds"),
                    );
                    (true, ceremony_ms, Some(scheduler_delay_ms), None, None)
                }
                Ok(_) if !failures.is_empty() => (
                    false,
                    started.elapsed().as_secs_f64() * 1000.0,
                    None,
                    Some("container_failure".into()),
                    Some(format!("{failures:?}")),
                ),
                Ok(_) => (
                    false,
                    started.elapsed().as_secs_f64() * 1000.0,
                    None,
                    Some("correctness_failure".into()),
                    Some("ring public key changed during refresh".into()),
                ),
                Err(error) => {
                    let class = if error.is::<PssRefreshTimeout>() {
                        "timeout"
                    } else {
                        "protocol_failure"
                    };
                    (
                        false,
                        started.elapsed().as_secs_f64() * 1000.0,
                        None,
                        Some(class.into()),
                        Some(format!("{error:#}")),
                    )
                }
            };
            viable &= success || warmup;
            let mut record = base_trial(
                ctx.manifest,
                ctx.stack,
                ctx.stack_id,
                rings,
                Operation::PssRefresh,
                trial_index,
                warmup,
                duration_ms,
                None,
                success,
                class,
                error,
            );
            record.scheduler_delay_ms = scheduler_delay_ms;
            record.ring_id = Some(ring.definition.id.clone());
            record.ring_pk = Some(ring_pk.clone());
            record.metric_deltas = metric_deltas;
            ctx.store.append_trial(&record)?;
        }
        Ok(viable)
    }

    async fn run_reshare_trials(
        &self,
        ctx: &mut TrialContext<'_>,
        compose: &DockerCompose,
        controller: &VeraClient,
        endpoints: &[NodeEndpoint],
        rings: &CaseRings,
    ) -> Result<bool> {
        let mut viable = true;
        for (trial, planned) in rings.reshare.iter().enumerate() {
            let warmup = trial < self.experiment.warmups;
            let trial_index = trial.saturating_sub(self.experiment.warmups);
            let key = TrialKey::serial(
                ctx.stack_id,
                &ctx.stack.profile.name,
                &rings.case,
                Operation::PssReshare,
                trial_index,
                warmup,
            );
            if ctx.completed.contains(&key) {
                continue;
            }

            let ring_pk = establish_ring(
                ctx.clients,
                controller,
                &planned.ring,
                ctx.rng,
                Duration::from_secs(self.experiment.timeouts.dkg_secs),
            )
            .await?;
            let old_states = ctx
                .clients
                .ring_states(&planned.ring.members, &ring_pk)
                .await?;
            let old_last_pss = planned
                .ring
                .members
                .iter()
                .copied()
                .zip(old_states.iter().map(|state| state.last_pss))
                .collect::<BTreeMap<_, _>>();
            let union = planned.ring.authorized_members.clone();
            let committee = union
                .iter()
                .map(|index| endpoints[*index - 1].clone())
                .collect::<Vec<_>>();
            let next_node_keys = planned.next_node_keys.clone();
            let before = scrape_committee(&committee).await;
            let started_at = unix_ms();
            let started = Instant::now();
            let result = timeout(
                Duration::from_secs(self.experiment.timeouts.pss_refresh_secs),
                async {
                    let response = controller
                        .orbis_start_ring_reshare_by_acp(
                            &planned.ring.definition.id,
                            next_node_keys.clone(),
                            Some(rings.case.threshold as u32),
                        )
                        .await?;
                    if response.code != 0 {
                        bail!("Vera rejected reshare announcement: {}", response.log);
                    }
                    wait_reshare_finalized(
                        controller,
                        ctx.clients,
                        &planned.ring.definition.id,
                        &ring_pk,
                        &planned.next_members,
                        &next_node_keys,
                        rings.case.threshold,
                        &old_last_pss,
                    )
                    .await
                },
            )
            .await;
            let after = scrape_committee(&committee).await;
            let metric_deltas = metric_delta(&before, &after);
            let failures = compose.container_failures().await.unwrap_or_default();
            let (success, class, error) = match result {
                Ok(Ok(())) if failures.is_empty() => (true, None, None),
                Ok(Ok(())) => (
                    false,
                    Some("container_failure".into()),
                    Some(format!("{failures:?}")),
                ),
                Ok(Err(error)) => (
                    false,
                    Some("correctness_or_protocol_failure".into()),
                    Some(format!("{error:#}")),
                ),
                Err(_) => (
                    false,
                    Some("timeout".into()),
                    Some("PSS reshare deadline exceeded".into()),
                ),
            };
            viable &= success || warmup;
            let mut record = base_trial(
                ctx.manifest,
                ctx.stack,
                ctx.stack_id,
                rings,
                Operation::PssReshare,
                trial_index,
                warmup,
                started.elapsed().as_secs_f64() * 1000.0,
                None,
                success,
                class,
                error,
            );
            record.started_at_unix_ms = started_at;
            record.ring_id = Some(planned.ring.definition.id.clone());
            record.ring_pk = Some(ring_pk);
            record.metric_deltas = metric_deltas;
            ctx.store.append_trial(&record)?;
        }
        Ok(viable)
    }
}

#[derive(Clone, Debug)]
struct PlannedRing {
    definition: RingDefinition,
    members: Vec<usize>,
    authorized_members: Vec<usize>,
}

#[derive(Clone, Debug)]
struct PlannedReshare {
    ring: PlannedRing,
    next_members: Vec<usize>,
    next_node_keys: Vec<String>,
}

#[derive(Clone, Debug)]
struct CaseRings {
    case: RingCase,
    dkg: Vec<PlannedRing>,
    online: Option<PlannedRing>,
    refresh: Option<PlannedRing>,
    reshare: Vec<PlannedReshare>,
}

impl CaseRings {
    fn all(&self) -> impl Iterator<Item = &PlannedRing> {
        self.dkg
            .iter()
            .chain(self.online.iter())
            .chain(self.refresh.iter())
            .chain(self.reshare.iter().map(|planned| &planned.ring))
    }

    fn all_mut(&mut self) -> impl Iterator<Item = &mut PlannedRing> {
        self.dkg
            .iter_mut()
            .chain(self.online.iter_mut())
            .chain(self.refresh.iter_mut())
            .chain(self.reshare.iter_mut().map(|planned| &mut planned.ring))
    }
}

fn plan_rings(
    stack: &StackPlan,
    identities: &[NodeIdentity],
    experiment: &Experiment,
) -> Result<Vec<CaseRings>> {
    let mut output = Vec::new();
    for (case_index, case) in stack.cases.iter().enumerate() {
        let mut ordinal = 0usize;
        let mut make = |pss_interval_secs: u64| -> Result<PlannedRing> {
            let mut rng = StdRng::seed_from_u64(
                experiment.seed
                    ^ (stack.stack_index as u64).rotate_left(11)
                    ^ (case_index as u64).rotate_left(23)
                    ^ (ordinal as u64).rotate_left(37),
            );
            ordinal += 1;
            let mut members: Vec<usize> = (1..=stack.network_size).collect();
            members.shuffle(&mut rng);
            members.truncate(case.ring_size);
            members.sort_unstable();
            let node_keys: Vec<String> = members
                .iter()
                .map(|index| identities[*index - 1].node_key.clone())
                .collect();
            Ok(PlannedRing {
                // Filled in by `create_rings_on_chain` once the ring exists on-chain
                // (Vera assigns the ID; it's no longer precomputed).
                definition: RingDefinition {
                    id: String::new(),
                    peer_node_keys: node_keys.clone(),
                    operator_node_keys: node_keys,
                    threshold: case.threshold,
                    pss_interval_secs,
                    policy_id: RING_GOVERNANCE_POLICY_ID.to_string(),
                },
                authorized_members: members.clone(),
                members,
            })
        };
        let dkg = if experiment.operations.contains(&Operation::Dkg) {
            (0..experiment.warmups + experiment.repetitions)
                .map(|_| make(86_400))
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let online = (experiment.operations.contains(&Operation::Pre)
            || experiment.operations.contains(&Operation::Sign))
        .then(|| make(86_400))
        .transpose()?;
        let refresh = experiment
            .operations
            .contains(&Operation::PssRefresh)
            .then(|| make(experiment.pss_interval_secs))
            .transpose()?;
        let reshare = if experiment.operations.contains(&Operation::PssReshare) {
            let overlap = experiment
                .reshare_overlap
                .context("pss_reshare requires reshare_overlap")?;
            (0..experiment.warmups + experiment.repetitions)
                .map(|trial| {
                    let mut ring = make(86_400)?;
                    let mut selection_rng = StdRng::seed_from_u64(
                        experiment.seed
                            ^ (stack.stack_index as u64).rotate_left(7)
                            ^ (case_index as u64).rotate_left(19)
                            ^ (trial as u64).rotate_left(41),
                    );
                    let mut shared = ring.members.clone();
                    shared.shuffle(&mut selection_rng);
                    shared.truncate(overlap);
                    let old = ring.members.iter().copied().collect::<HashSet<_>>();
                    let mut outsiders = (1..=stack.network_size)
                        .filter(|member| !old.contains(member))
                        .collect::<Vec<_>>();
                    outsiders.shuffle(&mut selection_rng);
                    outsiders.truncate(case.ring_size - overlap);
                    let mut next_members = shared;
                    next_members.extend(outsiders);
                    next_members.sort_unstable();

                    let mut authorized_members = ring.members.clone();
                    authorized_members.extend(next_members.iter().copied());
                    authorized_members.sort_unstable();
                    authorized_members.dedup();
                    ring.definition.operator_node_keys = authorized_members
                        .iter()
                        .map(|index| identities[*index - 1].node_key.clone())
                        .collect();
                    ring.definition
                        .operator_node_keys
                        .push(CONTROLLER_PUBLIC_KEY.to_string());
                    ring.authorized_members = authorized_members;
                    let next_node_keys = next_members
                        .iter()
                        .map(|index| identities[*index - 1].node_key.clone())
                        .collect();
                    Ok(PlannedReshare {
                        ring,
                        next_members,
                        next_node_keys,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        output.push(CaseRings {
            case: case.clone(),
            dkg,
            online,
            refresh,
            reshare,
        });
    }
    Ok(output)
}

fn committee_endpoints(ring: &PlannedRing, endpoints: &[NodeEndpoint]) -> Vec<NodeEndpoint> {
    ring.members
        .iter()
        .map(|index| endpoints[*index - 1].clone())
        .collect()
}

async fn establish_ring(
    clients: &mut DirectClients,
    controller: &VeraClient,
    ring: &PlannedRing,
    rng: &mut StdRng,
    deadline: Duration,
) -> Result<String> {
    if let Some(existing) = controller.orbis_read_ring(&ring.definition.id).await? {
        if !existing.ring_pk.is_empty() {
            return Ok(existing.ring_pk);
        }
    }
    let initiator = ring.members[(rng.next_u64() as usize) % ring.members.len()] - 1;
    clients.start_dkg(initiator, &ring.definition.id).await?;
    clients
        .wait_ring_finalized_everywhere(controller, &ring.definition.id, &ring.members, deadline)
        .await
}

async fn prepare_online_fixtures(
    endpoint: &NodeEndpoint,
    ring_id: &str,
    ring_pk: &str,
    chain_config: ChainConfig,
    ring_size: usize,
) -> Result<OnlineFixtures> {
    let policy_id = cli_tool::add_policy_to_chain_with_config(chain_config.clone()).await?;
    let reader_identity = format!("orbis-bench-reader-{ring_size}");
    let (reader_sk, reader_pk) = generate_keypair()?;
    let reader_pk_bytes = reader_pk.to_bytes()?;
    let plaintext = format!("orbis benchmark plaintext for ring {ring_size}").into_bytes();
    let resource = "document".to_string();
    let permission = "read".to_string();
    let prepared = cli_tool::prepare_secret(
        &plaintext,
        ring_pk,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        None,
    )?;
    let stored = cli_tool::store_prepared_secret(
        endpoint.grpc_url.clone(),
        &prepared,
        ring_id.to_string(),
        Some(reader_identity.clone()),
        true,
    )
    .await?;
    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        stored.object_id.clone(),
        resource.clone(),
        chain_config.clone(),
    )
    .await?;
    cli_tool::set_relationship_on_chain_with_config(
        policy_id.clone(),
        stored.object_id.clone(),
        resource.clone(),
        "reader".into(),
        Some(reader_identity.clone()),
        chain_config.clone(),
    )
    .await?;

    let sign_identity = format!("orbis-bench-signer-{ring_size}");
    let (derivation_id, derived_public_key) = cli_tool::post_key_derivation_with_config(
        ring_id.to_string(),
        format!("benchmark-sign-derivation-{ring_size}"),
        policy_id.clone(),
        resource.clone(),
        permission,
        chain_config.clone(),
    )
    .await?;
    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        derivation_id.clone(),
        resource.clone(),
        chain_config.clone(),
    )
    .await?;
    cli_tool::set_relationship_on_chain_with_config(
        policy_id,
        derivation_id.clone(),
        resource,
        "reader".into(),
        Some(sign_identity.clone()),
        chain_config,
    )
    .await?;

    Ok(OnlineFixtures {
        pre: PreFixture {
            ring_pk: ring_pk.to_string(),
            reader_pk: reader_pk_bytes,
            reader_sk,
            object_id: stored.object_id,
            reader_identity,
            derivation: None,
            salt: None,
            expected_plaintext: plaintext,
        },
        sign: SignFixture {
            derivation_id,
            derived_public_key,
            reader_identity: sign_identity,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn base_trial(
    manifest: &RunManifest,
    stack: &StackPlan,
    stack_id: &str,
    rings: &CaseRings,
    operation: Operation,
    trial_index: usize,
    warmup: bool,
    duration_ms: f64,
    verification_ms: Option<f64>,
    success: bool,
    error_class: Option<String>,
    error: Option<String>,
) -> TrialRecord {
    TrialRecord {
        run_id: manifest.run_id.clone(),
        stack_id: stack_id.into(),
        profile: stack.profile.name.clone(),
        network_size: stack.network_size,
        case: rings.case.clone(),
        operation,
        trial_index,
        warmup,
        concurrency: None,
        started_at_unix_ms: unix_ms(),
        duration_ms,
        client_total_ms: None,
        acknowledgement_ms: None,
        verification_ms,
        scheduler_delay_ms: None,
        throughput_per_sec: None,
        successful_requests: None,
        failed_requests: None,
        latency_p50_ms: None,
        latency_p95_ms: None,
        latency_p99_ms: None,
        success,
        error_class,
        error,
        ring_id: rings.online.as_ref().map(|ring| ring.definition.id.clone()),
        ring_pk: None,
        metric_deltas: BTreeMap::new(),
    }
}

fn load_trial(
    manifest: &RunManifest,
    stack: &StackPlan,
    stack_id: &str,
    rings: &CaseRings,
    operation: Operation,
    concurrency: usize,
    mut measurement: LoadMeasurement,
) -> TrialRecord {
    measurement.latencies.sort_by(f64::total_cmp);
    let total = measurement.successes + measurement.failures;
    TrialRecord {
        run_id: manifest.run_id.clone(),
        stack_id: stack_id.into(),
        profile: stack.profile.name.clone(),
        network_size: stack.network_size,
        case: rings.case.clone(),
        operation,
        trial_index: 0,
        warmup: false,
        concurrency: Some(concurrency),
        started_at_unix_ms: unix_ms(),
        duration_ms: measurement.duration_ms,
        client_total_ms: None,
        acknowledgement_ms: None,
        verification_ms: None,
        scheduler_delay_ms: None,
        throughput_per_sec: Some(measurement.successes as f64 / (measurement.duration_ms / 1000.0)),
        successful_requests: Some(measurement.successes),
        failed_requests: Some(measurement.failures),
        latency_p50_ms: percentile_sorted(&measurement.latencies, 0.50),
        latency_p95_ms: percentile_sorted(&measurement.latencies, 0.95),
        latency_p99_ms: percentile_sorted(&measurement.latencies, 0.99),
        success: measurement.failures == 0 && total > 0,
        error_class: (measurement.failures > 0).then(|| "load_request_failures".into()),
        error: (measurement.failures > 0)
            .then(|| format!("{} of {total} requests failed", measurement.failures)),
        ring_id: rings.online.as_ref().map(|ring| ring.definition.id.clone()),
        ring_pk: None,
        metric_deltas: BTreeMap::new(),
    }
}

async fn discover_endpoints(compose: &DockerCompose, count: usize) -> Result<Vec<NodeEndpoint>> {
    let mut output = Vec::with_capacity(count);
    for index in 1..=count {
        let service = node_service(index);
        let grpc = compose.published_port(&service, 50051).await?;
        let metrics = compose.published_port(&service, 9090).await?;
        output.push(NodeEndpoint {
            index,
            service,
            grpc_url: format!("http://127.0.0.1:{grpc}"),
            metrics_url: format!("http://127.0.0.1:{metrics}/metrics"),
        });
    }
    Ok(output)
}

async fn discover_identities(
    endpoints: &[NodeEndpoint],
    deadline: Duration,
) -> Result<Vec<NodeIdentity>> {
    let each_deadline = deadline.min(Duration::from_secs(120));
    let results = join_all(
        endpoints
            .iter()
            .cloned()
            .map(|endpoint| discover_node_identity(endpoint, each_deadline)),
    )
    .await;
    results.into_iter().collect()
}

async fn discover_chain_config(compose: &DockerCompose) -> Result<ChainConfig> {
    let rpc = compose.published_port("vera", 26657).await?;
    let rest = compose.published_port("vera", 1317).await?;
    let grpc = compose.published_port("vera", 9090).await?;
    Ok(ChainConfig::builder()
        .rpc_url(Some(format!("http://127.0.0.1:{rpc}")))
        .rest_url(Some(format!("http://127.0.0.1:{rest}")))
        .grpc_url(Some(format!("http://127.0.0.1:{grpc}")))
        .build())
}

async fn controller_client(config: ChainConfig) -> Result<VeraClient> {
    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())?;
    Ok(VeraClient::with_signer(config, signer).await?)
}

async fn scrape_committee(committee: &[NodeEndpoint]) -> Vec<MetricSnapshot> {
    let client = reqwest::Client::new();
    join_all(
        committee
            .iter()
            .map(|endpoint| scrape(&client, &endpoint.metrics_url, Duration::from_secs(2))),
    )
    .await
    .into_iter()
    .filter_map(Result::ok)
    .collect()
}

async fn wait_refresh_metrics_settle(
    committee: &[NodeEndpoint],
    before: &[MetricSnapshot],
    deadline: Duration,
) {
    let before = aggregate(before);
    let completed_key =
        "dkg_session_duration_seconds_count{kind=\"refresh\",outcome=\"completed\"}";
    let expected = committee.len() as f64;
    let _ = timeout(deadline, async {
        loop {
            let current = aggregate(&scrape_committee(committee).await);
            let completed = current.get(completed_key).copied().unwrap_or(0.0)
                - before.get(completed_key).copied().unwrap_or(0.0);
            let active = current
                .get("refresh_active_sessions")
                .copied()
                .unwrap_or(0.0);
            if completed >= expected && active <= 0.0 {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

fn metric_delta(before: &[MetricSnapshot], after: &[MetricSnapshot]) -> BTreeMap<String, f64> {
    let mut result = delta(&aggregate(before), &aggregate(after));
    retain_benchmark_metrics(&mut result);
    result
}

fn histogram_average_ms(deltas: &BTreeMap<String, f64>, metric: &str) -> Option<f64> {
    let sum = deltas.get(&format!("{metric}_sum"))?;
    let count = deltas.get(&format!("{metric}_count"))?;
    (*count > 0.0).then(|| sum / count * 1_000.0)
}

async fn wait_reshare_finalized(
    controller: &VeraClient,
    clients: &DirectClients,
    ring_id: &str,
    original_ring_pk: &str,
    next_members: &[usize],
    next_node_keys: &[String],
    expected_threshold: usize,
    old_last_pss: &BTreeMap<usize, u64>,
) -> Result<()> {
    let mut expected_keys = next_node_keys.to_vec();
    expected_keys.sort();
    let mut last_progress = Instant::now()
        .checked_sub(Duration::from_secs(10))
        .unwrap_or_else(Instant::now);
    loop {
        let ring = read_ring_with_retry(controller, ring_id)
            .await?
            .with_context(|| format!("reshare ring {ring_id} disappeared from Vera"))?;
        let mut actual_keys = ring.peer_node_keys.clone();
        actual_keys.sort();
        let chain_finalized = ring.ring_pk == original_ring_pk
            && actual_keys == expected_keys
            && ring.threshold as usize == expected_threshold
            && ring.new_peer_node_keys.is_empty()
            && ring.new_threshold.is_none();

        if chain_finalized {
            match clients.ring_states(next_members, original_ring_pk).await {
                Ok(states) => {
                    let expected_polynomial = states
                        .first()
                        .map(|state| state.public_polynomial.as_str())
                        .filter(|polynomial| !polynomial.is_empty());
                    let matching_polynomials = expected_polynomial.is_some()
                        && states.iter().all(|state| {
                            Some(state.public_polynomial.as_str()) == expected_polynomial
                        });
                    let overlapping_members_updated =
                        next_members.iter().zip(&states).all(|(member, state)| {
                            old_last_pss
                                .get(member)
                                .is_none_or(|before| state.last_pss > *before)
                        });
                    if matching_polynomials && overlapping_members_updated {
                        return Ok(());
                    }
                    if last_progress.elapsed() >= Duration::from_secs(10) {
                        eprintln!(
                            "ring {ring_id}: Vera reshare finalized; waiting for matching new-committee state and last_pss advancement"
                        );
                        last_progress = Instant::now();
                    }
                }
                Err(error) if last_progress.elapsed() >= Duration::from_secs(10) => {
                    eprintln!(
                        "ring {ring_id}: Vera reshare finalized; local-state verification pending: {error:#}"
                    );
                    last_progress = Instant::now();
                }
                Err(_) => {}
            }
        } else if last_progress.elapsed() >= Duration::from_secs(10) {
            eprintln!(
                "ring {ring_id}: waiting for reshare finalization (current={}, next={}, threshold={}, key_preserved={})",
                ring.peer_node_keys.len(),
                ring.new_peer_node_keys.len(),
                ring.threshold,
                ring.ring_pk == original_ring_pk
            );
            last_progress = Instant::now();
        }
        sleep(Duration::from_millis(500)).await;
    }
}

pub(crate) async fn read_ring_with_retry(
    controller: &VeraClient,
    ring_id: &str,
) -> Result<Option<Ring>> {
    const MAX_ATTEMPTS: usize = 3;
    let mut backoff = Duration::from_millis(250);
    for attempt in 1..=MAX_ATTEMPTS {
        match controller.orbis_read_ring(ring_id).await {
            Ok(ring) => return Ok(ring),
            Err(error) if attempt < MAX_ATTEMPTS => {
                eprintln!(
                    "ring {ring_id}: Vera read failed ({attempt}/{MAX_ATTEMPTS}): {error:#}; retrying"
                );
                sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(2));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("read ring {ring_id} from Vera after {MAX_ATTEMPTS} attempts")
                });
            }
        }
    }
    unreachable!("bounded retry loop always returns")
}

struct ResourceSampler {
    stop_tx: watch::Sender<bool>,
    sample_rx: mpsc::Receiver<crate::results::ResourceSample>,
    task: JoinHandle<()>,
}

fn start_resource_sampler(
    compose: DockerCompose,
    run_id: String,
    stack_id: String,
) -> ResourceSampler {
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let (sample_tx, sample_rx) = mpsc::channel(10_000);
    let task = tokio::spawn(async move {
        loop {
            if *stop_rx.borrow() {
                break;
            }
            if let Ok(samples) = compose.resource_samples(&run_id, &stack_id).await {
                for sample in samples {
                    if sample_tx.send(sample).await.is_err() {
                        return;
                    }
                }
            }
            tokio::select! {
                _ = sleep(Duration::from_secs(1)) => {},
                _ = stop_rx.changed() => {},
            }
        }
    });
    ResourceSampler {
        stop_tx,
        sample_rx,
        task,
    }
}

async fn stop_resource_sampler(
    sampler: Option<ResourceSampler>,
    store: &mut ResultStore,
) -> Result<()> {
    let Some(ResourceSampler {
        stop_tx,
        mut sample_rx,
        mut task,
    }) = sampler
    else {
        return Ok(());
    };
    stop_tx.send(true).ok();
    // The sampler task blocks on a bounded `sample_tx.send(...).await` once
    // the channel fills, so it must keep draining here as it awaits the
    // task's exit — awaiting the task alone, with nothing draining, can
    // deadlock the two sides against each other.
    let task_result = loop {
        tokio::select! {
            result = &mut task => break result,
            Some(sample) = sample_rx.recv() => {
                store.append_resource(&sample)?;
            }
        }
    };
    let drain_result = drain_resource_samples(store, &mut sample_rx);
    task_result.context("resource sampler task failed")?;
    drain_result
}

fn drain_resource_samples(
    store: &mut ResultStore,
    receiver: &mut mpsc::Receiver<crate::results::ResourceSample>,
) -> Result<()> {
    while let Ok(sample) = receiver.try_recv() {
        store.append_resource(&sample)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn test_identity(index: usize) -> NodeIdentity {
        NodeIdentity {
            endpoint: NodeEndpoint {
                index,
                service: format!("node-{index:03}"),
                grpc_url: format!("http://node-{index:03}:50051"),
                metrics_url: format!("http://node-{index:03}:9090"),
            },
            public_address: format!("orbis1{index:04}"),
            peer_id: format!("peer-{index:03}"),
            p2p_address: format!("peer-{index:03}@127.0.0.1:{}", 10_000 + index),
            node_key: format!("node-key-{index:03}"),
        }
    }

    #[tokio::test]
    async fn resource_sampler_shutdown_waits_and_drains_buffered_samples() {
        let temp = tempfile::tempdir().unwrap();
        let mut experiment = Experiment::single(3, 3, 2);
        experiment.output_dir = temp.path().join("results");
        let runner = BenchmarkRunner::new(experiment, RunOptions::default()).unwrap();
        let (interrupt_tx, interrupt_rx) = watch::channel(false);
        interrupt_tx.send(true).unwrap();
        let error = runner.run_with_interrupt(interrupt_rx).await.unwrap_err();
        let run_dir = error
            .downcast_ref::<BenchmarkInterrupted>()
            .unwrap()
            .run_dir()
            .to_path_buf();
        let (mut store, _) = ResultStore::resume(run_dir.clone()).unwrap();

        let (stop_tx, mut stop_rx) = watch::channel(false);
        let (sample_tx, sample_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            sample_tx
                .send(crate::results::ResourceSample {
                    run_id: "run".into(),
                    stack_id: "stack".into(),
                    sampled_at_unix_ms: 1,
                    service: "node-001".into(),
                    container_id: "container".into(),
                    cpu_percent: Some(1.0),
                    memory_bytes: Some(2),
                    memory_limit_bytes: Some(3),
                    network_rx_bytes: Some(4),
                    network_tx_bytes: Some(5),
                    block_read_bytes: Some(6),
                    block_write_bytes: Some(7),
                    pids: Some(8),
                })
                .await
                .unwrap();
            if !*stop_rx.borrow() {
                stop_rx.changed().await.unwrap();
            }
        });
        let sampler = ResourceSampler {
            stop_tx,
            sample_rx,
            task,
        };

        timeout(
            Duration::from_secs(1),
            stop_resource_sampler(Some(sampler), &mut store),
        )
        .await
        .expect("sampler shutdown should not hang")
        .unwrap();
        drop(store);
        assert!(fs::read_to_string(run_dir.join("resource-samples.csv"))
            .unwrap()
            .contains("node-001"));
    }

    #[test]
    fn reshare_planning_is_deterministic_and_has_exact_overlap() {
        let mut experiment = Experiment::single(50, 34, 23);
        experiment.operations = BTreeSet::from([Operation::PssReshare]);
        experiment.profiles = vec![NetworkProfile::lan()];
        experiment.reshare_overlap = Some(18);
        let mut plan = experiment.resolve().unwrap();
        plan.assign_indices();
        let identities = (1..=50).map(test_identity).collect::<Vec<_>>();

        let first = plan_rings(&plan.stacks[0], &identities, &experiment).unwrap();
        let second = plan_rings(&plan.stacks[0], &identities, &experiment).unwrap();
        assert_eq!(first[0].reshare.len(), 6);
        for (left, right) in first[0].reshare.iter().zip(&second[0].reshare) {
            assert_eq!(left.ring.members, right.ring.members);
            assert_eq!(left.next_members, right.next_members);
            let old = left.ring.members.iter().copied().collect::<HashSet<_>>();
            let next = left.next_members.iter().copied().collect::<HashSet<_>>();
            assert_eq!(old.intersection(&next).count(), 18);
            assert_eq!(old.union(&next).count(), 50);
            assert_eq!(left.ring.authorized_members.len(), 50);
            assert_eq!(left.ring.definition.operator_node_keys.len(), 51);
            assert!(left
                .ring
                .definition
                .operator_node_keys
                .contains(&CONTROLLER_PUBLIC_KEY.to_string()));
        }
    }
}
