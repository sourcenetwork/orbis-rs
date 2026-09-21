//! In-process backend: real orbis-node instances as tokio tasks over loopback
//! Iroh, backed by a shared `DummyBulletin`/`DummyAuthZ` (`crate::harness`)
//! instead of a Dockerized Vera. No Compose project, no chain setup, no metrics
//! endpoint, no resource sampling (there are no containers to sample), and
//! `pss_reshare` isn't supported (see `run_stack_in_process`). WAN profiles are
//! approximated in software by `network::ShapedNetwork`. Counterpart to
//! `docker.rs` — each `run_*_trials_in_process` method's doc comment says what's
//! omitted relative to its Docker counterpart and why.

use super::*;

impl BenchmarkRunner {
    /// In-process counterpart of `docker::run_stack_docker`: real orbis-node
    /// instances as tokio tasks over loopback Iroh, backed by a shared
    /// `DummyBulletin` instead of a Dockerized Vera. No Compose project, no
    /// chain setup, no resource sampling (there are no containers to sample).
    /// `validate()` restricts this backend to the `dkg`, `pre`, `sign`, and
    /// `pss_refresh` operations; `pss_reshare` is rejected. WAN profiles are
    /// supported and approximated in software by `network::ShapedNetwork` — see
    /// `run_dkg_trials_in_process`, `run_pre_trials_in_process`,
    /// `run_sign_trials_in_process`, and `run_pss_trials_in_process`.
    pub(super) async fn run_stack_in_process(
        &self,
        store: &mut ResultStore,
        manifest: &mut RunManifest,
        stack: &StackPlan,
        stack_id: &str,
        completed: &HashSet<TrialKey>,
        interrupt_rx: &mut watch::Receiver<bool>,
    ) -> Result<StackRunOutcome> {
        let shaping = network::NetworkShapingProfile {
            delay_ms: stack.profile.delay_ms,
            jitter_ms: stack.profile.jitter_ms,
            loss_percent: stack.profile.loss_percent,
        };
        eprintln!(
            "[{stack_id}] starting {} in-process nodes (no Docker, no chain, profile={}{})",
            stack.network_size,
            stack.profile.name,
            if shaping.is_noop() {
                String::new()
            } else {
                format!(
                    " delay={}ms jitter={}ms loss={}%",
                    shaping.delay_ms, shaping.jitter_ms, shaping.loss_percent
                )
            }
        );
        let wants_pss_refresh = self.experiment.operations.contains(&Operation::PssRefresh);
        let stack_work = async {
            let harness = HarnessNetwork::spin_up(
                stack.network_size,
                stack_id,
                shaping,
                if wants_pss_refresh {
                    self.experiment.pss_poll_interval_secs
                } else {
                    0
                },
            )
            .await?;
            eprintln!(
                "[{stack_id}] {} in-process nodes ready",
                harness.endpoints.len()
            );
            let mut clients = DirectClients::connect(&harness.endpoints).await?;
            let mut rng = StdRng::seed_from_u64(
                self.experiment.seed ^ (stack.stack_index as u64).rotate_left(17),
            );
            let mut all_cases_viable = true;
            for case in &stack.cases {
                if self.experiment.operations.contains(&Operation::Dkg) {
                    eprintln!(
                        "[{stack_id}] measuring ring={} threshold={} (in-process, dkg)",
                        case.ring_size, case.threshold
                    );
                    let viable = self
                        .run_dkg_trials_in_process(
                            &mut TrialContext {
                                store: &mut *store,
                                manifest: &*manifest,
                                stack,
                                stack_id,
                                clients: &mut clients,
                                completed,
                                rng: &mut rng,
                            },
                            &harness,
                            case,
                        )
                        .await?;
                    all_cases_viable &= viable;
                }

                let wants_online = self.experiment.operations.contains(&Operation::Pre)
                    || self.experiment.operations.contains(&Operation::Sign);
                if wants_online {
                    eprintln!(
                        "[{stack_id}] establishing online ring={} threshold={} (in-process, pre/sign)",
                        case.ring_size, case.threshold
                    );
                    let (ring_id, members, ring_pk) = establish_ring_in_process(
                        &harness,
                        &mut clients,
                        case.ring_size,
                        case.threshold,
                        stack.network_size,
                        86_400,
                        Duration::from_secs(self.experiment.timeouts.dkg_secs),
                        &mut rng,
                    )
                    .await?;
                    let fixtures = prepare_online_fixtures_in_process(
                        &harness,
                        &harness.endpoints[members[0] - 1],
                        &ring_id,
                        &ring_pk,
                        case.ring_size,
                    )
                    .await?;

                    if self.experiment.operations.contains(&Operation::Pre) {
                        let viable = self
                            .run_pre_trials_in_process(
                                &mut TrialContext {
                                    store: &mut *store,
                                    manifest: &*manifest,
                                    stack,
                                    stack_id,
                                    clients: &mut clients,
                                    completed,
                                    rng: &mut rng,
                                },
                                case,
                                &ring_id,
                                &members,
                                &fixtures.pre,
                            )
                            .await?;
                        all_cases_viable &= viable;
                    }
                    if self.experiment.operations.contains(&Operation::Sign) {
                        let viable = self
                            .run_sign_trials_in_process(
                                &mut TrialContext {
                                    store: &mut *store,
                                    manifest: &*manifest,
                                    stack,
                                    stack_id,
                                    clients: &mut clients,
                                    completed,
                                    rng: &mut rng,
                                },
                                case,
                                &ring_id,
                                &members,
                                &fixtures.sign,
                            )
                            .await?;
                        all_cases_viable &= viable;
                    }
                }

                if wants_pss_refresh {
                    eprintln!(
                        "[{stack_id}] establishing refresh ring={} threshold={} (in-process, pss_refresh)",
                        case.ring_size, case.threshold
                    );
                    let (ring_id, members, ring_pk) = establish_ring_in_process(
                        &harness,
                        &mut clients,
                        case.ring_size,
                        case.threshold,
                        stack.network_size,
                        self.experiment.pss_interval_secs,
                        Duration::from_secs(self.experiment.timeouts.dkg_secs),
                        &mut rng,
                    )
                    .await?;
                    let viable = self
                        .run_pss_trials_in_process(
                            &mut TrialContext {
                                store: &mut *store,
                                manifest: &*manifest,
                                stack,
                                stack_id,
                                clients: &mut clients,
                                completed,
                                rng: &mut rng,
                            },
                            &harness,
                            case,
                            &ring_id,
                            &members,
                            &ring_pk,
                        )
                        .await?;
                    all_cases_viable &= viable;
                }
            }
            Ok::<_, anyhow::Error>(all_cases_viable)
        };

        let stack_result = tokio::select! {
            biased;
            _ = wait_for_interrupt(interrupt_rx) => None,
            result = stack_work => Some(result),
        };

        match stack_result {
            Some(Ok(viable)) => Ok(StackRunOutcome::Completed(viable)),
            Some(Err(error)) => Err(error),
            None => {
                eprintln!("[{stack_id}] Ctrl-C received; tearing down in-process network");
                Ok(StackRunOutcome::Interrupted)
            }
        }
    }

    async fn run_dkg_trials_in_process(
        &self,
        ctx: &mut TrialContext<'_>,
        harness: &HarnessNetwork,
        case: &RingCase,
    ) -> Result<bool> {
        let mut viable = true;
        let initiator_offset = (ctx.rng.next_u64() as usize) % case.ring_size;
        for trial in 0..self.experiment.warmups + self.experiment.repetitions {
            let warmup = trial < self.experiment.warmups;
            let trial_index = trial.saturating_sub(self.experiment.warmups);
            let key = TrialKey::serial(
                ctx.stack_id,
                &ctx.stack.profile.name,
                case,
                Operation::Dkg,
                trial_index,
                warmup,
            );
            if ctx.completed.contains(&key) {
                continue;
            }
            let mut members: Vec<usize> = (1..=ctx.stack.network_size).collect();
            members.shuffle(ctx.rng);
            members.truncate(case.ring_size);
            members.sort_unstable();
            let ring_id = format!("harness-ring-{}", uuid::Uuid::new_v4());
            // Not a PSS-tested ring: a long interval keeps it effectively
            // never-due, matching Docker's DKG/online rings (`docker::plan_rings`'s
            // `make(86_400)`).
            harness.seed_pending_ring(&ring_id, &members, case.threshold, 86_400)?;
            let initiator_position = (initiator_offset + trial) % members.len();
            let initiator = members[initiator_position] - 1;
            let started_at = unix_ms();
            let started = Instant::now();
            let result = timeout(
                Duration::from_secs(self.experiment.timeouts.dkg_secs),
                async {
                    let acknowledgement = ctx.clients.start_dkg(initiator, &ring_id).await?;
                    let ring_pk = harness
                        .wait_ring_finalized_everywhere(
                            ctx.clients,
                            &ring_id,
                            &members,
                            Duration::from_secs(self.experiment.timeouts.dkg_secs),
                        )
                        .await?;
                    Ok::<_, anyhow::Error>((acknowledgement, ring_pk))
                },
            )
            .await;
            let (success, error_class, error, acknowledgement_ms, ring_pk) = match result {
                Ok(Ok((ack, ring_pk))) => (
                    true,
                    None,
                    None,
                    Some(ack.acknowledgement_ms),
                    Some(ring_pk),
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
                case: case.clone(),
                operation: Operation::Dkg,
                trial_index,
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
                ring_id: Some(ring_id),
                ring_pk,
                metric_deltas: BTreeMap::new(),
            })?;
        }
        Ok(viable)
    }

    /// In-process counterpart of `docker::run_pre_trials`: same request/
    /// measurement logic (`clients.pre` is backend-agnostic — a plain gRPC
    /// call), minus `compose.container_failures()` (no containers) and metric
    /// scraping (no Prometheus endpoint on harness nodes, see `harness.rs`).
    async fn run_pre_trials_in_process(
        &self,
        ctx: &mut TrialContext<'_>,
        case: &RingCase,
        ring_id: &str,
        members: &[usize],
        fixture: &PreFixture,
    ) -> Result<bool> {
        let mut viable = true;
        let initiator_offset = (ctx.rng.next_u64() as usize) % case.ring_size;
        for trial in 0..self.experiment.warmups + self.experiment.repetitions {
            let warmup = trial < self.experiment.warmups;
            let trial_index = trial.saturating_sub(self.experiment.warmups);
            let key = TrialKey::serial(
                ctx.stack_id,
                &ctx.stack.profile.name,
                case,
                Operation::Pre,
                trial_index,
                warmup,
            );
            if ctx.completed.contains(&key) {
                continue;
            }
            let initiator_position = (initiator_offset + trial) % members.len();
            let initiator = members[initiator_position] - 1;
            let started = Instant::now();
            let result = timeout(
                Duration::from_secs(self.experiment.timeouts.pre_secs),
                ctx.clients.pre(initiator, fixture),
            )
            .await;
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            let (success, duration_ms, client_total_ms, verification_ms, class, error) =
                match result {
                    Ok(Ok(result)) => (
                        true,
                        result.rpc_ms,
                        Some(result.total_ms),
                        Some(result.decrypt_ms),
                        None,
                        None,
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
            let mut record = base_trial_in_process(
                ctx.manifest,
                ctx.stack,
                ctx.stack_id,
                case,
                ring_id,
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
            ctx.store.append_trial(&record)?;
        }
        for (stage_index, &concurrency) in self.experiment.load.concurrency.iter().enumerate() {
            let key = TrialKey::load(
                ctx.stack_id,
                &ctx.stack.profile.name,
                case,
                Operation::Pre,
                concurrency,
            );
            if ctx.completed.contains(&key) {
                continue;
            }
            let initiator = members[(initiator_offset + stage_index) % members.len()] - 1;
            let client = ctx.clients.pre_client(initiator)?;
            run_pre_load(
                client.clone(),
                fixture.clone(),
                concurrency,
                Duration::from_secs(self.experiment.load.warmup_secs),
            )
            .await;
            let measurement = run_pre_load(
                client,
                fixture.clone(),
                concurrency,
                Duration::from_secs(self.experiment.load.measure_secs),
            )
            .await;
            viable &= measurement.failures == 0 && measurement.successes > 0;
            ctx.store.append_trial(&load_trial_in_process(
                ctx.manifest,
                ctx.stack,
                ctx.stack_id,
                case,
                ring_id,
                Operation::Pre,
                concurrency,
                measurement,
            ))?;
        }
        Ok(viable)
    }

    /// In-process counterpart of `docker::run_sign_trials` — see
    /// `run_pre_trials_in_process` for what's omitted and why.
    async fn run_sign_trials_in_process(
        &self,
        ctx: &mut TrialContext<'_>,
        case: &RingCase,
        ring_id: &str,
        members: &[usize],
        fixture: &SignFixture,
    ) -> Result<bool> {
        let mut viable = true;
        let initiator_offset = (ctx.rng.next_u64() as usize) % case.ring_size;
        for trial in 0..self.experiment.warmups + self.experiment.repetitions {
            let warmup = trial < self.experiment.warmups;
            let trial_index = trial.saturating_sub(self.experiment.warmups);
            let key = TrialKey::serial(
                ctx.stack_id,
                &ctx.stack.profile.name,
                case,
                Operation::Sign,
                trial_index,
                warmup,
            );
            if ctx.completed.contains(&key) {
                continue;
            }
            let initiator_position = (initiator_offset + trial) % members.len();
            let initiator = members[initiator_position] - 1;
            let message = format!("orbis-bench-sign-{}-{trial}", ctx.manifest.run_id).into_bytes();
            let started = Instant::now();
            let result = timeout(
                Duration::from_secs(self.experiment.timeouts.sign_secs),
                ctx.clients.sign(initiator, fixture, message),
            )
            .await;
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            let (success, duration_ms, client_total_ms, verification_ms, class, error) =
                match result {
                    Ok(Ok(result)) => (
                        true,
                        result.rpc_ms,
                        Some(result.total_ms),
                        Some(result.verification_ms),
                        None,
                        None,
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
            let mut record = base_trial_in_process(
                ctx.manifest,
                ctx.stack,
                ctx.stack_id,
                case,
                ring_id,
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
            ctx.store.append_trial(&record)?;
        }
        for (stage_index, &concurrency) in self.experiment.load.concurrency.iter().enumerate() {
            let key = TrialKey::load(
                ctx.stack_id,
                &ctx.stack.profile.name,
                case,
                Operation::Sign,
                concurrency,
            );
            if ctx.completed.contains(&key) {
                continue;
            }
            let initiator = members[(initiator_offset + stage_index) % members.len()] - 1;
            let client = ctx.clients.sign_client(initiator)?;
            run_sign_load(
                client.clone(),
                fixture.clone(),
                concurrency,
                Duration::from_secs(self.experiment.load.warmup_secs),
            )
            .await;
            let measurement = run_sign_load(
                client,
                fixture.clone(),
                concurrency,
                Duration::from_secs(self.experiment.load.measure_secs),
            )
            .await;
            viable &= measurement.failures == 0 && measurement.successes > 0;
            ctx.store.append_trial(&load_trial_in_process(
                ctx.manifest,
                ctx.stack,
                ctx.stack_id,
                case,
                ring_id,
                Operation::Sign,
                concurrency,
                measurement,
            ))?;
        }
        Ok(viable)
    }

    /// In-process counterpart of `docker::run_pss_trials`. `DirectClients::wait_pss_refresh`
    /// is already backend-agnostic (pure gRPC `GetRingState` polling), so
    /// it's reused as-is; the check that the ring's public key survived the
    /// refresh reads `harness.ring_pk(ring_id)` directly instead of
    /// `docker::read_ring_with_retry(controller, ...)`. No metrics endpoint on
    /// this backend (see `harness.rs`'s module docs), so `pss_timing` is called
    /// with `None` for the metrics-derived scheduler delay — it already
    /// falls back to the client-observed value (always `0.0` from
    /// `wait_pss_refresh`) in that case, same as Docker trials where the
    /// metric happened to be unavailable.
    async fn run_pss_trials_in_process(
        &self,
        ctx: &mut TrialContext<'_>,
        harness: &HarnessNetwork,
        case: &RingCase,
        ring_id: &str,
        members: &[usize],
        ring_pk: &str,
    ) -> Result<bool> {
        let original_ring_pk = ring_pk.to_string();
        let mut viable = true;
        for trial in 0..self.experiment.warmups + self.experiment.repetitions {
            let warmup = trial < self.experiment.warmups;
            let trial_index = trial.saturating_sub(self.experiment.warmups);
            let key = TrialKey::serial(
                ctx.stack_id,
                &ctx.stack.profile.name,
                case,
                Operation::PssRefresh,
                trial_index,
                warmup,
            );
            if ctx.completed.contains(&key) {
                continue;
            }
            let baseline = ctx.clients.ring_states(members, &original_ring_pk).await?;
            let due = baseline
                .iter()
                .map(|state| state.last_pss)
                .max()
                .unwrap_or(0)
                .saturating_add(
                    self.experiment
                        .pss_interval_secs
                        .saturating_sub(PSS_GRACE_PERIOD_SECS),
                );
            let started = Instant::now();
            let result = ctx
                .clients
                .wait_pss_refresh(
                    members,
                    &original_ring_pk,
                    &baseline,
                    due,
                    Duration::from_secs(self.experiment.timeouts.pss_refresh_secs),
                )
                .await;
            let current_ring_pk = harness.ring_pk(ring_id).await?;
            let (success, duration_ms, scheduler_delay_ms, class, error) = match result {
                Ok(measurement)
                    if current_ring_pk.as_deref() == Some(original_ring_pk.as_str()) =>
                {
                    let (ceremony_ms, scheduler_delay_ms) = pss_timing(
                        measurement.ceremony_ms,
                        measurement.scheduler_delay_ms,
                        None,
                    );
                    (true, ceremony_ms, Some(scheduler_delay_ms), None, None)
                }
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
            let mut record = base_trial_in_process(
                ctx.manifest,
                ctx.stack,
                ctx.stack_id,
                case,
                ring_id,
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
            record.ring_pk = Some(original_ring_pk.clone());
            ctx.store.append_trial(&record)?;
        }
        Ok(viable)
    }
}

/// In-process counterpart of `docker::establish_ring`: picks a fresh, random
/// `ring_size`-member committee out of the harness network, seeds it as a
/// pending ring on the shared bulletin, runs DKG, and waits for it to
/// converge. Always fresh (unlike `establish_ring`, which reuses an
/// already-finalized on-chain ring across a resumed run) since in-process
/// state is ephemeral per run to begin with. Returns `(ring_id, members,
/// ring_pk)`.
async fn establish_ring_in_process(
    harness: &HarnessNetwork,
    clients: &mut DirectClients,
    ring_size: usize,
    threshold: usize,
    network_size: usize,
    pss_interval_secs: u64,
    deadline: Duration,
    rng: &mut StdRng,
) -> Result<(String, Vec<usize>, String)> {
    let mut members: Vec<usize> = (1..=network_size).collect();
    members.shuffle(rng);
    members.truncate(ring_size);
    members.sort_unstable();
    let ring_id = format!("harness-ring-{}", uuid::Uuid::new_v4());
    harness.seed_pending_ring(&ring_id, &members, threshold, pss_interval_secs)?;
    let initiator = members[(rng.next_u64() as usize) % members.len()] - 1;
    clients.start_dkg(initiator, &ring_id).await?;
    let ring_pk = harness
        .wait_ring_finalized_everywhere(clients, &ring_id, &members, deadline)
        .await?;
    Ok((ring_id, members, ring_pk))
}

/// In-process counterpart of `docker::prepare_online_fixtures`. `prepare_secret`
/// and `store_prepared_secret` are already chain-independent (local encryption +
/// a direct `StoreSecretService` gRPC call), so they're reused as-is; the
/// chain-only ACP registration calls (`register_object_to_chain_with_config`,
/// `set_relationship_on_chain_with_config`, `add_policy_to_chain_with_config`)
/// are dropped entirely rather than replaced — see `harness.rs`'s module docs
/// for why `DummyAuthZ` makes them unnecessary — and
/// `post_key_derivation_with_config` is replaced by
/// `HarnessNetwork::post_key_derivation`, which posts to the shared bulletin
/// directly instead of building a real chain client.
async fn prepare_online_fixtures_in_process(
    harness: &HarnessNetwork,
    endpoint: &NodeEndpoint,
    ring_id: &str,
    ring_pk: &str,
    ring_size: usize,
) -> Result<OnlineFixtures> {
    let policy_id = HARNESS_POLICY_ID.to_string();
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

    let sign_identity = format!("orbis-bench-signer-{ring_size}");
    let (derivation_id, derived_public_key) = harness
        .post_key_derivation(
            ring_id,
            ring_pk,
            &format!("benchmark-sign-derivation-{ring_size}"),
            &policy_id,
            &resource,
            &permission,
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
