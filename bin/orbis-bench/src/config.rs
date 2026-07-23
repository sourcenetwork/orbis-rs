use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_LOCAL_RINGS_PER_NODE: usize = 256;
/// Mirrors the production scheduler's early-due grace window. Benchmark PSS
/// intervals must exceed it so due-to-start and ceremony time remain separable.
pub const PSS_GRACE_PERIOD_SECS: u64 = 10;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoFeature {
    Bls12_381,
    Decaf377,
}

impl CryptoFeature {
    pub fn compiled() -> Self {
        #[cfg(feature = "bls12-381")]
        {
            Self::Bls12_381
        }
        #[cfg(feature = "decaf377")]
        {
            Self::Decaf377
        }
    }

    pub fn feature_name(self) -> &'static str {
        match self {
            Self::Bls12_381 => "bls12-381",
            Self::Decaf377 => "decaf377",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Dkg,
    Pre,
    Sign,
    PssRefresh,
    PssReshare,
}

fn default_operations() -> BTreeSet<Operation> {
    [
        Operation::Dkg,
        Operation::Pre,
        Operation::Sign,
        Operation::PssRefresh,
    ]
    .into_iter()
    .collect()
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProfileKind {
    Lan,
    Wan,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProfile {
    pub name: String,
    pub kind: NetworkProfileKind,
    #[serde(default)]
    pub delay_ms: f64,
    #[serde(default)]
    pub jitter_ms: f64,
    #[serde(default)]
    pub loss_percent: f64,
}

impl NetworkProfile {
    pub fn lan() -> Self {
        Self {
            name: "lan".to_string(),
            kind: NetworkProfileKind::Lan,
            delay_ms: 0.0,
            jitter_ms: 0.0,
            loss_percent: 0.0,
        }
    }

    pub fn wan_50ms() -> Self {
        Self {
            name: "wan-50ms".to_string(),
            kind: NetworkProfileKind::Wan,
            delay_ms: 25.0,
            jitter_ms: 5.0,
            loss_percent: 0.1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RingCase {
    pub ring_size: usize,
    pub threshold: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkGroup {
    pub network_size: usize,
    pub cases: Vec<RingCase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoadConfig {
    pub concurrency: Vec<usize>,
    pub warmup_secs: u64,
    pub measure_secs: u64,
}

impl Default for LoadConfig {
    fn default() -> Self {
        Self {
            concurrency: vec![1, 4, 16],
            warmup_secs: 10,
            measure_secs: 30,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimeoutConfig {
    pub setup_secs: u64,
    pub dkg_secs: u64,
    pub pre_secs: u64,
    pub sign_secs: u64,
    pub pss_refresh_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            setup_secs: 30 * 60,
            dkg_secs: 15 * 60,
            pre_secs: 2 * 60,
            sign_secs: 2 * 60,
            pss_refresh_secs: 15 * 60,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceLimits {
    pub cpus_per_node: Option<f64>,
    pub memory_per_node: Option<String>,
}

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}
fn default_name() -> String {
    "orbis-capacity".to_string()
}
fn default_repetitions() -> usize {
    5
}
fn default_warmups() -> usize {
    1
}
fn default_seed() -> u64 {
    0x0b15_beec_u64
}
fn default_output_dir() -> PathBuf {
    PathBuf::from("bench-results")
}
fn default_sourcehub_ref() -> String {
    "392d69c6f8c10c2f9f9bf45eda882d2da2ab854c".to_string()
}
fn default_batch_size() -> usize {
    25
}
fn default_pss_interval() -> u64 {
    15
}
fn default_pss_poll_interval() -> u64 {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Experiment {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default = "default_name")]
    pub name: String,
    pub crypto: CryptoFeature,
    pub networks: Vec<NetworkGroup>,
    #[serde(default = "default_operations")]
    pub operations: BTreeSet<Operation>,
    #[serde(default = "default_profiles")]
    pub profiles: Vec<NetworkProfile>,
    #[serde(default = "default_repetitions")]
    pub repetitions: usize,
    #[serde(default = "default_warmups")]
    pub warmups: usize,
    #[serde(default = "default_seed")]
    pub seed: u64,
    #[serde(default)]
    pub load: LoadConfig,
    #[serde(default)]
    pub timeouts: TimeoutConfig,
    #[serde(default)]
    pub resources: ResourceLimits,
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    #[serde(default = "default_sourcehub_ref")]
    pub sourcehub_ref: String,
    #[serde(default = "default_batch_size")]
    pub setup_batch_size: usize,
    #[serde(default = "default_pss_interval")]
    pub pss_interval_secs: u64,
    #[serde(default = "default_pss_poll_interval")]
    pub pss_poll_interval_secs: u64,
    /// Number of nodes shared by the current and next committees for a
    /// `pss_reshare` trial. Reshare is opt-in and therefore has no default.
    #[serde(default)]
    pub reshare_overlap: Option<usize>,
}

fn default_profiles() -> Vec<NetworkProfile> {
    vec![NetworkProfile::lan(), NetworkProfile::wan_50ms()]
}

impl Experiment {
    pub fn from_yaml(path: &Path) -> Result<Self> {
        let bytes =
            fs::read(path).with_context(|| format!("read experiment config {}", path.display()))?;
        let experiment: Self = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("parse experiment config {}", path.display()))?;
        experiment.validate()?;
        Ok(experiment)
    }

    pub fn single(network_size: usize, ring_size: usize, threshold: usize) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            name: format!("orbis-{network_size}n-{ring_size}r-{threshold}t"),
            crypto: CryptoFeature::compiled(),
            networks: vec![NetworkGroup {
                network_size,
                cases: vec![RingCase {
                    ring_size,
                    threshold,
                }],
            }],
            operations: default_operations(),
            profiles: default_profiles(),
            repetitions: default_repetitions(),
            warmups: default_warmups(),
            seed: default_seed(),
            load: LoadConfig::default(),
            timeouts: TimeoutConfig::default(),
            resources: ResourceLimits::default(),
            output_dir: default_output_dir(),
            sourcehub_ref: default_sourcehub_ref(),
            setup_batch_size: default_batch_size(),
            pss_interval_secs: default_pss_interval(),
            pss_poll_interval_secs: default_pss_poll_interval(),
            reshare_overlap: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!(
                "unsupported schema_version {}; expected {}",
                self.schema_version,
                SCHEMA_VERSION
            );
        }
        if self.crypto != CryptoFeature::compiled() {
            bail!(
                "config requests crypto '{}' but this binary was compiled for '{}'",
                self.crypto.feature_name(),
                CryptoFeature::compiled().feature_name()
            );
        }
        if self.name.trim().is_empty() {
            bail!("experiment name cannot be empty");
        }
        if self.networks.is_empty() {
            bail!("at least one network group is required");
        }
        if self.profiles.is_empty() {
            bail!("at least one network profile is required");
        }
        if self.operations.is_empty() {
            bail!("at least one operation is required");
        }
        if self.repetitions == 0 {
            bail!("repetitions must be at least 1");
        }
        if self.setup_batch_size == 0 {
            bail!("setup_batch_size must be at least 1");
        }
        if self.load.measure_secs == 0 {
            bail!("load.measure_secs must be at least 1");
        }
        if [
            self.timeouts.setup_secs,
            self.timeouts.dkg_secs,
            self.timeouts.pre_secs,
            self.timeouts.sign_secs,
            self.timeouts.pss_refresh_secs,
        ]
        .contains(&0)
        {
            bail!("all timeout values must be at least 1 second");
        }
        if self.pss_poll_interval_secs == 0 {
            bail!("pss_poll_interval_secs must be at least 1");
        }
        if self.operations.contains(&Operation::PssRefresh)
            && self.pss_interval_secs <= PSS_GRACE_PERIOD_SECS
        {
            bail!(
                "pss_interval_secs must exceed the production scheduler grace window ({PSS_GRACE_PERIOD_SECS}s)"
            );
        }
        if self.operations.contains(&Operation::PssReshare) && self.reshare_overlap.is_none() {
            bail!("pss_reshare experiments require reshare_overlap");
        }
        if self.rings_per_case() > MAX_LOCAL_RINGS_PER_NODE {
            bail!(
                "one case requires {} local ring slots, exceeding MAX_LOCAL_RINGS_PER_NODE ({MAX_LOCAL_RINGS_PER_NODE})",
                self.rings_per_case()
            );
        }
        if self
            .resources
            .cpus_per_node
            .is_some_and(|cpus| !cpus.is_finite() || cpus <= 0.0)
        {
            bail!("resources.cpus_per_node must be finite and greater than zero");
        }
        if self
            .resources
            .memory_per_node
            .as_ref()
            .is_some_and(|memory| memory.trim().is_empty())
        {
            bail!("resources.memory_per_node cannot be empty");
        }
        let mut profile_names = BTreeSet::new();
        for profile in &self.profiles {
            if profile.name.trim().is_empty() || !profile_names.insert(profile.name.clone()) {
                bail!("network profile names must be non-empty and unique");
            }
            if !profile.delay_ms.is_finite()
                || !profile.jitter_ms.is_finite()
                || !profile.loss_percent.is_finite()
            {
                bail!("profile '{}' shaping values must be finite", profile.name);
            }
            if profile.delay_ms < 0.0 || profile.jitter_ms < 0.0 {
                bail!("profile '{}' has a negative delay or jitter", profile.name);
            }
            if !(0.0..=100.0).contains(&profile.loss_percent) {
                bail!("profile '{}' loss_percent must be in 0..=100", profile.name);
            }
            if profile.kind == NetworkProfileKind::Lan
                && (profile.delay_ms != 0.0
                    || profile.jitter_ms != 0.0
                    || profile.loss_percent != 0.0)
            {
                bail!(
                    "LAN profile '{}' cannot contain shaping values",
                    profile.name
                );
            }
        }
        if (self.operations.contains(&Operation::Pre) || self.operations.contains(&Operation::Sign))
            && self.load.concurrency.is_empty()
        {
            bail!("PRE or SIGN experiments require at least one load concurrency");
        }
        for (group_index, group) in self.networks.iter().enumerate() {
            if group.network_size == 0 {
                bail!("network group {group_index} has network_size 0");
            }
            if group.cases.is_empty() {
                bail!("network group {group_index} has no ring cases");
            }
            for case in &group.cases {
                if case.ring_size == 0 || case.ring_size > group.network_size {
                    bail!(
                        "ring size {} must be in 1..={} for network group {}",
                        case.ring_size,
                        group.network_size,
                        group_index
                    );
                }
                if case.threshold == 0 || case.threshold > case.ring_size {
                    bail!(
                        "threshold {} must be in 1..={} for ring size {}",
                        case.threshold,
                        case.ring_size,
                        case.ring_size
                    );
                }
                if self.operations.contains(&Operation::PssReshare) {
                    let overlap = self
                        .reshare_overlap
                        .expect("reshare_overlap was validated above");
                    if overlap > case.ring_size {
                        bail!(
                            "reshare_overlap {overlap} cannot exceed ring size {}",
                            case.ring_size
                        );
                    }
                    let union_size = case.ring_size.saturating_mul(2).saturating_sub(overlap);
                    if union_size > group.network_size {
                        bail!(
                            "reshare old/new union requires {union_size} nodes (ring size {}, overlap {overlap}) but network group {group_index} has {}",
                            case.ring_size,
                            group.network_size
                        );
                    }
                }
            }
        }
        for concurrency in &self.load.concurrency {
            if *concurrency == 0 {
                bail!("load concurrency values must be at least 1");
            }
        }
        Ok(())
    }

    pub fn resolve(&self) -> Result<ExperimentPlan> {
        self.validate()?;
        let ring_slots = self.rings_per_case();
        let mut stacks = Vec::new();
        for group in &self.networks {
            for profile in &self.profiles {
                let mut batch = Vec::new();
                let mut batch_rings = 0usize;
                for case in &group.cases {
                    if !batch.is_empty() && batch_rings + ring_slots > MAX_LOCAL_RINGS_PER_NODE {
                        stacks.push(StackPlan::new(
                            group.network_size,
                            profile.clone(),
                            std::mem::take(&mut batch),
                            batch_rings,
                        ));
                        batch_rings = 0;
                    }
                    batch.push(case.clone());
                    batch_rings += ring_slots;
                }
                if !batch.is_empty() {
                    stacks.push(StackPlan::new(
                        group.network_size,
                        profile.clone(),
                        batch,
                        batch_rings,
                    ));
                }
            }
        }
        Ok(self.plan_from_stacks(stacks, ring_slots))
    }

    /// Resolve an advancing capacity sweep into one fresh stack per
    /// `(network size, ring case, profile)`. Keeping the profiles for each ring
    /// adjacent lets the runner decide viability for a size before provisioning
    /// the next size.
    pub fn resolve_capacity_sweep(&self) -> Result<ExperimentPlan> {
        self.validate()?;
        let ring_slots = self.rings_per_case();
        let mut stacks = Vec::new();
        for group in &self.networks {
            for case in &group.cases {
                for profile in &self.profiles {
                    stacks.push(StackPlan::new(
                        group.network_size,
                        profile.clone(),
                        vec![case.clone()],
                        ring_slots,
                    ));
                }
            }
        }
        Ok(self.plan_from_stacks(stacks, ring_slots))
    }

    fn plan_from_stacks(&self, stacks: Vec<StackPlan>, ring_slots: usize) -> ExperimentPlan {
        let serial_trials = stacks
            .iter()
            .map(|stack| {
                stack.cases.len() * self.operations.len() * (self.warmups + self.repetitions)
            })
            .sum();
        let load_seconds = if self.operations.contains(&Operation::Pre)
            || self.operations.contains(&Operation::Sign)
        {
            let online_operations = usize::from(self.operations.contains(&Operation::Pre))
                + usize::from(self.operations.contains(&Operation::Sign));
            stacks
                .iter()
                .map(|stack| {
                    stack.cases.len()
                        * online_operations
                        * self.load.concurrency.len()
                        * (self.load.warmup_secs + self.load.measure_secs) as usize
                })
                .sum()
        } else {
            0
        };
        ExperimentPlan {
            stacks,
            rings_per_case: ring_slots,
            serial_trials,
            estimated_minimum_secs: serial_trials as u64 + load_seconds as u64,
        }
    }

    pub fn rings_per_case(&self) -> usize {
        let dkg_rings = if self.operations.contains(&Operation::Dkg) {
            self.warmups + self.repetitions
        } else {
            0
        };
        let needs_online_ring =
            self.operations.contains(&Operation::Pre) || self.operations.contains(&Operation::Sign);
        let needs_refresh_ring = self.operations.contains(&Operation::PssRefresh);
        let reshare_rings = if self.operations.contains(&Operation::PssReshare) {
            self.warmups + self.repetitions
        } else {
            0
        };
        dkg_rings + usize::from(needs_online_ring) + usize::from(needs_refresh_ring) + reshare_rings
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StackPlan {
    pub stack_index: usize,
    pub network_size: usize,
    pub profile: NetworkProfile,
    pub cases: Vec<RingCase>,
    pub maximum_local_rings: usize,
}

impl StackPlan {
    fn new(
        network_size: usize,
        profile: NetworkProfile,
        cases: Vec<RingCase>,
        maximum_local_rings: usize,
    ) -> Self {
        Self {
            stack_index: 0,
            network_size,
            profile,
            cases,
            maximum_local_rings,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ExperimentPlan {
    pub stacks: Vec<StackPlan>,
    pub rings_per_case: usize,
    pub serial_trials: usize,
    pub estimated_minimum_secs: u64,
}

impl ExperimentPlan {
    pub fn assign_indices(&mut self) {
        for (index, stack) in self.stacks.iter_mut().enumerate() {
            stack.stack_index = index;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_ring_threshold_and_network_relationship() {
        let mut experiment = Experiment::single(3, 3, 2);
        experiment.networks[0].cases[0].ring_size = 4;
        assert!(experiment.validate().is_err());
        experiment.networks[0].cases[0].ring_size = 3;
        experiment.networks[0].cases[0].threshold = 4;
        assert!(experiment.validate().is_err());
    }

    #[test]
    fn partitions_sweeps_before_local_ring_limit() {
        let mut experiment = Experiment::single(50, 3, 2);
        experiment.profiles = vec![NetworkProfile::lan()];
        experiment.networks[0].cases = (3..=50)
            .map(|ring_size| RingCase {
                ring_size,
                threshold: (2 * ring_size).div_ceil(3),
            })
            .collect();
        let plan = experiment.resolve().unwrap();
        assert!(plan.stacks.len() > 1);
        assert!(plan
            .stacks
            .iter()
            .all(|stack| stack.maximum_local_rings <= MAX_LOCAL_RINGS_PER_NODE));
    }

    #[test]
    fn default_case_has_two_profiles_and_all_core_operations() {
        let experiment = Experiment::single(50, 10, 7);
        assert_eq!(experiment.profiles.len(), 2);
        assert_eq!(experiment.operations.len(), 4);
        assert_eq!(experiment.repetitions, 5);
    }

    #[test]
    fn capacity_sweep_pairs_profiles_before_advancing_ring_size() {
        let mut experiment = Experiment::single(10, 3, 2);
        experiment.networks[0].cases.push(RingCase {
            ring_size: 5,
            threshold: 4,
        });
        let plan = experiment.resolve_capacity_sweep().unwrap();
        let sizes: Vec<_> = plan
            .stacks
            .iter()
            .map(|stack| stack.cases[0].ring_size)
            .collect();
        assert_eq!(sizes, vec![3, 3, 5, 5]);
        assert!(plan.stacks.iter().all(|stack| stack.cases.len() == 1));
    }

    #[test]
    fn reshare_requires_a_feasible_explicit_overlap() {
        let mut experiment = Experiment::single(50, 34, 23);
        experiment.operations = BTreeSet::from([Operation::PssReshare]);
        assert!(experiment.validate().is_err());

        experiment.reshare_overlap = Some(17);
        assert!(experiment.validate().is_err(), "34 + 34 - 17 exceeds 50");

        experiment.reshare_overlap = Some(18);
        assert!(experiment.validate().is_ok());
        assert_eq!(experiment.rings_per_case(), 6);

        experiment.reshare_overlap = Some(35);
        assert!(experiment.validate().is_err());
    }
}
