use crate::config::Operation;
use crate::results::{read_trials, summarize, RunManifest, SummaryRow, TrialRecord};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub fn generate_report(run_dir: &Path) -> Result<()> {
    let manifest: RunManifest = serde_json::from_slice(
        &fs::read(run_dir.join("manifest.json")).context("read report manifest")?,
    )?;
    let trials = read_trials(run_dir)?;
    let mut summary = summarize(&trials);
    for row in &mut summary {
        let expected = if row.concurrency.is_some() {
            1
        } else {
            manifest.experiment.repetitions
        };
        row.viable &= row.trials == expected;
    }
    let resources = read_resource_summary(&run_dir.join("resource-samples.csv"))?;
    let html = render_report(&manifest, &trials, &summary, &resources);
    fs::write(run_dir.join("report.html"), html)?;
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct ResourceSummary {
    sample_count: usize,
    peak_aggregate_rss_bytes: u64,
    peak_aggregate_cpu_percent: f64,
    cpu_seconds: f64,
    network_rx_bytes: u64,
    network_tx_bytes: u64,
}

fn read_resource_summary(path: &Path) -> Result<ResourceSummary> {
    if !path.exists() {
        return Ok(ResourceSummary::default());
    }
    let mut by_stack_timestamp: BTreeMap<(String, u128), (u64, f64)> = BTreeMap::new();
    let mut network_by_container: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for line in fs::read_to_string(path)?.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 10 {
            continue;
        }
        let timestamp = fields[2].parse().unwrap_or(0);
        let cpu = fields[5].parse().unwrap_or(0.0);
        let rss = fields[6].parse().unwrap_or(0);
        let entry = by_stack_timestamp
            .entry((fields[1].to_string(), timestamp))
            .or_default();
        entry.0 += rss;
        entry.1 += cpu;
        let network = network_by_container
            .entry(format!("{}/{}", fields[1], fields[4]))
            .or_default();
        network.0 = network.0.max(fields[8].parse().unwrap_or(0));
        network.1 = network.1.max(fields[9].parse().unwrap_or(0));
    }
    let mut cpu_seconds = 0.0;
    let mut previous_by_stack: BTreeMap<&str, (u128, f64)> = BTreeMap::new();
    for ((stack, timestamp), (_, cpu_percent)) in &by_stack_timestamp {
        if let Some((previous_timestamp, previous_cpu)) = previous_by_stack.get(stack.as_str()) {
            cpu_seconds += previous_cpu / 100.0
                * timestamp.saturating_sub(*previous_timestamp) as f64
                / 1_000.0;
        }
        previous_by_stack.insert(stack, (*timestamp, *cpu_percent));
    }
    Ok(ResourceSummary {
        sample_count: by_stack_timestamp.len(),
        peak_aggregate_rss_bytes: by_stack_timestamp
            .values()
            .map(|value| value.0)
            .max()
            .unwrap_or(0),
        peak_aggregate_cpu_percent: by_stack_timestamp
            .values()
            .map(|value| value.1)
            .fold(0.0, f64::max),
        cpu_seconds,
        network_rx_bytes: network_by_container.values().map(|value| value.0).sum(),
        network_tx_bytes: network_by_container.values().map(|value| value.1).sum(),
    })
}

fn render_report(
    manifest: &RunManifest,
    trials: &[TrialRecord],
    rows: &[SummaryRow],
    resources: &ResourceSummary,
) -> String {
    let measured: Vec<&TrialRecord> = trials.iter().filter(|trial| !trial.warmup).collect();
    let successes = measured.iter().filter(|trial| trial.success).count();
    let ceremony_rows: Vec<&SummaryRow> = rows
        .iter()
        .filter(|row| row.concurrency.is_none())
        .collect();
    let load_rows: Vec<&SummaryRow> = rows
        .iter()
        .filter(|row| row.concurrency.is_some())
        .collect();
    let mut warnings = manifest.warnings.clone();
    if ceremony_rows
        .iter()
        .any(|row| row.trials < manifest.experiment.repetitions)
    {
        warnings.push("One or more serial cases have fewer measured trials than requested; the sweep is incomplete.".into());
    }
    if manifest.experiment.repetitions < 5 {
        warnings.push(
            "Small sample count: use more repetitions before making reliability or SLA claims."
                .into(),
        );
    }
    if resources.peak_aggregate_cpu_percent > manifest.host.cpu_count as f64 * 85.0 {
        warnings.push("The host approached CPU saturation; latency may primarily reflect local scheduling contention.".into());
    }
    if docker_memory_bytes(manifest)
        .is_some_and(|total| resources.peak_aggregate_rss_bytes as f64 > total as f64 * 0.85)
    {
        warnings.push("The benchmark approached the Docker memory allocation; latency and viability may be memory-constrained.".into());
    }
    warnings.push("WAN results are single-host UDP egress emulation, not measurements across independent machines or Internet routes.".into());

    let mut html = String::with_capacity(64 * 1024);
    html.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    html.push_str("<title>Orbis benchmark report</title><style>");
    html.push_str(CSS);
    html.push_str("</style></head><body><main>");
    write!(html, "<header><p class=\"eyebrow\">ORBIS NETWORK CAPACITY</p><h1>{}</h1><p class=\"lead\">Observed behavior on the recorded host—not a universal protocol maximum.</p><div class=\"meta\"><span>Run {}</span><span>Crypto {}</span><span>Seed {}</span><span>Status {:?}</span></div></header>", escape(&manifest.experiment.name), escape(&manifest.run_id), escape(&manifest.crypto_implementation), manifest.experiment.seed, manifest.status).ok();
    html.push_str("<section class=\"cards\">");
    stat_card(
        &mut html,
        "Measured trials",
        &measured.len().to_string(),
        "warm-ups excluded",
    );
    stat_card(
        &mut html,
        "Passed",
        &successes.to_string(),
        &format!("{:.1}%", percent(successes, measured.len())),
    );
    stat_card(
        &mut html,
        "Peak aggregate RSS",
        &human_bytes(resources.peak_aggregate_rss_bytes),
        &format!("{} resource snapshots", resources.sample_count),
    );
    stat_card(
        &mut html,
        "Peak aggregate CPU",
        &format!("{:.0}%", resources.peak_aggregate_cpu_percent),
        "Docker one-second samples",
    );
    stat_card(
        &mut html,
        "Approx. CPU-seconds",
        &format!("{:.1}", resources.cpu_seconds),
        "integrated Docker CPU samples",
    );
    stat_card(
        &mut html,
        "Container network I/O",
        &format!(
            "{} ↓ / {} ↑",
            human_bytes(resources.network_rx_bytes),
            human_bytes(resources.network_tx_bytes)
        ),
        "maximum cumulative counters",
    );
    html.push_str("</section>");

    html.push_str("<section><h2>Ceremony duration by scale</h2><p>Time on the X axis, scale on the Y axis, one line per network profile connecting the median at each size. Range bars show min/max, the filled dot is the median, faint dots are individual measured trials. DKG needs every ring member, so it scales with ring size; PRE and Sign only need a threshold of shares, so they scale with threshold.</p>");
    html.push_str("<h3>DKG</h3>");
    html.push_str(&scale_chart(
        trials,
        rows,
        Operation::Dkg,
        "Ring size",
        false,
        |row| row.ring_size,
    ));
    html.push_str("<h3>PRE</h3>");
    html.push_str(&scale_chart(
        trials,
        rows,
        Operation::Pre,
        "Threshold",
        false,
        |row| row.threshold,
    ));
    html.push_str("<h3>Sign</h3>");
    html.push_str(&scale_chart(
        trials,
        rows,
        Operation::Sign,
        "Threshold",
        false,
        |row| row.threshold,
    ));
    html.push_str("</section>");

    html.push_str("<section><h2>Closed-loop latency by concurrency</h2><p>Same layout, but the range bar spans p50\u{2192}p95 latency (tooltip has p50/p95/p99/throughput) instead of min/max duration, since a load trial measures a fixed window of many requests rather than one ceremony.</p>");
    html.push_str("<h3>PRE</h3>");
    html.push_str(&scale_chart(
        trials,
        rows,
        Operation::Pre,
        "Concurrency",
        true,
        |row| row.concurrency.unwrap_or(0),
    ));
    html.push_str("<h3>Sign</h3>");
    html.push_str(&scale_chart(
        trials,
        rows,
        Operation::Sign,
        "Concurrency",
        true,
        |row| row.concurrency.unwrap_or(0),
    ));
    html.push_str("</section>");

    html.push_str("<section><h2>Capacity result</h2><p>The largest ring below is the largest <em>all-pass ring observed</em> under that exact profile and operation.</p><div class=\"table-wrap\"><table><thead><tr><th>Profile</th><th>Operation</th><th>Largest viable ring</th><th>Network</th><th>Threshold</th></tr></thead><tbody>");
    for capacity in largest_viable(rows, manifest.experiment.operations.len()) {
        write!(html, "<tr><td>{}</td><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>", escape(&capacity.profile), escape(&capacity.operation), capacity.ring_size, capacity.network_size, capacity.threshold).ok();
    }
    html.push_str("</tbody></table></div></section>");

    html.push_str("<section><h2>Ceremony detail</h2><p>Exact per-case medians. Timeouts remain failures and are shown separately below.</p><div class=\"table-wrap\"><table><thead><tr><th>Profile</th><th>Network</th><th>Ring</th><th>Threshold</th><th>Operation</th><th>Primary median (s)</th><th>Client total median (s)</th><th>Decrypt/verify median (s)</th><th>Acknowledgement median (s)</th><th>Scheduler delay median (s)</th></tr></thead><tbody>");
    for row in &ceremony_rows {
        write!(html, "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{:?}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>", escape(&row.profile), row.network_size, row.ring_size, row.threshold, row.operation, fmt_seconds(row.median_ms), fmt_seconds(row.client_total_median_ms), fmt_seconds(row.verification_median_ms), fmt_seconds(row.acknowledgement_median_ms), fmt_seconds(row.scheduler_delay_median_ms)).ok();
    }
    html.push_str("</tbody></table></div>");
    html.push_str("</section>");

    html.push_str("<section><h2>PRE and SIGN closed-loop load</h2><div class=\"table-wrap\"><table><thead><tr><th>Profile</th><th>Network</th><th>Ring</th><th>Threshold</th><th>Operation</th><th>Concurrency</th><th>Throughput/s</th><th>p50 (s)</th><th>p95 (s)</th><th>p99 (s)</th><th>All pass</th></tr></thead><tbody>");
    for row in load_rows {
        write!(html, "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{:?}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{}</td></tr>", escape(&row.profile), row.network_size, row.ring_size, row.threshold, row.operation, row.concurrency.unwrap_or(0), fmt(row.throughput_per_sec), fmt_seconds(row.p50_ms), fmt_seconds(row.p95_ms), fmt_seconds(row.p99_ms), pass_badge(row.viable)).ok();
    }
    html.push_str("</tbody></table></div></section>");

    html.push_str("<section><h2>Success and timeouts</h2>");
    html.push_str(&success_chart(rows, trials));
    html.push_str("</section>");

    let metric_totals = aggregate_metric_deltas(trials);
    html.push_str("<details><summary>Advanced / raw evidence</summary>");
    html.push_str("<section><h2>DKG and PSS phase breakdown</h2><div class=\"table-wrap\"><table><thead><tr><th>Ceremony</th><th>Phase</th><th>Node observations</th><th>Average node phase (s)</th><th>Aggregate node-time (s)</th></tr></thead><tbody>");
    for phase in phase_breakdown(&metric_totals) {
        write!(html, "<tr><td>{}</td><td>{}</td><td class=\"num\">{:.0}</td><td class=\"num\">{:.3}</td><td class=\"num\">{:.3}</td></tr>", escape(&phase.kind), escape(&phase.phase), phase.count, phase.average_ms / 1000.0, phase.total_ms / 1000.0).ok();
    }
    html.push_str("</tbody></table></div></section>");

    html.push_str("<section><h2>DKG transport evidence</h2><div class=\"table-wrap\"><table><thead><tr><th>Plane</th><th>Measurement</th><th>Labels</th><th>Value</th></tr></thead><tbody>");
    let mut transport_rows = dkg_transport_evidence(&metric_totals);
    transport_rows.extend(missing_topology_evidence(trials));
    if transport_rows.is_empty() {
        html.push_str("<tr><td colspan=\"4\" class=\"empty\">No DKG transport metrics were recorded.</td></tr>");
    } else {
        for row in transport_rows {
            write!(
                html,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"num\">{}</td></tr>",
                escape(&row.plane),
                escape(&row.measurement),
                escape(&row.labels),
                escape(&row.value)
            )
            .ok();
        }
    }
    html.push_str("</tbody></table></div><p class=\"note\">Counters and histogram observations are exact before/after deltas summed across trials. Active-connection and neighbor gauges are reported as end-minus-start deltas; use node scrapes for point-in-time values.</p></section>");

    html.push_str("<section><h2>Protocol and resource evidence</h2><div class=\"split\"><div><h3>Metric deltas</h3><div class=\"table-wrap compact\"><table><thead><tr><th>Metric</th><th>Total delta</th></tr></thead><tbody>");
    for (metric, value) in metric_totals.iter().take(30) {
        write!(
            html,
            "<tr><td><code>{}</code></td><td class=\"num\">{:.3}</td></tr>",
            escape(metric),
            value
        )
        .ok();
    }
    html.push_str("</tbody></table></div></div><div><h3>Environment</h3><dl>");
    definition(
        &mut html,
        "Git commit",
        manifest.host.git_commit.as_deref().unwrap_or("unknown"),
    );
    definition(
        &mut html,
        "Git dirty",
        &manifest
            .host
            .git_dirty
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".into()),
    );
    definition(
        &mut html,
        "OS / architecture",
        &format!("{} / {}", manifest.host.os, manifest.host.architecture),
    );
    definition(&mut html, "Host CPUs", &manifest.host.cpu_count.to_string());
    definition(
        &mut html,
        "CPU model",
        manifest.host.cpu_model.as_deref().unwrap_or("not recorded"),
    );
    definition(
        &mut html,
        "Host memory",
        &manifest
            .host
            .host_memory_bytes
            .map(human_bytes)
            .unwrap_or_else(|| "not recorded".into()),
    );
    definition(
        &mut html,
        "Available disk at start",
        &manifest
            .host
            .disk_available_bytes
            .map(human_bytes)
            .unwrap_or_else(|| "not recorded".into()),
    );
    definition(
        &mut html,
        "Node image digest",
        manifest.node_image.as_deref().unwrap_or("not recorded"),
    );
    definition(
        &mut html,
        "SourceHub image digest",
        manifest
            .sourcehub_image
            .as_deref()
            .unwrap_or("not recorded"),
    );
    definition(&mut html, "SourceHub ref", &manifest.sourcehub_ref);
    definition(
        &mut html,
        "P2P messages (counter delta)",
        &format!(
            "{:.0}",
            (metric_prefix_total(&metric_totals, "p2p_messages_")
                + metric_prefix_total(&metric_totals, "network_messages_"))
            .max(0.0)
        ),
    );
    definition(
        &mut html,
        "P2P bytes (counter delta)",
        &human_bytes(
            (metric_prefix_total(&metric_totals, "p2p_bytes_")
                + metric_prefix_total(&metric_totals, "network_bytes_"))
            .max(0.0) as u64,
        ),
    );
    html.push_str("</dl></div></div></section>");
    html.push_str("</details>");

    html.push_str("<section class=\"warnings\"><h2>Interpretation warnings</h2><ul>");
    warnings.sort();
    warnings.dedup();
    for warning in warnings {
        write!(html, "<li>{}</li>", escape(&truncate_error(&warning))).ok();
    }
    html.push_str("</ul></section>");
    html.push_str("<footer>Raw evidence: manifest.json · trials.jsonl · setup-failures.jsonl · summary.csv · resource-samples.csv · resolved Compose/genesis · failure logs</footer></main></body></html>");
    html
}

/// A resolved (min, median, max) triple in milliseconds for one chart row,
/// plus an optional list of individual-trial x-positions (in seconds) to
/// scatter near the row. Ceremony rows plot real min/median/max durations
/// with every measured trial as a point; load rows have no single
/// "duration" (they run a fixed measurement window), so they plot
/// p50→p95 as the range with p50 as the marker, and skip the scatter.
struct RowMetrics {
    min_ms: f64,
    median_ms: f64,
    max_ms: f64,
    detail: String,
    scatter_seconds: Vec<f64>,
}

fn ceremony_metrics(row: &SummaryRow, trials: &[TrialRecord]) -> Option<RowMetrics> {
    let (min_ms, median_ms, max_ms) = (row.min_ms?, row.median_ms?, row.max_ms?);
    Some(RowMetrics {
        min_ms,
        median_ms,
        max_ms,
        detail: format!(
            "median {:.2}s (min {:.2}s, max {:.2}s)",
            median_ms / 1000.0,
            min_ms / 1000.0,
            max_ms / 1000.0
        ),
        scatter_seconds: trials
            .iter()
            .filter(|trial| trial_matches_row(trial, row))
            .map(|trial| trial.duration_ms / 1000.0)
            .collect(),
    })
}

fn load_metrics(row: &SummaryRow, _trials: &[TrialRecord]) -> Option<RowMetrics> {
    let p50 = row.p50_ms?;
    let p95 = row.p95_ms.unwrap_or(p50);
    Some(RowMetrics {
        min_ms: p50,
        median_ms: p50,
        max_ms: p95,
        detail: format!(
            "p50 {:.2}s, p95 {:.2}s, p99 {:.2}s, {} req/s",
            p50 / 1000.0,
            p95 / 1000.0,
            row.p99_ms.unwrap_or(p95) / 1000.0,
            fmt(row.throughput_per_sec)
        ),
        scatter_seconds: Vec::new(),
    })
}

/// Renders a duration-by-scale chart: time (seconds) on the X axis, a
/// caller-chosen scale metric (ring size, threshold, concurrency, ...) on
/// the Y axis as discrete rows, one color-coded series per network profile.
/// A line connects each series' median across rows, with a min/max range
/// and individual trial points layered on top where available.
fn scale_chart(
    trials: &[TrialRecord],
    rows: &[SummaryRow],
    operation: Operation,
    y_axis_label: &str,
    is_load: bool,
    y_value: impl Fn(&SummaryRow) -> usize,
) -> String {
    let filtered: Vec<&SummaryRow> = rows
        .iter()
        .filter(|row| row.operation == operation && row.concurrency.is_some() == is_load)
        .collect();
    if filtered.is_empty() {
        return format!(
            "<p class=\"empty\">No {:?} {} recorded.</p>",
            operation,
            if is_load { "load trials" } else { "trials" }
        );
    }
    let metrics_for = |row: &SummaryRow| {
        if is_load {
            load_metrics(row, trials)
        } else {
            ceremony_metrics(row, trials)
        }
    };

    let mut y_values: Vec<usize> = filtered.iter().map(|row| y_value(row)).collect();
    y_values.sort_unstable();
    y_values.dedup();

    let mut profiles: Vec<String> = filtered.iter().map(|row| row.profile.clone()).collect();
    profiles.sort();
    profiles.dedup();

    let colors = [
        "#4de3a6", "#ffb454", "#7fb7ff", "#ff7b8b", "#b69cff", "#54d8e8",
    ];

    let width = 1040.0;
    let left = 90.0;
    let right = 30.0;
    let top = 20.0;
    let bottom = 46.0;
    let row_height = 46.0;
    let height = top + bottom + y_values.len() as f64 * row_height;

    let max_seconds = (filtered
        .iter()
        .filter_map(|row| metrics_for(row))
        .map(|metrics| metrics.max_ms)
        .fold(0.0_f64, f64::max)
        / 1000.0)
        .max(1.0);
    let axis_y = height - bottom;
    let x = |seconds: f64| left + (seconds / max_seconds) * (width - left - right);
    let row_y = |value: usize| {
        let index = y_values.iter().position(|v| *v == value).unwrap_or(0);
        top + index as f64 * row_height + row_height / 2.0
    };
    let profile_offset = |profile: &str| {
        let index = profiles.iter().position(|p| p == profile).unwrap_or(0) as f64;
        let n = profiles.len().max(1) as f64;
        (index - (n - 1.0) / 2.0) * (row_height / (n + 1.0))
    };

    let mut svg = String::new();
    write!(
        svg,
        "<line class=\"axis\" x1=\"{left}\" y1=\"{top}\" x2=\"{left}\" y2=\"{axis_y}\"/><line class=\"axis\" x1=\"{left}\" y1=\"{axis_y}\" x2=\"{}\" y2=\"{axis_y}\"/>",
        width - right
    )
    .ok();
    for &value in &y_values {
        let yy = row_y(value);
        write!(
            svg,
            "<line class=\"grid\" x1=\"{left}\" y1=\"{yy}\" x2=\"{}\" y2=\"{yy}\"/><text class=\"tick\" x=\"{}\" y=\"{}\" text-anchor=\"end\">{value}</text>",
            width - right,
            left - 10.0,
            yy + 4.0
        )
        .ok();
    }
    for tick in 0..=5 {
        let seconds = max_seconds * tick as f64 / 5.0;
        let xx = x(seconds);
        write!(
            svg,
            "<line class=\"grid\" x1=\"{xx}\" y1=\"{top}\" x2=\"{xx}\" y2=\"{axis_y}\"/><text class=\"tick\" x=\"{xx}\" y=\"{}\" text-anchor=\"middle\">{:.1}s</text>",
            axis_y + 18.0,
            seconds
        )
        .ok();
    }

    // Connecting line per profile, drawn first so markers sit on top of it.
    for (index, profile) in profiles.iter().enumerate() {
        let color = colors[index % colors.len()];
        let mut points: Vec<(f64, f64)> = filtered
            .iter()
            .filter(|row| &row.profile == profile)
            .filter_map(|row| {
                let metrics = metrics_for(row)?;
                Some((
                    row_y(y_value(row)) + profile_offset(profile),
                    x(metrics.median_ms / 1000.0),
                ))
            })
            .collect();
        points.sort_by(|a, b| a.0.total_cmp(&b.0));
        if points.len() >= 2 {
            let path: String = points
                .iter()
                .map(|(yy, xx)| format!("{xx:.1},{yy:.1}"))
                .collect::<Vec<_>>()
                .join(" ");
            write!(
                svg,
                "<polyline points=\"{path}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"2\" opacity=\".65\"/>"
            )
            .ok();
        }
    }

    for row in &filtered {
        let color_index = profiles.iter().position(|p| *p == row.profile).unwrap_or(0);
        let color = colors[color_index % colors.len()];
        let yy = row_y(y_value(row)) + profile_offset(&row.profile);
        let Some(metrics) = metrics_for(row) else {
            continue;
        };
        let (min_s, median_s, max_s) = (
            metrics.min_ms / 1000.0,
            metrics.median_ms / 1000.0,
            metrics.max_ms / 1000.0,
        );
        write!(
            svg,
            "<line x1=\"{}\" y1=\"{yy}\" x2=\"{}\" y2=\"{yy}\" stroke=\"{color}\" stroke-width=\"2\"/><circle cx=\"{}\" cy=\"{yy}\" r=\"5\" fill=\"{color}\"><title>{} {:?} network {} ring {} threshold {} {}</title></circle>",
            x(min_s),
            x(max_s),
            x(median_s),
            escape(&row.profile),
            row.operation,
            row.network_size,
            row.ring_size,
            row.threshold,
            escape(&metrics.detail)
        )
        .ok();
        for (index, seconds) in metrics.scatter_seconds.iter().enumerate() {
            write!(
                svg,
                "<circle cx=\"{}\" cy=\"{}\" r=\"2.5\" fill=\"{color}\" opacity=\".55\"/>",
                x(*seconds),
                yy + (index as f64 - 2.0) * 1.6
            )
            .ok();
        }
    }
    write!(
        svg,
        "<text class=\"label\" x=\"{}\" y=\"{}\">Time (s)</text><text class=\"label\" transform=\"translate(20,{}) rotate(-90)\">{}</text>",
        width / 2.0,
        height - 6.0,
        height / 2.0,
        escape(y_axis_label)
    )
    .ok();

    let mut legend = String::from("<div class=\"legend\">");
    for (index, profile) in profiles.iter().enumerate() {
        write!(
            legend,
            "<span class=\"legend-item\"><i style=\"background:{}\"></i>{}</span>",
            colors[index % colors.len()],
            escape(profile)
        )
        .ok();
    }
    legend.push_str("</div>");

    format!(
        "<div class=\"chart\"><svg viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"{:?} duration by {}\">{svg}</svg>{legend}</div>",
        operation, y_axis_label
    )
}

fn success_chart(rows: &[SummaryRow], trials: &[TrialRecord]) -> String {
    if rows.is_empty() {
        return "<p class=\"empty\">No trials recorded.</p>".into();
    }
    let width = 1040.0;
    let row_height = 25.0;
    let height = 35.0 + rows.len() as f64 * row_height;
    let mut svg = format!("<div class=\"chart\"><svg viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"Pass, timeout, and other-failure rates by benchmark case\">");
    for (index, row) in rows.iter().enumerate() {
        let yy = 22.0 + index as f64 * row_height;
        let rate = percent(row.successes, row.trials);
        let timeouts = trials
            .iter()
            .filter(|trial| trial_matches_row(trial, row))
            .filter(|trial| trial.error_class.as_deref() == Some("timeout"))
            .count();
        let timeout_rate = percent(timeouts, row.trials);
        let failure_rate = (100.0 - rate - timeout_rate).max(0.0);
        write!(svg,"<text class=\"row-label\" x=\"8\" y=\"{}\">{} n{} r{} t{} {:?} c{}</text><rect x=\"310\" y=\"{}\" width=\"650\" height=\"13\" rx=\"6\" fill=\"#243044\"/><rect x=\"310\" y=\"{}\" width=\"{}\" height=\"13\" fill=\"#4de3a6\"/><rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"13\" fill=\"#ffb454\"/><rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"13\" fill=\"#ff7b8b\"/><text class=\"tick\" x=\"1032\" y=\"{}\" text-anchor=\"end\">{:.0}% · {} timeout</text>",yy,escape(&row.profile),row.network_size,row.ring_size,row.threshold,row.operation,row.concurrency.unwrap_or(0),yy-10.0,yy-10.0,6.5*rate,310.0+6.5*rate,yy-10.0,6.5*timeout_rate,310.0+6.5*(rate+timeout_rate),yy-10.0,6.5*failure_rate,yy,rate,timeouts).ok();
    }
    svg.push_str("</svg></div>");
    svg
}

fn trial_matches_row(trial: &TrialRecord, row: &SummaryRow) -> bool {
    !trial.warmup
        && trial.profile == row.profile
        && trial.network_size == row.network_size
        && trial.case.ring_size == row.ring_size
        && trial.case.threshold == row.threshold
        && trial.operation == row.operation
        && trial.concurrency == row.concurrency
}

#[derive(Clone)]
struct Capacity {
    profile: String,
    operation: String,
    ring_size: usize,
    network_size: usize,
    threshold: usize,
}
fn largest_viable(rows: &[SummaryRow], operation_count: usize) -> Vec<Capacity> {
    let mut map: BTreeMap<(String, String), Capacity> = BTreeMap::new();
    for row in rows
        .iter()
        .filter(|row| row.viable && row.concurrency.is_none())
    {
        let operation = format!("{:?}", row.operation);
        let key = (row.profile.clone(), operation.clone());
        let candidate = Capacity {
            profile: row.profile.clone(),
            operation,
            ring_size: row.ring_size,
            network_size: row.network_size,
            threshold: row.threshold,
        };
        if map
            .get(&key)
            .is_none_or(|old| candidate.ring_size > old.ring_size)
        {
            map.insert(key, candidate);
        }
    }
    let mut overall: BTreeMap<(String, usize, usize, usize), (bool, BTreeSet<_>)> = BTreeMap::new();
    for row in rows {
        let entry = overall
            .entry((
                row.profile.clone(),
                row.network_size,
                row.ring_size,
                row.threshold,
            ))
            .or_insert_with(|| (true, BTreeSet::new()));
        entry.0 &= row.viable;
        entry.1.insert(row.operation);
    }
    for ((profile, network_size, ring_size, threshold), (viable, operations)) in overall {
        if viable && operations.len() == operation_count {
            let key = (profile.clone(), "Overall".to_string());
            let candidate = Capacity {
                profile,
                operation: "Overall".to_string(),
                ring_size,
                network_size,
                threshold,
            };
            if map
                .get(&key)
                .is_none_or(|old| candidate.ring_size > old.ring_size)
            {
                map.insert(key, candidate);
            }
        }
    }
    map.into_values().collect()
}

fn aggregate_metric_deltas(trials: &[TrialRecord]) -> Vec<(String, f64)> {
    let mut map = BTreeMap::new();
    for trial in trials {
        for (key, value) in &trial.metric_deltas {
            *map.entry(key.clone()).or_insert(0.0) += value;
        }
    }
    let mut values: Vec<_> = map.into_iter().collect();
    values.sort_by(|a, b| b.1.total_cmp(&a.1));
    values
}

#[derive(Debug)]
struct PhaseBreakdown {
    kind: String,
    phase: String,
    count: f64,
    average_ms: f64,
    total_ms: f64,
}

#[derive(Debug, PartialEq)]
struct TransportEvidence {
    plane: String,
    measurement: String,
    labels: String,
    value: String,
}

fn dkg_transport_evidence(metrics: &[(String, f64)]) -> Vec<TransportEvidence> {
    let lookup: BTreeMap<&str, f64> = metrics
        .iter()
        .map(|(metric, value)| (metric.as_str(), *value))
        .collect();
    let mut rows = Vec::new();
    for (metric, value) in metrics {
        let (name, labels) = metric
            .split_once('{')
            .map_or((metric.as_str(), ""), |(name, labels)| {
                (name, labels.strip_suffix('}').unwrap_or(labels))
            });
        let plane = if name.starts_with("dkg_control_") {
            "control".to_string()
        } else if name.starts_with("dkg_public_") {
            "public".to_string()
        } else if name.starts_with("dkg_private_") {
            "private".to_string()
        } else if name.starts_with("dkg_transport_") {
            metric_label(metric, "plane").unwrap_or_else(|| "transport".into())
        } else if name.starts_with("p2p_") {
            "network".to_string()
        } else {
            continue;
        };

        if name.ends_with("_bucket") || name.ends_with("_created") {
            continue;
        }
        if let Some(base) = name.strip_suffix("_sum") {
            let count_key = if labels.is_empty() {
                format!("{base}_count")
            } else {
                format!("{base}_count{{{labels}}}")
            };
            let count = lookup.get(count_key.as_str()).copied().unwrap_or(0.0);
            if count > 0.0 {
                rows.push(TransportEvidence {
                    plane: plane.clone(),
                    measurement: format!("{base} average"),
                    labels: labels.to_string(),
                    value: format!("{:.2} ms (n={count:.0})", value / count * 1_000.0),
                });
            }
            continue;
        }
        if name.ends_with("_count") {
            continue;
        }

        let value = if name.contains("bytes") {
            human_bytes(value.max(0.0) as u64)
        } else if name.contains("active") || name.contains("neighbors") {
            format!("{value:+.0} end-minus-start")
        } else {
            format!("{value:.0}")
        };
        rows.push(TransportEvidence {
            plane,
            measurement: name.to_string(),
            labels: labels.to_string(),
            value,
        });
    }
    rows.sort_by(|left, right| {
        (&left.plane, &left.measurement, &left.labels).cmp(&(
            &right.plane,
            &right.measurement,
            &right.labels,
        ))
    });
    rows
}

fn missing_topology_evidence(trials: &[TrialRecord]) -> Vec<TransportEvidence> {
    const MARKER: &str = "topology probe acknowledgement missing from ";
    let mut rows = trials
        .iter()
        .filter_map(|trial| {
            let details = trial.error.as_deref()?.split_once(MARKER)?.1;
            let (count, remainder) = details.split_once(" participants")?;
            let prefixes = remainder
                .split_once(':')
                .map(|(_, prefixes)| prefixes.trim())
                .filter(|prefixes| !prefixes.is_empty())
                .unwrap_or("prefixes unavailable");
            Some(TransportEvidence {
                plane: "control".into(),
                measurement: "topology probe missing participants".into(),
                labels: format!(
                    "profile=\"{}\",network=\"{}\",ring=\"{}\",threshold=\"{}\",trial=\"{}\"",
                    trial.profile,
                    trial.network_size,
                    trial.case.ring_size,
                    trial.case.threshold,
                    trial.trial_index
                ),
                value: format!("{count} ({prefixes})"),
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| (&left.labels, &left.value).cmp(&(&right.labels, &right.value)));
    rows
}

fn phase_breakdown(metrics: &[(String, f64)]) -> Vec<PhaseBreakdown> {
    let lookup: BTreeMap<&str, f64> = metrics
        .iter()
        .map(|(metric, value)| (metric.as_str(), *value))
        .collect();
    let mut phases = Vec::new();
    for (metric, seconds) in metrics
        .iter()
        .filter(|(metric, _)| metric.starts_with("dkg_phase_duration_seconds_sum{"))
    {
        let count_key = metric.replacen(
            "dkg_phase_duration_seconds_sum",
            "dkg_phase_duration_seconds_count",
            1,
        );
        let count = lookup.get(count_key.as_str()).copied().unwrap_or(0.0);
        if count <= 0.0 {
            continue;
        }
        phases.push(PhaseBreakdown {
            kind: metric_label(metric, "kind").unwrap_or_else(|| "unknown".into()),
            phase: metric_label(metric, "phase").unwrap_or_else(|| "unknown".into()),
            count,
            average_ms: seconds / count * 1_000.0,
            total_ms: seconds * 1_000.0,
        });
    }
    phases.sort_by(|left, right| (&left.kind, &left.phase).cmp(&(&right.kind, &right.phase)));
    phases
}

fn metric_label(metric: &str, label: &str) -> Option<String> {
    let labels = metric.split_once('{')?.1.strip_suffix('}')?;
    labels.split(',').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        (name == label).then(|| value.trim_matches('"').to_string())
    })
}

fn metric_prefix_total(metrics: &[(String, f64)], prefix: &str) -> f64 {
    metrics
        .iter()
        .filter(|(metric, _)| metric.starts_with(prefix))
        .map(|(_, value)| value)
        .sum()
}

fn docker_memory_bytes(manifest: &RunManifest) -> Option<u64> {
    let value = manifest.host.docker_info.as_ref()?.get("MemTotal")?;
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}
fn stat_card(out: &mut String, label: &str, value: &str, note: &str) {
    write!(
        out,
        "<article><span>{}</span><strong>{}</strong><small>{}</small></article>",
        escape(label),
        escape(value),
        escape(note)
    )
    .ok();
}
fn definition(out: &mut String, label: &str, value: &str) {
    write!(out, "<dt>{}</dt><dd>{}</dd>", escape(label), escape(value)).ok();
}
fn percent(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64 * 100.0
    }
}
fn fmt(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.2}"))
        .unwrap_or_else(|| "—".into())
}
/// Formats a millisecond duration as seconds, matching the report-wide
/// convention of tracking everything in seconds rather than milliseconds.
fn fmt_seconds(ms: Option<f64>) -> String {
    ms.map(|ms| format!("{:.3}", ms / 1000.0))
        .unwrap_or_else(|| "—".into())
}
/// Keeps only the first paragraph of an error (before a "Caused by"/traceback
/// continuation), so warnings stay scannable instead of dumping a full
/// multi-line error chain inline. The complete error remains available in
/// setup-failures.jsonl and trials.jsonl.
fn truncate_error(message: &str) -> String {
    match message.split_once("\n\n") {
        Some((first, _)) => format!("{first} (see setup-failures.jsonl/trials.jsonl for detail)"),
        None => message.to_string(),
    }
}
fn pass_badge(pass: bool) -> &'static str {
    if pass {
        "<span class=\"pass\">PASS</span>"
    } else {
        "<span class=\"fail\">FAIL</span>"
    }
}
fn human_bytes(bytes: u64) -> String {
    let gib = bytes as f64 / 1_073_741_824.0;
    if gib >= 1.0 {
        format!("{gib:.2} GiB")
    } else {
        format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
    }
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const CSS: &str = r#"
:root{color-scheme:dark;--bg:#09101c;--panel:#111b2b;--line:#26354b;--text:#edf4ff;--muted:#91a4be;--accent:#4de3a6;--warn:#ffb454;--bad:#ff7b8b}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 0,#183054 0,transparent 32%),var(--bg);color:var(--text);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,sans-serif}main{max-width:1180px;margin:auto;padding:54px 28px 80px}header{border-bottom:1px solid var(--line);padding-bottom:30px}.eyebrow{letter-spacing:.2em;color:var(--accent);font-weight:700;font-size:12px}h1{font-size:clamp(36px,6vw,68px);line-height:1;margin:.2em 0}.lead{font-size:19px;color:var(--muted)}.meta{display:flex;gap:10px;flex-wrap:wrap}.meta span{background:#162338;border:1px solid var(--line);border-radius:99px;padding:5px 11px;color:#c6d4e8}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.cards article{background:linear-gradient(145deg,#152238,#0f1828);border:1px solid var(--line);border-radius:14px;padding:18px}.cards span,.cards small{display:block;color:var(--muted)}.cards strong{display:block;font-size:28px;margin:5px 0}section{margin-top:42px}h2{font-size:26px;margin-bottom:6px}h3{color:#dbe8fa}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)}table{border-collapse:collapse;width:100%}th,td{padding:10px 13px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}th{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}td.num{text-align:right;font-variant-numeric:tabular-nums}.pass,.fail{font-size:11px;font-weight:800;padding:3px 7px;border-radius:99px}.pass{color:var(--accent);background:#12392d}.fail{color:var(--bad);background:#40202a}.chart{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:10px;overflow:auto}.chart svg{min-width:760px}.axis{stroke:#71849e}.grid{stroke:#26354b}.tick,.row-label{fill:#91a4be;font-size:11px}.row-label{font-size:10px}.label{fill:#cdd9e9;font-size:13px}.split{display:grid;grid-template-columns:1.25fr .75fr;gap:18px}.compact code{font-size:11px}dl{display:grid;grid-template-columns:150px 1fr;gap:9px 14px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}.warnings{border:1px solid #604424;background:#211b14;border-radius:14px;padding:4px 22px 18px}.warnings li{margin:7px 0;color:#f2d4aa}footer{margin-top:40px;color:var(--muted);border-top:1px solid var(--line);padding-top:18px}.empty{color:var(--muted)}.legend{display:flex;gap:16px;flex-wrap:wrap;padding:8px 6px 2px}.legend-item{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12px}.legend-item i{display:inline-block;width:10px;height:10px;border-radius:3px}details{border:1px solid var(--line);border-radius:14px;background:var(--panel);padding:16px 20px;margin-top:42px}details summary{cursor:pointer;font-weight:700;font-size:18px;color:#dbe8fa;list-style:none}details summary::-webkit-details-marker{display:none}details summary::before{content:"▸ ";color:var(--accent)}details[open] summary::before{content:"▾ "}details section{margin-top:26px}@media(max-width:800px){.cards{grid-template-columns:repeat(2,1fr)}.split{grid-template-columns:1fr}main{padding:32px 16px}}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Experiment, Operation, RingCase};
    use crate::results::{HostMetadata, RunStatus};
    use sha2::{Digest, Sha256};

    fn sample_trial() -> TrialRecord {
        TrialRecord {
            run_id: "test-run".into(),
            stack_id: "orbis-bench-test-s000".into(),
            profile: "lan".into(),
            network_size: 3,
            case: RingCase {
                ring_size: 3,
                threshold: 2,
            },
            operation: Operation::Dkg,
            trial_index: 0,
            warmup: false,
            concurrency: None,
            started_at_unix_ms: 1,
            duration_ms: 1.0,
            client_total_ms: None,
            acknowledgement_ms: None,
            verification_ms: None,
            scheduler_delay_ms: None,
            throughput_per_sec: None,
            successful_requests: None,
            failed_requests: None,
            latency_p50_ms: None,
            latency_p95_ms: None,
            latency_p99_ms: None,
            success: true,
            error_class: None,
            error: None,
            ring_id: Some("ring".into()),
            ring_pk: Some("pk".into()),
            metric_deltas: BTreeMap::new(),
        }
    }

    #[test]
    fn html_escapes_user_supplied_names() {
        assert_eq!(escape("<x>&\""), "&lt;x&gt;&amp;&quot;");
    }
    #[test]
    fn empty_charts_remain_offline_and_valid() {
        assert!(
            scale_chart(&[], &[], Operation::Dkg, "Ring size", false, |row| row
                .ring_size)
            .contains("No Dkg")
        );
    }

    #[test]
    fn phase_histograms_are_reduced_to_node_phase_durations() {
        let metrics = vec![
            (
                "dkg_phase_duration_seconds_count{kind=\"refresh\",phase=\"phase2_shares\"}".into(),
                4.0,
            ),
            (
                "dkg_phase_duration_seconds_sum{kind=\"refresh\",phase=\"phase2_shares\"}".into(),
                2.0,
            ),
        ];
        let rows = phase_breakdown(&metrics);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "refresh");
        assert_eq!(rows[0].phase, "phase2_shares");
        assert_eq!(rows[0].average_ms, 500.0);
        assert_eq!(rows[0].total_ms, 2_000.0);
    }

    #[test]
    fn dkg_transport_evidence_reports_latency_events_and_network_deltas() {
        let metrics = vec![
            (
                "dkg_control_readiness_duration_seconds_count{kind=\"fresh\"}".into(),
                2.0,
            ),
            (
                "dkg_control_readiness_duration_seconds_sum{kind=\"fresh\"}".into(),
                1.0,
            ),
            (
                "dkg_transport_events_total{plane=\"public\",event=\"repair\"}".into(),
                3.0,
            ),
            (
                "dkg_transport_events_total{plane=\"control\",event=\"probe_ack\"}".into(),
                8.0,
            ),
            (
                "dkg_transport_events_total{plane=\"public\",event=\"rejoin_isolation\"}".into(),
                1.0,
            ),
            (
                "p2p_bytes_sent_total{protocol=\"gossip\"}".into(),
                1_048_576.0,
            ),
            ("p2p_gossip_neighbors{protocol=\"gossip\"}".into(), -1.0),
        ];
        let rows = dkg_transport_evidence(&metrics);
        assert!(rows.iter().any(|row| {
            row.plane == "control"
                && row.measurement == "dkg_control_readiness_duration_seconds average"
                && row.value == "500.00 ms (n=2)"
        }));
        assert!(rows.iter().any(|row| {
            row.plane == "public"
                && row.measurement == "dkg_transport_events_total"
                && row.value == "3"
        }));
        assert!(rows.iter().any(|row| {
            row.plane == "control" && row.labels.contains("probe_ack") && row.value == "8"
        }));
        assert!(rows.iter().any(|row| {
            row.plane == "public" && row.labels.contains("rejoin_isolation") && row.value == "1"
        }));
        assert!(rows.iter().any(|row| {
            row.plane == "network"
                && row.measurement == "p2p_bytes_sent_total"
                && row.value == "1.0 MiB"
        }));
        assert!(rows.iter().any(|row| {
            row.measurement == "p2p_gossip_neighbors" && row.value == "-1 end-minus-start"
        }));
    }

    #[test]
    fn failed_preparation_surfaces_exact_missing_participants() {
        let mut trial = sample_trial();
        trial.profile = "lan".into();
        trial.network_size = 50;
        trial.case.ring_size = 8;
        trial.case.threshold = 7;
        trial.trial_index = 3;
        trial.success = false;
        trial.error = Some(
            "Network communication error: topology probe acknowledgement missing from 2 participants before preparation deadline: aaaaaaaaaaaa,bbbbbbbbbbbb"
                .into(),
        );

        let rows = missing_topology_evidence(&[trial]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].plane, "control");
        assert_eq!(rows[0].measurement, "topology probe missing participants");
        assert!(rows[0].labels.contains("network=\"50\""));
        assert!(rows[0].labels.contains("ring=\"8\""));
        assert_eq!(rows[0].value, "2 (aaaaaaaaaaaa,bbbbbbbbbbbb)");
    }

    #[test]
    fn resource_cpu_integration_does_not_charge_gaps_between_stacks() {
        let path = std::env::temp_dir().join(format!(
            "orbis-bench-resource-test-{}.csv",
            uuid::Uuid::new_v4().simple()
        ));
        let header = "run_id,stack_id,sampled_at_unix_ms,service,container_id,cpu_percent,memory_bytes,memory_limit_bytes,network_rx_bytes,network_tx_bytes,block_read_bytes,block_write_bytes,pids\n";
        let rows = [
            "r,a,0,node-1,c1,100,10,100,1,2,0,0,1",
            "r,a,1000,node-1,c1,100,20,100,3,4,0,0,1",
            "r,b,1000000,node-1,c2,100,30,100,5,6,0,0,1",
            "r,b,1001000,node-1,c2,100,40,100,7,8,0,0,1",
        ]
        .join("\n");
        fs::write(&path, format!("{header}{rows}\n")).unwrap();
        let summary = read_resource_summary(&path).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(summary.sample_count, 4);
        assert_eq!(summary.peak_aggregate_rss_bytes, 40);
        assert_eq!(summary.cpu_seconds, 2.0);
        assert_eq!(summary.network_rx_bytes, 10);
        assert_eq!(summary.network_tx_bytes, 12);
    }

    #[test]
    fn offline_report_golden_digest() {
        let mut experiment = Experiment::single(3, 3, 2);
        experiment.repetitions = 1;
        let manifest = RunManifest {
            schema_version: 1,
            run_id: "golden-run".into(),
            created_at_unix_ms: 1,
            completed_at_unix_ms: Some(2),
            status: RunStatus::Completed,
            sourcehub_ref: experiment.sourcehub_ref.clone(),
            experiment,
            host: HostMetadata {
                os: "test-os".into(),
                architecture: "test-arch".into(),
                cpu_count: 8,
                cpu_model: Some("Test CPU".into()),
                host_memory_bytes: Some(16 * 1024 * 1024 * 1024),
                disk_available_bytes: Some(100 * 1024 * 1024 * 1024),
                git_commit: Some("abc123".into()),
                git_dirty: Some(false),
                docker_version: Some("test".into()),
                docker_info: None,
            },
            node_image: Some("sha256:node".into()),
            sourcehub_image: Some("sha256:sourcehub".into()),
            crypto_implementation: "bls12-381".into(),
            stack_projects: vec!["orbis-bench-golden-s000".into()],
            profile_calibration: BTreeMap::new(),
            setup_batch_evidence: BTreeMap::new(),
            warnings: Vec::new(),
        };
        let trial = TrialRecord {
            run_id: manifest.run_id.clone(),
            stack_id: "orbis-bench-golden-s000".into(),
            profile: "lan".into(),
            network_size: 3,
            case: RingCase {
                ring_size: 3,
                threshold: 2,
            },
            operation: Operation::Dkg,
            trial_index: 0,
            warmup: false,
            concurrency: None,
            started_at_unix_ms: 1,
            duration_ms: 123.0,
            client_total_ms: None,
            acknowledgement_ms: Some(4.0),
            verification_ms: None,
            scheduler_delay_ms: None,
            throughput_per_sec: None,
            successful_requests: None,
            failed_requests: None,
            latency_p50_ms: None,
            latency_p95_ms: None,
            latency_p99_ms: None,
            success: true,
            error_class: None,
            error: None,
            ring_id: Some("ring".into()),
            ring_pk: Some("pk".into()),
            metric_deltas: BTreeMap::from([("dkg_transport_messages_total".into(), 12.0)]),
        };
        let rows = summarize(std::slice::from_ref(&trial));
        let html = render_report(&manifest, &[trial], &rows, &ResourceSummary::default());
        assert_eq!(
            hex::encode(Sha256::digest(html)),
            "32b9cd69d990f490471bf2cfe2c2cde7d5db031e90e1d7c02b36c6f1af7557e3"
        );
    }
}
