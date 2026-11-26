use crate::config::Operation;
use crate::results::{
    apply_expected_trial_counts, read_trials, summarize, RunManifest, SummaryRow, TrialRecord,
};
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
    apply_expected_trial_counts(&mut summary, &manifest);
    let html = render_report(&manifest, &trials, &summary);
    fs::write(run_dir.join("report.html"), html)?;
    Ok(())
}

fn render_report(manifest: &RunManifest, trials: &[TrialRecord], rows: &[SummaryRow]) -> String {
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
    warnings.push("WAN results are in-process software shaping, not measurements across independent machines or Internet routes.".into());

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
    html.push_str("</section>");

    html.push_str("<section><h2>Ceremony duration by scale</h2><p>Time on the X axis, scale on the Y axis, one line per network profile connecting the median at each size. Range bars show min/max, the filled dot is the median, faint dots are individual measured trials. DKG needs every ring member, so it scales with ring size; PRE, PET, and Sign only need a threshold of shares, so they scale with threshold.</p>");
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
    html.push_str("<h3>PET</h3>");
    html.push_str(&scale_chart(
        trials,
        rows,
        Operation::Pet,
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
    html.push_str("<h3>PET</h3>");
    html.push_str(&scale_chart(
        trials,
        rows,
        Operation::Pet,
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

    html.push_str("<section><h2>Closed-loop load</h2><div class=\"table-wrap\"><table><thead><tr><th>Profile</th><th>Network</th><th>Ring</th><th>Threshold</th><th>Operation</th><th>Concurrency</th><th>Throughput/s</th><th>p50 (s)</th><th>p95 (s)</th><th>p99 (s)</th><th>All pass</th></tr></thead><tbody>");
    for row in load_rows {
        write!(html, "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{:?}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{}</td></tr>", escape(&row.profile), row.network_size, row.ring_size, row.threshold, row.operation, row.concurrency.unwrap_or(0), fmt(row.throughput_per_sec), fmt_seconds(row.p50_ms), fmt_seconds(row.p95_ms), fmt_seconds(row.p99_ms), pass_badge(row.viable)).ok();
    }
    html.push_str("</tbody></table></div></section>");

    html.push_str("<section><h2>Success and timeouts</h2>");
    html.push_str(&success_chart(rows, trials));
    html.push_str("</section>");

    html.push_str("<details><summary>Advanced / raw evidence</summary>");
    html.push_str("<section><h2>DKG transport evidence</h2><div class=\"table-wrap\"><table><thead><tr><th>Plane</th><th>Measurement</th><th>Labels</th><th>Value</th></tr></thead><tbody>");
    let transport_rows = missing_topology_evidence(trials);
    if transport_rows.is_empty() {
        html.push_str("<tr><td colspan=\"4\" class=\"empty\">No DKG transport failures were recorded.</td></tr>");
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
    html.push_str("</tbody></table></div></section>");

    html.push_str("<section><h2>Environment</h2><dl>");
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
    html.push_str("</dl></section>");
    html.push_str("</details>");

    html.push_str("<section class=\"warnings\"><h2>Interpretation warnings</h2><ul>");
    warnings.sort();
    warnings.dedup();
    for warning in warnings {
        write!(html, "<li>{}</li>", escape(&truncate_error(&warning))).ok();
    }
    html.push_str("</ul></section>");
    html.push_str("<footer>Raw evidence: manifest.json · trials.jsonl · setup-failures.jsonl · summary.csv · failure logs</footer></main></body></html>");
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
    // `ceremony_metrics` rescans all of `trials` per call; compute it once per
    // filtered row here (index-aligned with `filtered`) instead of repeating
    // that scan for the same row in the max-seconds, polyline, and marker
    // passes below.
    let row_metrics: Vec<Option<RowMetrics>> =
        filtered.iter().map(|row| metrics_for(row)).collect();

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

    let max_seconds = (row_metrics
        .iter()
        .filter_map(|metrics| metrics.as_ref())
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
            .zip(row_metrics.iter())
            .filter(|(row, _)| &row.profile == profile)
            .filter_map(|(row, metrics)| {
                let metrics = metrics.as_ref()?;
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

    for (row, metrics) in filtered.iter().zip(row_metrics.iter()) {
        let color_index = profiles.iter().position(|p| *p == row.profile).unwrap_or(0);
        let color = colors[color_index % colors.len()];
        let yy = row_y(y_value(row)) + profile_offset(&row.profile);
        let Some(metrics) = metrics else {
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

#[derive(Debug, PartialEq)]
struct TransportEvidence {
    plane: String,
    measurement: String,
    labels: String,
    value: String,
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
    use crate::config::{Operation, RingCase};

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
}
