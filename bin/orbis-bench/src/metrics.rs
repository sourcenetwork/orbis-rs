use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::time::Duration;

pub type MetricSnapshot = BTreeMap<String, f64>;

pub async fn scrape(endpoint: &str, timeout: Duration) -> Result<MetricSnapshot> {
    let response = reqwest::Client::builder()
        .timeout(timeout)
        .build()?
        .get(endpoint)
        .send()
        .await
        .with_context(|| format!("scrape Prometheus endpoint {endpoint}"))?;
    if !response.status().is_success() {
        bail!("metrics scrape {endpoint} returned {}", response.status());
    }
    parse_prometheus(&response.text().await?)
}

pub fn parse_prometheus(input: &str) -> Result<MetricSnapshot> {
    let mut snapshot = BTreeMap::new();
    for (line_number, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let split = line
            .rfind(|character: char| character.is_ascii_whitespace())
            .ok_or_else(|| anyhow::anyhow!("invalid metric line {}: {line}", line_number + 1))?;
        let name = line[..split].trim();
        let value_text = line[split..].trim();
        // Prometheus text can optionally include a timestamp after the value.
        let value_text = value_text
            .split_ascii_whitespace()
            .next()
            .unwrap_or(value_text);
        let value = match value_text {
            "+Inf" => f64::INFINITY,
            "-Inf" => f64::NEG_INFINITY,
            "NaN" => f64::NAN,
            value => value.parse().with_context(|| {
                format!("invalid value on metric line {}: {line}", line_number + 1)
            })?,
        };
        snapshot.insert(canonical_metric_key(name), value);
    }
    Ok(snapshot)
}

fn canonical_metric_key(name: &str) -> String {
    let Some(labels_start) = name.find('{') else {
        return name.to_string();
    };
    let Some(labels_end) = name.rfind('}') else {
        return name.to_string();
    };
    let metric = &name[..labels_start];
    let labels = &name[labels_start + 1..labels_end];
    let mut labels = split_labels(labels);
    labels.sort_unstable();
    format!("{metric}{{{}}}", labels.join(","))
}

fn split_labels(labels: &str) -> Vec<&str> {
    let mut output = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in labels.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                output.push(labels[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < labels.len() {
        output.push(labels[start..].trim());
    }
    output
}

pub fn delta(before: &MetricSnapshot, after: &MetricSnapshot) -> MetricSnapshot {
    after
        .iter()
        .filter_map(|(key, after_value)| {
            let before_value = before.get(key).copied().unwrap_or(0.0);
            let difference = after_value - before_value;
            difference.is_finite().then(|| (key.clone(), difference))
        })
        .collect()
}

pub fn aggregate(snapshots: &[MetricSnapshot]) -> MetricSnapshot {
    let mut result = BTreeMap::new();
    for snapshot in snapshots {
        for (key, value) in snapshot {
            *result.entry(key.clone()).or_insert(0.0) += value;
        }
    }
    result
}

pub fn retain_benchmark_metrics(snapshot: &mut MetricSnapshot) {
    snapshot.retain(|key, _| {
        [
            "dkg_",
            "pss_",
            "pre_",
            "sign_",
            "p2p_",
            "network_messages_",
            "network_bytes_",
            "grpc_requests_",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_labels_timestamps_and_histograms() {
        let parsed = parse_prometheus(
            r#"
# HELP dkg_phase_duration_seconds duration
dkg_phase_duration_seconds_bucket{phase="shares",kind="fresh",le="1"} 4
dkg_phase_duration_seconds_sum{kind="fresh",phase="shares"} 2.5 1234
plain_total 9
"#,
        )
        .unwrap();
        assert_eq!(
            parsed["dkg_phase_duration_seconds_bucket{kind=\"fresh\",le=\"1\",phase=\"shares\"}"],
            4.0
        );
        assert_eq!(parsed["plain_total"], 9.0);
    }

    #[test]
    fn computes_counter_deltas() {
        let before = BTreeMap::from([("requests_total".to_string(), 10.0)]);
        let after = BTreeMap::from([("requests_total".to_string(), 14.0)]);
        assert_eq!(delta(&before, &after)["requests_total"], 4.0);
    }

    #[test]
    fn retains_dkg_p2p_metrics_for_reports() {
        let mut snapshot = BTreeMap::from([
            (
                "p2p_bytes_sent_total{protocol=\"gossip\"}".to_string(),
                42.0,
            ),
            ("unrelated_runtime_metric".to_string(), 7.0),
        ]);
        retain_benchmark_metrics(&mut snapshot);
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.contains_key("p2p_bytes_sent_total{protocol=\"gossip\"}"));
    }
}
