use serde_json::{json, Value};

const FILES: &[&str] = &[
    "native_gateway_cluster_test.go",
    "native_gateway_commands_test.go",
    "native_gateway_container_test.go",
    "native_gateway_decisions_test.go",
    "native_gateway_edits_test.go",
    "native_gateway_executable_test.go",
    "native_gateway_limits_test.go",
    "native_gateway_process_test.go",
    "native_gateway_reads_test.go",
    "native_gateway_ring_fixture_test.go",
    "native_gateway_ring_test.go",
    "native_identity_login_test.go",
];

pub(super) fn summarize(output: &str, exit_code: Option<i32>) -> Value {
    let mut locations = Vec::new();
    for line in output.lines() {
        for &file in FILES {
            let Some(suffix) = line
                .trim_start()
                .strip_prefix(file)
                .and_then(|s| s.strip_prefix(':'))
            else {
                continue;
            };
            let Some((number, _)) = suffix.split_once(':') else {
                continue;
            };
            if number.is_empty() || number.len() > 6 || !number.bytes().all(|b| b.is_ascii_digit())
            {
                continue;
            }
            let Ok(number) = number.parse::<u32>() else {
                continue;
            };
            if number == 0 {
                continue;
            }
            let point = (file, number);
            locations.retain(|existing| *existing != point);
            locations.push(point);
            if locations.len() > 16 {
                locations.remove(0);
            }
        }
    }
    json!({
        "exit_code": exit_code,
        "test_timeout": output.lines().any(|line| line.starts_with("panic: test timed out after ")),
        "context_deadline": output.contains("context deadline exceeded"),
        "locations": locations.into_iter().map(|(file, line)| json!({"file": file, "line": line})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_go_failure_keeps_only_known_source_locations() {
        let result = summarize("    native_gateway_ring_test.go:51: private credentials\n/private/secret/native_gateway_ring_test.go:42: secret\nunknown.go:123: private data\n", Some(1));
        assert_eq!(
            result["locations"],
            json!([{"file": "native_gateway_ring_test.go", "line": 51}])
        );
        assert_eq!(result["exit_code"], 1);
        assert!(!result["test_timeout"].as_bool().unwrap());
        let encoded = result.to_string();
        for private in ["secret", "credentials", "private", "unknown.go"] {
            assert!(!encoded.contains(private));
        }
    }

    #[test]
    fn trust_go_failure_rejects_ambiguous_source_lines() {
        for number in ["0", "-1", "+1", "1.5", "1000000", "1/path", ""] {
            let output = format!("native_gateway_ring_test.go:{number}: private");
            assert_eq!(summarize(&output, None)["locations"], json!([]));
        }
    }

    #[test]
    fn trust_go_failure_preserves_recent_locations_and_deadline_flags() {
        let mut output =
            String::from("panic: test timed out after 2m0s\ncontext deadline exceeded\n");
        for line in 1..=20 {
            output.push_str(&format!("native_gateway_ring_test.go:{line}: private\n"));
        }
        output.push_str("native_gateway_ring_test.go:5: private\n");
        let result = summarize(&output, Some(2));
        let locations = result["locations"].as_array().unwrap();
        assert_eq!(locations.len(), 16);
        assert_eq!(locations[0]["line"], 6);
        assert_eq!(locations[15]["line"], 5);
        assert_eq!(result["test_timeout"], true);
        assert_eq!(result["context_deadline"], true);
    }
}
