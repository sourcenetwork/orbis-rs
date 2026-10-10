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

pub(super) fn summarize(output: &str, exit_code: Option<i32>, truncated: bool) -> Value {
    let mut locations = Vec::new();
    for line in output.lines() {
        for &file in FILES {
            let line = line.trim_start();
            let stack_frame = line.starts_with("github.com/sourcenetwork/trust-api/cmd/trust-api/")
                || line.starts_with("/fixture/cmd/trust-api/");
            let line = line
                .strip_prefix("github.com/sourcenetwork/trust-api/cmd/trust-api/")
                .or_else(|| line.strip_prefix("/fixture/cmd/trust-api/"))
                .unwrap_or(line);
            let Some(suffix) = line.strip_prefix(file).and_then(|s| s.strip_prefix(':')) else {
                continue;
            };
            let end = suffix
                .bytes()
                .position(|byte| !byte.is_ascii_digit())
                .unwrap_or(suffix.len());
            let (number, tail) = suffix.split_at(end);
            let stack_offset = tail.strip_prefix(" +0x").is_some_and(|offset| {
                !offset.is_empty()
                    && offset.len() <= 16
                    && offset.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
            if !tail.starts_with(':') && !(stack_frame && (tail.is_empty() || stack_offset)) {
                continue;
            }
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
    let signal = ["SIGSEGV", "SIGBUS", "SIGABRT", "SIGILL"]
        .into_iter()
        .find(|signal| {
            output.lines().any(|line| {
                line.strip_prefix(*signal)
                    .is_some_and(|rest| rest.starts_with(':'))
            })
        });
    json!({
        "exit_code": exit_code,
        "test_timeout": output.lines().any(|line| line.starts_with("panic: test timed out after ")),
        "context_deadline": output.contains("context deadline exceeded"),
        "test_started": output.lines().any(|line| line == "=== RUN   TestNativeGatewayRingDKGContract"),
        "panic": output.lines().any(|line| line.starts_with("panic: ")),
        "fatal_runtime": output.lines().any(|line| line.starts_with("fatal error: ")),
        "invalid_flag": output.lines().any(|line| line.starts_with("flag provided but not defined: ")),
        "cgo_signal": output.contains("signal arrived during cgo execution"),
        "signal": signal,
        "output_truncated": truncated,
        "locations": locations.into_iter().map(|(file, line)| json!({"file": file, "line": line})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_go_failure_keeps_only_known_source_locations() {
        let result = summarize("    native_gateway_ring_test.go:51: private credentials\n/private/secret/native_gateway_ring_test.go:42: secret\nunknown.go:123: private data\n", Some(1), false);
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
            assert_eq!(summarize(&output, None, false)["locations"], json!([]));
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
        let result = summarize(&output, Some(2), false);
        let locations = result["locations"].as_array().unwrap();
        assert_eq!(locations.len(), 16);
        assert_eq!(locations[0]["line"], 6);
        assert_eq!(locations[15]["line"], 5);
        assert_eq!(result["test_timeout"], true);
        assert_eq!(result["context_deadline"], true);
    }

    #[test]
    fn trust_go_failure_extracts_only_known_trimmed_stack_frames() {
        let output = "panic: private credential\n\
            github.com/sourcenetwork/trust-api/cmd/trust-api/native_gateway_ring_test.go:51 +0xabc\n\
            /fixture/cmd/trust-api/native_gateway_ring_fixture_test.go:73\n\
            /private/secret/native_gateway_ring_test.go:42 +0x123\n\
            github.com/other/trust-api/cmd/trust-api/native_gateway_ring_test.go:44 +0x456\n";
        let result = summarize(output, Some(2), false);
        assert_eq!(
            result["locations"],
            json!([
                {"file": "native_gateway_ring_test.go", "line": 51},
                {"file": "native_gateway_ring_fixture_test.go", "line": 73},
            ])
        );
        assert_eq!(result["panic"], true);
        for private in ["credential", "/fixture", "/private", "github.com", "0xabc"] {
            assert!(!result.to_string().contains(private));
        }
    }

    #[test]
    fn trust_go_failure_rejects_malformed_stack_offsets() {
        for offset in [
            "",
            "+0x",
            "+0xsecret",
            "+0x123/path",
            "+0x12345678901234567",
        ] {
            let output = format!("github.com/sourcenetwork/trust-api/cmd/trust-api/native_gateway_ring_test.go:51 {offset}");
            assert_eq!(summarize(&output, None, false)["locations"], json!([]));
        }
    }

    #[test]
    fn trust_go_failure_classifies_runtime_exit_without_exposing_details() {
        let output = "=== RUN   TestNativeGatewayRingDKGContract\n\
            SIGABRT: private address\nsignal arrived during cgo execution\n\
            fatal error: private runtime state\nflag provided but not defined: private flag\n";
        let result = summarize(output, Some(2), true);
        assert_eq!(result["test_started"], true);
        assert_eq!(result["signal"], "SIGABRT");
        assert_eq!(result["cgo_signal"], true);
        assert_eq!(result["fatal_runtime"], true);
        assert_eq!(result["invalid_flag"], true);
        assert_eq!(result["output_truncated"], true);
        assert_eq!(result["panic"], false);
        assert!(!result.to_string().contains("private"));
        let clean = summarize("an echoed SIGSEGV: private message", None, false);
        assert_eq!(clean["signal"], Value::Null);
        assert_eq!(clean["test_started"], false);
    }
}
