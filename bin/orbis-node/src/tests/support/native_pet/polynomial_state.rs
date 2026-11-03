use serde::Serialize;

#[derive(Clone, Default, Serialize)]
pub(super) struct Response {
    status: Option<i32>,
    present: Option<bool>,
    changed: Option<bool>,
    matches_first: Option<bool>,
}

#[derive(Clone, Default, Serialize)]
pub(super) struct Member {
    pub connected: Option<bool>,
    pub main: Response,
    pub pet: Response,
}

impl Response {
    pub fn observe(
        response: Result<&str, tonic::Code>,
        previous: Option<&str>,
        first: Option<&str>,
    ) -> Self {
        match response {
            Ok(value) => Self {
                status: Some(0),
                present: Some(!value.is_empty()),
                changed: previous.map(|old| value != old),
                matches_first: first.map(|first| value == first),
            },
            Err(code) => Self {
                status: Some(code as i32),
                ..Self::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_polynomial_state_distinguishes_stale_and_divergent_generations() {
        let stale = Response::observe(Ok("old"), Some("old"), Some("new"));
        assert_eq!(stale.changed, Some(false));
        assert_eq!(stale.matches_first, Some(false));
        let changed = Response::observe(Ok("different"), Some("old"), Some("new"));
        assert_eq!(changed.changed, Some(true));
        assert_eq!(changed.matches_first, Some(false));
        let converged = Response::observe(Ok("new"), Some("old"), Some("new"));
        assert_eq!(converged.changed, Some(true));
        assert_eq!(converged.matches_first, Some(true));
    }

    #[test]
    fn native_polynomial_state_distinguishes_pending_empty_and_rpc_failure() {
        let pending = Response::default();
        assert!(pending.status.is_none() && pending.present.is_none());
        let empty = Response::observe(Ok(""), None, None);
        assert_eq!(empty.status, Some(0));
        assert_eq!(empty.present, Some(false));
        let missing = Response::observe(Err(tonic::Code::NotFound), Some("old"), Some("new"));
        assert_eq!(missing.status, Some(5));
        assert!(
            missing.present.is_none()
                && missing.changed.is_none()
                && missing.matches_first.is_none()
        );
    }

    #[test]
    fn native_polynomial_state_never_serializes_polynomial_contents() {
        let member = Member {
            connected: Some(true),
            main: Response::observe(
                Ok("private-main"),
                Some("private-old"),
                Some("private-first"),
            ),
            pet: Response::observe(Ok("private-pet"), None, None),
        };
        let value = serde_json::to_value(member).unwrap();
        assert!(!value.to_string().contains("private"));
        for response in [&value["main"], &value["pet"]] {
            assert_eq!(response.as_object().unwrap().len(), 4);
            assert!(response
                .as_object()
                .unwrap()
                .values()
                .all(|value| value.is_null() || value.is_boolean() || value.is_i64()));
        }
    }
}
