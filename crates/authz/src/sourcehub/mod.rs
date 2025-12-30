use crate::{
    error::{AuthZError, Result},
    r#trait::Authz,
};

#[cfg(test)]
mod tests;

pub struct SourceHubAuth;

impl Authz for SourceHubAuth {
    fn check(persmission: Vec<u8>, subject: String) -> Result<bool> {
        Ok(true)
    }
}

impl SourceHubAuth {
    pub fn get_policy() {}
}
