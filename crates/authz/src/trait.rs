use crate::error::Result;

pub trait Authz {
    fn check(permission: Vec<u8>, subject: String) -> Result<bool>;
}
