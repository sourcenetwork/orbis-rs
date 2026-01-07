pub mod common;
pub mod error;
pub mod r#trait;

#[cfg(feature = "memory")]
pub mod memory;
#[cfg(feature = "memory")]
pub use memory::MemoryStorage as LocalStorageImpl;
#[cfg(feature = "redb")]
pub mod redb;
#[cfg(feature = "redb")]
pub use redb::RedbStorage as LocalStorageImpl;

#[cfg(test)]
mod tests;
