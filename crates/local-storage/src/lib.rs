pub mod common;
pub mod error;
pub mod r#trait;

#[cfg(feature = "memory")]
pub mod memory;
#[cfg(feature = "redb")]
pub mod redb;

// Enforce mutual exclusivity - only one backend can be selected
#[cfg(all(feature = "memory", feature = "redb"))]
compile_error!("Features 'memory' and 'redb' are mutually exclusive. Use --no-default-features to disable the default backend.");

// Export the selected implementation
#[cfg(feature = "memory")]
pub use memory::MemoryStorage as LocalStorageImpl;
#[cfg(feature = "redb")]
pub use redb::RedbStorage as LocalStorageImpl;

#[cfg(test)]
mod tests;
