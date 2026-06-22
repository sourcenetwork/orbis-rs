use clap::Parser;
use orbis_node::{run, Args};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(Args::parse()).await
}
