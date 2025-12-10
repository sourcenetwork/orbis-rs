// Include the generated proto code
pub mod crypto_service {
    tonic::include_proto!("crypto_service");
}

use crypto_service::crypto_service_client::CryptoServiceClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the server
    let _client = CryptoServiceClient::connect("http://[::1]:50051").await?;
    Ok(())
}
