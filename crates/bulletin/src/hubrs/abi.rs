use alloy_sol_types::sol;

// IBulletin precompile address on hub.rs chain
pub const BULLETIN_PRECOMPILE_ADDRESS: [u8; 20] = {
    let mut addr = [0u8; 20];
    addr[18] = 0x08;
    addr[19] = 0x11;
    addr
};

sol! {
    /// IBulletin precompile interface at address 0x0811 on hub.rs
    #[derive(Debug)]
    interface IBulletin {
        /// Register a new namespace on the bulletin board
        function registerNamespace(string memory namespace) external;

        /// Create a post in a namespace with payload, proof, and optional artifact
        function createPost(
            string memory namespace,
            bytes memory payload,
            bytes memory proof,
            string memory artifact
        ) external;

        /// Read a post by namespace and ID, returns JSON-encoded post bytes
        function getPost(
            string memory namespace,
            string memory id
        ) external view returns (bytes memory);
    }
}
