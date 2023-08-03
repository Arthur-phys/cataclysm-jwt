use std::collections::HashMap;

#[derive(Debug)]
/// # Usage
///
/// Simple struct to store a JWT in the most generic format possible.
/// A problem with other crates is that it asks that you know JWT fields prior to interacting with the server.
/// This implementation gives full control to the server implementer. They will have to validate every field of interest on their own, incluiding if such fields exists or not
/// and act accordingly. 
///
pub struct JWT {
    /// Header hashmap
    pub header: HashMap<String,String>,
    /// Payload hashmap
    pub payload: HashMap<String,String>,
    /// signature b64 encoded
    pub signature: String,
    /// Original jwt
    pub raw_jwt: String
}