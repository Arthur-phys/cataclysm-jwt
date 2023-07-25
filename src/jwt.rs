use std::collections::HashMap;

#[derive(Debug)]
pub struct JWT {
    pub header: HashMap<String,String>,
    pub payload: HashMap<String,String>,
    pub signature: String,
    pub raw_jwt: String
}