use std::collections::HashMap;

pub struct JWT {
    pub header: HashMap<String,String>,
    pub payload: HashMap<String,String>,
    pub signature: String
}