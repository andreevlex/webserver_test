use serde_derive;
use serde_json;

#[derive(Debug, Serialize, Deserialize)]
pub struct Facebook {
    pub accessToken: String,
    pub expiresIn: String,
    pub signedRequest: String,
    pub userID: String,
}
