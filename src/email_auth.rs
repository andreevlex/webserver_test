use serde_derive;
use serde_json;

#[derive(Debug, Serialize, Deserialize)]
pub struct Email {
    pub login: String,
    pub password: String,
}
