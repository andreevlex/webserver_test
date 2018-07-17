#[derive(Debug, Serialize, Deserialize)]
pub struct Email {
    pub login: String,
    pub password: String,
}
