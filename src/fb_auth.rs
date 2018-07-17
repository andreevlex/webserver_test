#[derive(Debug, Serialize, Deserialize)]
pub struct Facebook {
    #[serde(rename = "accessToken")]
    pub access_token: String,

    #[serde(rename = "expiresIn")]
    pub expires_in: String,

    #[serde(rename = "signedRequest")]
    pub signed_request: String,

    #[serde(rename = "userID")]
    pub user_id: String,
}
