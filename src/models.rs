#[derive(Serialize, Queryable)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub passwd: String,
}
