//! Db executor actor
use actix::prelude::*;
use actix_web::*;

use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};

use models;
use schema;

/// This is db executor actor. We are going to run 3 of them in parallel.
pub struct DbExecutor(pub Pool<ConnectionManager<SqliteConnection>>);

pub struct LoginUser {
    pub email: String,
}

impl Message for LoginUser {
    type Result = Result<Option<models::User>, Error>;
}

impl Actor for DbExecutor {
    type Context = SyncContext<Self>;
}

impl Handler<LoginUser> for DbExecutor {
    type Result = Result<Option<models::User>, Error>;

    fn handle(&mut self, msg: LoginUser, _: &mut Self::Context) -> Self::Result {
        use self::schema::users::dsl::*;

        let conn: &SqliteConnection = &self.0.get().unwrap();

        let mut items = users
            .filter(email.eq(&msg.email))
            .load::<models::User>(conn)
            .map_err(|_| error::ErrorInternalServerError("Error loading person"))?;

        Ok(items.pop())
    }
}
