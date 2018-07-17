extern crate actix;
extern crate actix_web;
extern crate cookie;
extern crate env_logger;
extern crate futures;
extern crate time;
#[macro_use]
extern crate diesel;

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate r2d2;
extern crate md5;
extern crate jsonwebtoken as jwt;

use std::env;

use actix::prelude::*;
use actix_web::{
    fs, middleware, server, App, AsyncResponder, Form, FutureResponse, HttpRequest, HttpResponse,
    Result,
};

use actix_web::http::{Method, StatusCode};

use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use futures::Future;

use jwt::{decode, encode, Validation};

// database
mod db;
mod models;
mod schema;

mod cookie_auth;
mod email_auth;
mod fb_auth;


use cookie_auth::{CookieIdentityPolicy, IdentityService, RequestIdentity};
use db::{DbExecutor, LoginUser};

use email_auth::Email;
use fb_auth::Facebook;

/// State with DbExecutor address
struct AppState {
    db: Addr<Syn, DbExecutor>,
}

#[derive(Debug, Serialize, Deserialize)]
enum AuthType {
    Email,
    Facebook,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    auth_type: AuthType,
    token: Option<String>,
}

fn p404(req: HttpRequest<AppState>) -> Result<fs::NamedFile> {
    open_static(req, "static/404.html")
}

fn open_static(_req: HttpRequest<AppState>, filename: &str) -> Result<fs::NamedFile> {
    Ok(fs::NamedFile::open(filename)?.set_status_code(StatusCode::NOT_FOUND))
}

fn user_good(req: &mut HttpRequest<AppState>) -> bool {
    let token = req.identity().unwrap_or("Anonymous").to_owned();

    if token == "Anonymous" {
        return false;
    }

    let key = "SECRET";
    let id = match env::var(key) {
        Ok(value) => {
            let token_data = decode::<Claims>(&token, value.as_ref(), &Validation::default())
                .expect("Invalid token");

            token_data.claims.sub
        }
        Err(_) => "Anonymous".to_owned(),
    };

    id != "Anonymous" // need jwt
}

fn index(mut req: HttpRequest<AppState>) -> HttpResponse {
    if user_good(&mut req) {
        return HttpResponse::Found().header("location", "/secret").finish();
    }

    HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/index.html"))
}

fn login_fb((mut req, params): (HttpRequest<AppState>, Form<Facebook>)) -> HttpResponse {
    match generate_jwt(
        params.user_id.clone(),
        AuthType::Facebook,
        Some(params.access_token.clone()),
    ) {
        Ok(token) => {
            req.remember(token);
            HttpResponse::Found().header("location", "/secret").finish()
        }
        Err(_) => HttpResponse::build(StatusCode::FORBIDDEN)
            .content_type("text/html; charset=utf-8")
            .body(include_str!("../static/login_false.html")),
    }
}

fn validate(password: String, usr: models::User) -> bool {
    let digest = md5::compute(password);

    format!("{:x}", digest) == usr.passwd
}

fn generate_jwt(sub: String, auth_type: AuthType, token: Option<String>) -> Result<String> {
    let key = "SECRET";
    match env::var(key) {
        Ok(value) => {
            let header = jwt::Header::default();
            let claims = Claims {
                sub,
                auth_type,
                token,
            };

            let token = encode(&header, &claims, value.as_ref()).unwrap(); // FIXME

            Ok(token)
        }
        Err(err) => Err(actix_web::error::ErrorInternalServerError(err)),
    }
}

fn login_email(
    (mut req, params): (HttpRequest<AppState>, Form<Email>),
) -> FutureResponse<HttpResponse> {
    req.state()
        .db
        .send(LoginUser {
            email: params.login.clone(),
        })
        .from_err()
        .and_then(move |res| match res {
            Ok(value) => {
                if let Some(user) = value {
                    if validate(params.password.clone(), user) {
                        match generate_jwt(params.login.clone(), AuthType::Email, None) {
                            Ok(token) => {
                                req.remember(token);
                                Ok(HttpResponse::Found().header("location", "/secret").finish())
                            }
                            Err(err) => Err(err),
                        }
                    } else {
                        Ok(HttpResponse::build(StatusCode::FORBIDDEN)
                            .content_type("text/html; charset=utf-8")
                            .body(include_str!("../static/login_false.html")))
                    }
                } else {
                    Ok(HttpResponse::build(StatusCode::FORBIDDEN)
                        .content_type("text/html; charset=utf-8")
                        .body(include_str!("../static/403.html")))
                }
            }
            Err(_) => Ok(HttpResponse::InternalServerError().into()),
        })
        .responder()
}

fn logout(mut req: HttpRequest<AppState>) -> HttpResponse {
    req.forget();
    HttpResponse::Found().header("location", "/").finish()
}

fn secret(mut req: HttpRequest<AppState>) -> HttpResponse {
    if user_good(&mut req) {
        return HttpResponse::build(StatusCode::OK)
            .content_type("text/html; charset=utf-8")
            .body(include_str!("../static/secret.html"));
    }

    HttpResponse::build(StatusCode::FORBIDDEN)
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/403.html"))
}

fn main() {
    env::set_var("RUST_LOG", "actix_web=debug");
    env_logger::init();

    let sys = actix::System::new("stq_web_test");

    let manager = ConnectionManager::<SqliteConnection>::new("test.db");
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");

    let db_addr = SyncArbiter::start(3, move || DbExecutor(pool.clone()));

    let _addr = server::new(move || {
        App::with_state(AppState {
            db: db_addr.clone(),
        }).middleware(middleware::Logger::default())
            .middleware(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth")
                    .secure(false),
            ))
            .resource("/", |r| {
                r.method(Method::GET).with(index);
            })
            .resource("login_fb", |r| {
                r.method(Method::POST).with(login_fb);
            })
            .resource("login_email", |r| {
                r.method(Method::POST).with(login_email);
            })
            .resource("/secret", |r| r.method(Method::GET).f(secret))
            .resource("/logout", |r| r.f(logout))
            .default_resource(|r| {
                r.method(Method::GET).f(p404);
            })
    }).bind("127.0.0.1:8081")
        .expect("Can not bind to 127.0.0.1:8081")
        .start();

    let _ = sys.run();
}
