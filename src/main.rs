#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_json;

use handlebars::Handlebars;
use iron::prelude::*;
use iron::{ status, AroundMiddleware };
use iron::headers::{ ContentType, Location };
use iron::mime::{ Mime, TopLevel, SubLevel };
use params::{ Params, Value };
use router::Router;
use secure_session::middleware::{ SessionMiddleware, SessionConfig };
use secure_session::session::ChaCha20Poly1305SessionManager;
use serde::{ Deserialize, Serialize };

use rusqlite::{ Connection, Error, NO_PARAMS };

use std::fs::File;
use std::io::Read;
use std::path::Path;

const STYLE_STRING:&'static str = include_str!("page/materialize.min.css");
const HOME_STRING:&'static str = include_str!("page/home.html");
const LOGIN_STRING:&'static str = include_str!("page/login.html");

const DDL_CREATE:&'static str = include_str!("ddl_create.sql");
const DDL_INSERT:&'static str = include_str!("ddl_insert.sql");

#[derive(Deserialize, Serialize)]
struct RawConfig {
    port: Option<u16>,
    key: Option<String>,
    db_name: Option<String>,
}

struct InsecureConfig {
    port: u16,
    key: [u8; 32],
    db_name: String,
}

#[derive(Deserialize, Serialize)]
struct Session {
    username: String,
}

struct SessionKey {}
impl typemap::Key for SessionKey {
    type Value = Session;
}

fn load_insecure_config(config_name:&str) -> InsecureConfig {
    let mut config = InsecureConfig {
        port: 3000,
        key: *b"secret1secret2secret3secret4abcd",
        db_name: String::from("insecure.db"),
    };

    let mut config_file = match File::open(Path::new(config_name)) {
        Ok(file) => file,
        Err(_) => {
            println!("could not find config {}, using defaults", config_name);
            return config;
        },
    };
    let mut config_string = String::new();
    match config_file.read_to_string(&mut config_string) {
        Ok(_) => match toml::from_str::<RawConfig>(&config_string) {
            Ok(raw_config) => {
                config.port = match raw_config.port {
                    Some(port) => port,
                    None => config.port,
                };

                config.key = match raw_config.key {
                    Some(key) => {
                        if key.len() == 32 {
                            let mut k = [0; 32];
                            k.copy_from_slice(&key.as_bytes()[0..32]);
                            k
                        } else {
                            println!("key {} of insufficient length", key);
                            println!("key length of 32 bytes required");
                            config.key
                        }
                    },
                    None => config.key,
                };

                config.db_name = match raw_config.db_name {
                    Some(db_name) => db_name,
                    None => config.db_name,
                };

                config
            },
            Err(_) => config,
        },
        Err(_) => config,
    }
}

lazy_static! {
    static ref CONFIG:InsecureConfig = load_insecure_config("config.toml");
}

fn main() {
    // Open DB
    println!("Opening DB insecure.db...");
    let _conn = match open_db(&CONFIG.db_name, true) {
        Ok(conn) => conn,
        Err(e) => {
            println!("Error opening db: {}", e);
            return;
        },
    };

    // Routes
    let mut router = Router::new();

    router.get("/", main_handler, "index");
    router.get("/style", style_handler, "style");
    router.get("/login", login_handler, "login");
    router.post("/login", login_post_handler, "post_login");
    router.get("/logout", logout_handler, "logout");

    let manager = ChaCha20Poly1305SessionManager::<Session>::from_key(CONFIG.key);
    let config = SessionConfig::default();
    let session = SessionMiddleware::<Session, SessionKey, ChaCha20Poly1305SessionManager<Session>>::new(manager, config);

    let handler = session.around(Box::new(router));

    match Iron::new(handler).http(&format!("0.0.0.0:{}", CONFIG.port)) {
        Ok(_) => println!("Listening on :{}", CONFIG.port),
        Err(e) => println!("{:?}", e),
    };
}

fn open_db(name:&str, ddl:bool) -> Result<Connection, Error> {
    let conn = match Connection::open(name) {
        Ok(conn) => conn,
        Err(_) => {
            println!("DB file {} not found, opening DB in memory", name);
            Connection::open_in_memory()?
        },
    };
    if ddl {
        conn.execute(DDL_CREATE, NO_PARAMS)?;
        conn.execute(DDL_INSERT, NO_PARAMS)?;
    }
    Ok(conn)
}

fn html_response(content:&str) -> Response {
    let mut res = Response::with((status::Ok, content));
    res.headers.set(ContentType::html());
    res
}

fn main_handler(req: &mut Request) -> IronResult<Response> {
    let username = req.extensions.get::<SessionKey>()
                      .map(|s| s.username.clone())
                      .unwrap_or(String::new());
    if username.is_empty() {
        let mut res = Response::with((status::Found, ""));
        res.headers.set(Location("/login".to_string()));
        Ok(res)
    } else {
        let reg = Handlebars::new();
        Ok(html_response(&reg.render_template(HOME_STRING, &json!({ "username": username })).unwrap()))
    }
}

fn style_handler(_req: &mut Request) -> IronResult<Response> {
    let mut res = Response::with((status::Ok, STYLE_STRING));
    res.headers.set(ContentType(Mime(TopLevel::Text, SubLevel::Css, vec![])));
    Ok(res)
}

fn login_handler(_req: &mut Request) -> IronResult<Response> {
    Ok(html_response(LOGIN_STRING))
}

fn logout_handler(req: &mut Request) -> IronResult<Response>  {
    let _ = req.extensions.remove::<SessionKey>();
    let mut res = Response::with((status::Found, ""));
    res.headers.set(Location("/login".to_string()));
    Ok(res)
}

fn login_post_handler(req: &mut Request) -> IronResult<Response> {
    // Get form data
    let params = match req.get_ref::<Params>() {
        Ok(params) => params,
        Err(_) => return Ok(html_response(&login_error_page("internal server error"))),
    };

    let username = match params.get("username").unwrap() {
        Value::String(username) => username,
        _ => return Ok(html_response(&login_error_page("Invalid username/password"))),
    };
    let password = match params.get("password").unwrap() {
        Value::String(password) => password,
        _ => return Ok(html_response(&login_error_page("Invalid username/password"))),
    };

    // DB stuff
    let conn = match open_db(&CONFIG.db_name, false) {
        Ok(conn) => conn,
        Err(_) => return Ok(html_response(&login_error_page("internal server error"))),
    };

    let mut statement = match conn.prepare(&format!("SELECT username FROM users WHERE username = '{}' AND password = '{}';", username, password)) {
        Ok(statement) => statement,
        Err(_) => return Ok(html_response(&login_error_page("internal server error"))),
    };
    let mut rows = match statement.query(NO_PARAMS) {
        Ok(rows) => rows,
        Err(_) => return Ok(html_response(&login_error_page("internal server error"))),
    };

    match rows.next().unwrap() {
        Some(row) => {
            let username:String = row.get(0).unwrap(); // Guranteed to be Some
            let _ = req.extensions.insert::<SessionKey>(Session { username });
            let mut res = Response::with((status::Found, ""));
            res.headers.set(Location("/".to_string()));
            Ok(res)
        },
        _ => Ok(html_response(&login_error_page("Invalid username/password"))),
    }
}

fn login_error_page(error:&str) -> String {
    let reg = Handlebars::new();
    reg.render_template(LOGIN_STRING, &json!({ "error": error })).unwrap()
}
