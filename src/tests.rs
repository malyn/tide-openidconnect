#![allow(clippy::unwrap_used)]

use std::{collections::HashMap, sync::Arc};

use async_lock::Mutex;
use async_std::prelude::*;
use once_cell::sync::Lazy;
use openidconnect::{HttpRequest, HttpResponse};
use tide::{
    http::headers::LOCATION,
    sessions::{MemoryStore, SessionMiddleware},
    Request, StatusCode,
};
use tide_testing::TideTestingExt;

use crate::{
    ClientId, ClientSecret, IssuerUrl, OpenIdConnectMiddleware, OpenIdConnectRouteExt, RedirectUrl,
};

const SECRET: [u8; 32] = *b"secrets must be >= 32 bytes long";

static ISSUER_URL: Lazy<IssuerUrl> =
    Lazy::new(|| IssuerUrl::new("https://localhost/issuer_url".to_string()).unwrap());
static CLIENT_ID: Lazy<ClientId> = Lazy::new(|| ClientId::new("CLIENT-ID".to_string()));
static CLIENT_SECRET: Lazy<ClientSecret> =
    Lazy::new(|| ClientSecret::new("CLIENT-SECRET".to_string()));
static REDIRECT_URL: Lazy<RedirectUrl> =
    Lazy::new(|| RedirectUrl::new("https://localhost/callback".to_string()).unwrap());

#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum Error {
    // /// Test error.
// #[error("Test error: {}", _0)]
// Test(String),
}

type PendingResponse = (String, Result<HttpResponse, Error>);

task_local! {
    static PENDING_RESPONSE: Arc<Mutex<Vec<PendingResponse>>> =
        Arc::new(Mutex::new(vec![]));
}

async fn set_pending_response(response: Vec<PendingResponse>) {
    let pending_response_guard = PENDING_RESPONSE.with(|pr| pr.clone());
    let mut pending_response = pending_response_guard.lock().await;
    *pending_response = response;
}

async fn pending_response_is_empty() -> bool {
    let pending_response_guard = PENDING_RESPONSE.with(|pr| pr.clone());
    let pending_response = pending_response_guard.lock().await;
    pending_response.is_empty()
}

pub(crate) async fn http_client(openid_request: HttpRequest) -> Result<HttpResponse, Error> {
    // Get the pending response, which must exist (otherwise the test
    // has a bug).
    let pending_response_guard = PENDING_RESPONSE.with(|pr| pr.clone());
    let mut pending_response = pending_response_guard.lock().await;

    // Pop the first request from the vector, *ensure that it matches
    // the request URI,* then return that response.
    if pending_response.is_empty() {
        panic!("No pending response for URL \"{}\"", openid_request.url);
    }
    let (expected_uri, response) = pending_response.remove(0);
    assert_eq!(openid_request.url.to_string(), expected_uri);
    response
}

fn create_discovery_response() -> PendingResponse {
    (
        "https://localhost/issuer_url/.well-known/openid-configuration".to_string(),
        Ok(HttpResponse {
            status_code: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: "{
                \"issuer\":\"https://localhost/issuer_url\",
                \"authorization_endpoint\":\"https://localhost/authorization\",
                \"jwks_uri\":\"https://localhost/jwks\",
                \"response_types_supported\":[\"code\"],
                \"subject_types_supported\":[\"public\"],
                \"id_token_signing_alg_values_supported\":[\"RS256\"]
            }"
            .as_bytes()
            .into(),
        }),
    )
}

fn create_jwks_response() -> PendingResponse {
    (
        "https://localhost/jwks".to_string(),
        Ok(HttpResponse {
            status_code: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: "{\"keys\":[]}".as_bytes().into(),
        }),
    )
}

#[derive(Debug, PartialEq)]
struct ParsedAuthorizeUrl {
    host: String,
    path: String,
    response_type: String,
    client_id: String,
    scopes: String,
    state: Option<String>,
    nonce: Option<String>,
    redirect_uri: String,
}

impl ParsedAuthorizeUrl {
    fn default() -> Self {
        Self {
            host: "localhost".to_owned(),
            path: "/authorization".to_owned(),
            response_type: "code".to_owned(),
            client_id: CLIENT_ID.to_string(),
            scopes: "openid".to_owned(),
            state: None,
            nonce: None,
            redirect_uri: "https://localhost/callback".to_string(),
        }
    }

    fn from_url(s: impl AsRef<str>) -> Self {
        let url = openidconnect::url::Url::parse(s.as_ref()).unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();

        Self {
            host: url.host_str().unwrap().to_owned(),
            path: url.path().to_owned(),
            response_type: query.get("response_type").unwrap().to_owned(),
            client_id: query.get("client_id").unwrap().to_owned(),
            scopes: query.get("scope").unwrap().to_owned(),
            state: Some(query.get("state").unwrap().to_owned()),
            nonce: Some(query.get("nonce").unwrap().to_owned()),
            redirect_uri: query.get("redirect_uri").unwrap().to_owned(),
        }
    }

    fn with_nonce(self, nonce: Option<String>) -> Self {
        Self { nonce, ..self }
    }

    fn with_scopes(self, scopes: impl AsRef<str>) -> Self {
        Self {
            scopes: scopes.as_ref().to_owned(),
            ..self
        }
    }

    fn with_state(self, state: Option<String>) -> Self {
        Self { state, ..self }
    }
}

#[async_std::test]
async fn middleware_can_be_initialized() -> tide::Result<()> {
    set_pending_response(vec![create_discovery_response(), create_jwks_response()]).await;

    OpenIdConnectMiddleware::new(&ISSUER_URL, &CLIENT_ID, &CLIENT_SECRET, &REDIRECT_URL).await;

    assert!(pending_response_is_empty().await);

    Ok(())
}

#[async_std::test]
async fn middleware_provides_login_route() -> tide::Result<()> {
    let mut app = tide::new();
    app.with(SessionMiddleware::new(MemoryStore::new(), &SECRET));

    set_pending_response(vec![create_discovery_response(), create_jwks_response()]).await;
    app.with(
        OpenIdConnectMiddleware::new(&ISSUER_URL, &CLIENT_ID, &CLIENT_SECRET, &REDIRECT_URL).await,
    );

    let res = app.get("/login").await?;
    assert_eq!(res.status(), StatusCode::Found);
    assert_eq!(
        ParsedAuthorizeUrl::from_url(res.header(LOCATION).unwrap().get(0).unwrap().as_str())
            .with_nonce(None)
            .with_state(None),
        ParsedAuthorizeUrl::default(),
    );

    Ok(())
}

#[async_std::test]
async fn login_path_can_be_changed() -> tide::Result<()> {
    let mut app = tide::new();
    app.with(SessionMiddleware::new(MemoryStore::new(), &SECRET));

    set_pending_response(vec![create_discovery_response(), create_jwks_response()]).await;
    app.with(
        OpenIdConnectMiddleware::new(&ISSUER_URL, &CLIENT_ID, &CLIENT_SECRET, &REDIRECT_URL)
            .await
            .with_login_path("/oauthlogin"),
    );

    let res = app.get("/oauthlogin").await?;
    assert_eq!(res.status(), StatusCode::Found);
    assert_eq!(
        ParsedAuthorizeUrl::from_url(res.header(LOCATION).unwrap().get(0).unwrap().as_str())
            .with_nonce(None)
            .with_state(None),
        ParsedAuthorizeUrl::default(),
    );

    Ok(())
}

#[async_std::test]
async fn oauth_scopes_can_be_changed() -> tide::Result<()> {
    let mut app = tide::new();
    app.with(SessionMiddleware::new(MemoryStore::new(), &SECRET));

    set_pending_response(vec![create_discovery_response(), create_jwks_response()]).await;
    app.with(
        OpenIdConnectMiddleware::new(&ISSUER_URL, &CLIENT_ID, &CLIENT_SECRET, &REDIRECT_URL)
            .await
            .with_scopes(&["profile"]),
    );

    let res = app.get("/login").await?;
    assert_eq!(res.status(), StatusCode::Found);
    assert_eq!(
        ParsedAuthorizeUrl::from_url(res.header(LOCATION).unwrap().get(0).unwrap().as_str())
            .with_nonce(None)
            .with_state(None),
        ParsedAuthorizeUrl::default().with_scopes("openid profile"),
    );

    Ok(())
}

// async fn logic_panics_on_missing_session_middleware() -> tide::Result<()> {
// Same as above, but we get a panic if the session middleware was not configured.

// async fn middleware_implements_redirect_handler() -> tide::Result<()> {
// Request to redirect_url (with the authorization code and stuff): checks the nonce and CSRF, makes the token call, sets session state, can get req.user_id() or whatever.

// async fn redirect_handler_rejects_invalid_csrf() -> tide::Result<()> {
// Same as above but with a non-matching CSRF: error.

// async fn redirect_handler_rejects_invalid_nonce() -> tide::Result<()> {
// Same as above but with a non-matching nonce: error.

// async fn redirect_handler_errors_on_missing_session_middleware() -> tide::Result<()> {
// *Error* (not panic) on missing session middleware, since this is indistinguishable from an expired session that was simply not present in the session store.
// I *think.* Let's verify that this is in fact what happens, because maybe we want one version that panics (if we can in fact detect that the session middleware is missing).

// TODO Move these to `route_ext.rs`?
// async fn unauthenticated_routes_do_not_force_login() -> tide::Result<()> {
// Basically: a request to a random /foo URL works.

#[async_std::test]
async fn authenticated_routes_require_login() -> tide::Result<()> {
    let mut app = tide::new();
    app.with(SessionMiddleware::new(MemoryStore::new(), &SECRET));

    set_pending_response(vec![create_discovery_response(), create_jwks_response()]).await;
    app.with(
        OpenIdConnectMiddleware::new(&ISSUER_URL, &CLIENT_ID, &CLIENT_SECRET, &REDIRECT_URL).await,
    );

    app.at("/needsauth")
        .authenticated()
        .get(|_req: Request<()>| -> std::pin::Pin<Box<dyn Future<Output = tide::Result> + Send>> {
            panic!(
                "An unauthenticated request should not have made it to an `authenticated()` handler."
            );
        });

    let res = app.get("/needsauth").await?;
    assert_eq!(res.status(), StatusCode::Found);
    assert_eq!(
        res.header(LOCATION).unwrap().get(0).unwrap().to_string(),
        "/login"
    );

    Ok(())
}

// async fn authenticated_and_unauthenticated_routes_can_coexist() -> tide::Result<()> {
// Basically: two routes, one that works and one that redirects to /login.
