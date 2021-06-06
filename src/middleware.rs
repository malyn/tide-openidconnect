use std::sync::Arc;

use crate::redirect_strategy::{HttpRedirect, RedirectStrategy};
use crate::request_ext::OpenIdConnectRequestExtData;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, RedirectUrl, Scope, SubjectIdentifier,
};
use serde::{Deserialize, Serialize};
use tide::{http::Method, Middleware, Next, Redirect, Request, StatusCode};

// Why are we using cfg(not(test)) / cfg(test) to select the http_client
// implementation? Because oauth2-rs, the crate that powers openidconnect-rs,
// expects the http_client function to be an asynchronous function instead
// of a(n asynchronous) trait. I can't find a way to expose a `with_http_client`
// function in the middleware trait and so my only option is to hardcode
// the http_client when we call openidconnect-rs. But that prevents us from
// writing unit tests without also implementing (an HTTPS!) OpenID Connect
// *server* in the tests. The simplest solution is to use conditional
// compilation to select the mock client when running tests, although all
// things considered I feel like the best solution would be for oauth2-rs
// to accept an async trait for the http_client instead of an async function.
// Note that this issue doesn't affect the openidconnect-rs/oauth2-rs tests
// (in those crates) themselves, because they are written at a level where
// they can trivially pass in a mock async function; it is only the users
// of those crates that run into this mocking issue.
#[cfg(not(test))]
use crate::isahc::http_client;

#[cfg(test)]
use tests::http_client;

const SESSION_KEY: &str = "tide.oidc";

#[derive(Debug, Deserialize, Serialize)]
enum MiddlewareSessionState {
    PreAuth(CsrfToken, Nonce),
    PostAuth(SubjectIdentifier),
}

/// # Middleware to enable OpenID Connect-based authentication
///
/// ... add docs ...
///
/// ## Example
/// ```no_run
/// use tide_openidconnect::{self, OpenIdConnectRequestExt};
///
/// # async_std::task::block_on(async {
/// let mut app = tide::new();
///
/// // OpenID Connect middleware *requires* session storage.
/// app.with(tide::sessions::SessionMiddleware::new(
///     tide::sessions::MemoryStore::new(),
///     b"don't actually use a hardcoded secret",
/// ));
///
/// // Initialize the OpenID Connect middleware; normally all of these
/// // configuration values would come from an environment-specific config
/// // file.
/// app.with(
///     tide_openidconnect::OpenIdConnectMiddleware::new(
///         tide_openidconnect::IssuerUrl::new("https://your-tenant-name.us.auth0.com/".to_string()).unwrap(),
///         tide_openidconnect::ClientId::new("app-id-goes-here".to_string()),
///         tide_openidconnect::ClientSecret::new("app-secret-goes-here".to_string()),
///         tide_openidconnect::RedirectUrl::new("http://your.cool.site/callback".to_string()).unwrap(),
///     )
///     .await,
/// );
///
/// app.at("/").get(|req: tide::Request<()>| async move {
///     Ok(format!(
///         "If you got this far, then the user is authenticated, and their user id is {:?}",
///         req.user_id()
///     ))
/// });
///
/// # })
/// ```

pub struct OpenIdConnectMiddleware {
    login_path: String,
    redirect_url: RedirectUrl,
    scopes: Vec<Scope>,
    landing_path: String,
    client: CoreClient,
    redirect_strategy: Arc<dyn RedirectStrategy>,
}

impl std::fmt::Debug for OpenIdConnectMiddleware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenIdConnectMiddleware")
            .field("login_path", &self.login_path)
            .field("scopes", &self.scopes)
            .field("redirect_url", &self.redirect_url)
            .field("landing_path", &self.landing_path)
            .finish()
    }
}

impl OpenIdConnectMiddleware {
    /// Creates a new OpenIdConnectMiddleware with a mandatory Issuer URL,
    /// Client Id, Client Secret, and Redirect URL.
    ///
    /// # Defaults
    ///
    /// The defaults for OpenIdConnectMiddleware are:
    /// - redirect strategy: HttpRedirect
    /// - login path: "/login"
    /// - landing path: "/"
    pub async fn new(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        client_secret: ClientSecret,
        redirect_url: RedirectUrl,
    ) -> Self {
        // Get the OpenID Connect provider metadata.
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, http_client)
            .await
            .expect("Unable to load OpenID Connect provider metadata.");

        // Create the OpenID Connect client.
        let client =
            CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
                .set_redirect_uri(redirect_url.clone());

        // Initialize the middleware with our defaults.
        let login_path = "/login".to_string();
        Self {
            login_path: login_path.clone(),
            scopes: vec![Scope::new("openid".to_string())],
            redirect_url,
            landing_path: "/".to_string(),
            client,
            redirect_strategy: Arc::new(HttpRedirect::new(login_path)),
        }
    }

    /// Sets the path to the "login" route that will be intercepted by the
    /// middleware in order to redirect the browser to the OpenID Connect
    /// authentication page.
    ///
    /// Defaults to "/login".
    pub fn with_login_path(mut self, login_path: &str) -> Self {
        self.login_path = login_path.to_string();
        self
    }

    /// Adds one or more scopes to the OpenID Connect request.
    ///
    /// Defaults to "openid" (which is the minimum required scope).
    pub fn with_scopes(mut self, scopes: &[impl AsRef<str>]) -> Self {
        self.scopes = scopes
            .iter()
            .map(|s| Scope::new(s.as_ref().to_owned()))
            .collect();
        self
    }

    /// Sets the path where the browser will be sent after a successful
    /// login sequence.
    ///
    /// Defaults to "/".
    pub fn with_landing_path(mut self, landing_path: &str) -> Self {
        self.landing_path = landing_path.to_string();
        self
    }

    /// Sets the function used to generate responses to unauthenticated
    /// requests.
    ///
    /// Defaults to building a "302 Found" response with a Location
    /// header.
    pub fn with_unauthenticated_redirect_strategy<R>(mut self, redirect_strategy: R) -> Self
    where
        R: RedirectStrategy + 'static,
    {
        self.redirect_strategy = Arc::new(redirect_strategy);
        self
    }

    async fn generate_redirect<State>(&self, mut req: Request<State>) -> tide::Result
    where
        State: Clone + Send + Sync + 'static,
    {
        let mut request = self.client.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for s in &self.scopes {
            request = request.add_scope(s.clone());
        }
        let (authorize_url, csrf_token, nonce) = request.url();

        // Initialize the middleware's session state so that we can
        // validate the login after the user completes the authentication
        // flow.
        req.session_mut()
            .insert(
                SESSION_KEY,
                MiddlewareSessionState::PreAuth(csrf_token, nonce),
            )
            .expect("OpenIdConnectMiddleware also requires SessionMiddleware.");

        Ok(Redirect::new(&authorize_url).into())
    }

    async fn handle_callback<State>(&self, mut req: Request<State>) -> tide::Result
    where
        State: Clone + Send + Sync + 'static,
    {
        // Get the middleware state from the session. If this fails then
        // A) the browser got to the callback URL without actually going
        // through the auth process, or B) more likely, the session
        // middleware is configured with Strict cookies instead of Lax
        // cookies. We cannot tell at this level which error occurred,
        // so we just reject the request and log the error.
        if let Some(MiddlewareSessionState::PreAuth(csrf_token, nonce)) =
            req.session().get(SESSION_KEY)
        {
            // Extract the OpenID callback information and verify the CSRF
            // state.
            #[derive(Deserialize)]
            struct OpenIdCallback {
                code: AuthorizationCode,
                state: String,
            }
            let callback_data: OpenIdCallback = req.query()?;
            if &callback_data.state != csrf_token.secret() {
                return Err(tide::http::Error::from_str(
                    StatusCode::Unauthorized,
                    "Invalid CSRF state.",
                ));
            }

            // Exchange the code for a token.
            let token_response = self
                .client
                .exchange_code(callback_data.code)
                .request_async(http_client)
                .await
                .map_err(|error| tide::http::Error::new(StatusCode::InternalServerError, error))?;
            println!("Access token: {}", token_response.access_token().secret());
            println!("Scopes: {:?}", token_response.scopes());

            // Get the claims and verify the nonce.
            let claims = token_response
                .extra_fields()
                .id_token()
                .ok_or_else(|| {
                    tide::http::Error::from_str(
                        StatusCode::InternalServerError,
                        "OpenID Connect server did not return an ID token.",
                    )
                })?
                .claims(&self.client.id_token_verifier(), &nonce)
                .map_err(|error| tide::http::Error::new(StatusCode::Unauthorized, error))?;
            println!("ID token: {:?}", claims);
            println!("User id: {}", claims.subject().as_str());

            // Add the user id to the session state in order to mark this
            // session as authenticated.
            req.session_mut()
                .insert(
                    SESSION_KEY,
                    MiddlewareSessionState::PostAuth(claims.subject().clone()),
                )
                .expect("OpenIdConnectMiddleware also requires SessionMiddleware.");

            // The user has logged in; redirect them to the main site.
            Ok(Redirect::new(&self.landing_path).into())
        } else {
            tide::log::warn!(
                    "Missing OpenID Connect state in session; make sure SessionMiddleware is configured with SameSite::Lax (but do *not* mutate server-side state on GET requests if you make that change!)."
                );
            Err(tide::http::Error::from_str(
                StatusCode::InternalServerError,
                "Missing authorization state.",
            ))
        }
    }
}

#[tide::utils::async_trait]
impl<State> Middleware<State> for OpenIdConnectMiddleware
where
    State: Clone + Send + Sync + 'static,
{
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> tide::Result {
        // Is this URL one of the URLs that we need to intercept as part
        // of the OpenID Connect auth process? If so, apply the appropriate
        // part of the auth process according to the URL. If not, verify
        // that the request is authenticated, and if not, redirect the
        // browser to the login URL. And if they are authenticated, then
        // just proceed to the handler (after populating the request extension
        // fields).
        if req.method() == Method::Get && req.url().path() == self.login_path {
            self.generate_redirect(req).await
        } else if req.method() == Method::Get && req.url().path() == self.redirect_url.url().path()
        {
            self.handle_callback(req).await
        } else {
            // Get the middleware's session state (which will *not* be
            // present if the browser has not yet gone through the auth
            // process), then augment the request with the authentication
            // status.
            match req.session().get(SESSION_KEY) {
                Some(MiddlewareSessionState::PostAuth(subject)) => {
                    req.set_ext(OpenIdConnectRequestExtData::Authenticated {
                        user_id: subject.to_string(),
                    })
                }
                _ => req.set_ext(OpenIdConnectRequestExtData::Unauthenticated {
                    redirect_strategy: self.redirect_strategy.clone(),
                }),
            };

            // Call the downstream middleware.
            Ok(next.run(req).await)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use async_lock::Mutex;
    use once_cell::sync::Lazy;
    use openidconnect::{HttpRequest, HttpResponse};
    use tide::{http::headers::LOCATION, Request, StatusCode};
    use tide_testing::TideTestingExt;

    use super::*;
    use crate::route_ext::OpenIdConnectRouteExt;

    const SECRET: [u8; 32] = *b"secrets must be >= 32 bytes long";

    #[derive(Clone, Debug, thiserror::Error)]
    pub(crate) enum Error {
        // /// Test error.
    // #[error("Test error: {}", _0)]
    // Test(String),
    }

    type PendingResponse = Vec<(String, Result<HttpResponse, Error>)>;

    static PENDING_RESPONSE: Lazy<Arc<Mutex<PendingResponse>>> =
        Lazy::new(|| Arc::new(Mutex::new(vec![])));

    async fn set_pending_response(response: PendingResponse) {
        (*PENDING_RESPONSE.lock().await) = response;
    }

    pub(crate) async fn http_client(openid_request: HttpRequest) -> Result<HttpResponse, Error> {
        // Get the pending response, which must exist (otherwise the test
        // has a bug).
        let mut pending_response_guard = PENDING_RESPONSE.lock().await;
        let pending_response: &mut PendingResponse = (*pending_response_guard).as_mut();

        // Pop the first request from the vector, *ensure that it matches
        // the request URI,* then return that response.
        if pending_response.is_empty() {
            panic!("No pending response for URL \"{}\"", openid_request.url);
        }
        let (expected_uri, response) = pending_response.remove(0);
        assert_eq!(openid_request.url.to_string(), expected_uri);
        response
    }

    #[async_std::test]
    async fn unauthed_request_redirects_to_login_uri() -> tide::Result<()> {
        let mut app = tide::new();
        app.with(tide::sessions::SessionMiddleware::new(
            tide::sessions::MemoryStore::new(),
            &SECRET,
        ));

        set_pending_response(vec![
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
            ),
            (
                "https://localhost/jwks".to_string(),
                Ok(HttpResponse {
                    status_code: http::StatusCode::OK,
                    headers: http::HeaderMap::new(),
                    body: "{\"keys\":[]}".as_bytes().into(),
                }),
            ),
        ])
        .await;

        // TODO Maybe have an `async fn with_provider_metadata(IssuerUrl)`
        // that is for "normal" use, but then also a ... `with_config()`
        // or something function that can be used if you do *not* have a
        // provider endpoint (and for unit tests)? And then we just use
        // that function here after verifying that provider metadata works...
        app.with(
            OpenIdConnectMiddleware::new(
                IssuerUrl::new("https://localhost/issuer_url".to_string()).unwrap(),
                ClientId::new("CLIENT-ID".to_string()),
                ClientSecret::new("CLIENT-SECRET".to_string()),
                RedirectUrl::new("https://localhost/callback".to_string()).unwrap(),
            )
            .await,
        );

        app.at("/")
            .authenticated()
            .get(|_req: Request<()>| -> std::pin::Pin<Box<dyn futures_lite::Future<Output = tide::Result> + Send>> {
                panic!(
                    "An unauthenticated request should not have made it to an `authenticated()` handler."
                );
            });

        let res = app.get("/").await?;
        assert_eq!(res.status(), StatusCode::Found);
        assert_eq!(
            res.header(LOCATION).unwrap().get(0).unwrap().to_string(),
            "/login"
        );

        Ok(())
    }
}
