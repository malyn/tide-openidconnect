//! OpenID Connect-based authentication middleware for Tide.

#![forbid(unsafe_code, future_incompatible)]
#![deny(
    missing_debug_implementations,
    nonstandard_style,
    missing_docs,
    unreachable_pub,
    missing_copy_implementations,
    unused_qualifications
)]

pub mod redirect_strategy;

use std::sync::Arc;

use crate::redirect_strategy::{HttpRedirect, RedirectStrategy};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest::http_client,
    AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse,
};
use serde::Deserialize;
use tide::{
    http::cookies::SameSite,
    http::mime,
    http::{Cookie, Method},
    Middleware, Next, Redirect, Request, Response, Route, StatusCode,
};

pub use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};

const CSRF_COOKIE_KEY: &str = "tide.oidc.csrf";
const NONCE_COOKIE_KEY: &str = "tide.oidc.nonce";

const USERID_SESSION_KEY: &str = "tide.oidc.userid";

#[derive(Debug, Deserialize)]
struct OpenIdCallback {
    code: AuthorizationCode,
    state: String,
}

struct OpenIdConnectRequestExtData {
    user_id: Option<String>,
    redirect_strategy: Arc<dyn RedirectStrategy>,
}

/// Provides access to request-level OpenID Connect authorization data.
pub trait OpenIdConnectRequestExt {
    /// Gets the provider-specific user id of the authenticated user, or
    /// None if the request has not been authenticated.
    fn user_id(&self) -> Option<String>;
}

impl<State> OpenIdConnectRequestExt for Request<State>
where
    State: Send + Sync + 'static,
{
    fn user_id(&self) -> Option<String> {
        let ext_data: &OpenIdConnectRequestExtData = self
            .ext()
            .expect("You must install OpenIdConnectMiddleware to access the Open ID request data.");
        ext_data.user_id.clone()
    }
}

trait OpenIdConnectRequestExtInternal {
    fn build_redirect(&self) -> Response;
}

impl<State> OpenIdConnectRequestExtInternal for Request<State>
where
    State: Send + Sync + 'static,
{
    fn build_redirect(&self) -> Response {
        let ext_data: &OpenIdConnectRequestExtData = self
            .ext()
            .expect("You must install OpenIdConnectMiddleware to access the Open ID request data.");
        ext_data.redirect_strategy.redirect()
    }
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
///         "If you got this far, then the user is authenticated, and their user id is {}",
///         req.user_id()
///     ))
/// });
///
/// # })
/// ```

pub struct OpenIdConnectMiddleware {
    login_path: String,
    redirect_url: RedirectUrl,
    landing_path: String,
    client: CoreClient,
    redirect_strategy: Arc<dyn RedirectStrategy>,
}

impl std::fmt::Debug for OpenIdConnectMiddleware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenIdConnectMiddleware")
            .field("login_path", &self.login_path)
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
    /// - login path: "/login"
    /// - landing path: "/"
    pub async fn new(
        issuer_url: IssuerUrl,
        client_id: ClientId,
        client_secret: ClientSecret,
        redirect_url: RedirectUrl,
    ) -> Self {
        // Get the OpenID Connect provider metadata.
        let provider_metadata = CoreProviderMetadata::discover(&issuer_url, http_client).unwrap();

        // Create the OpenID Connect client.
        let client =
            CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
                .set_redirect_uri(redirect_url.clone());

        // Initialize the middleware with our defaults.
        let login_path = "/login".to_string();
        Self {
            login_path: login_path.clone(),
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

    async fn generate_redirect<State>(&self, req: Request<State>) -> tide::Result
    where
        State: Clone + Send + Sync + 'static,
    {
        let (authorize_url, csrf_state, nonce) = self
            .client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // TODO Scopes will need to be configurable once we turn this into middleware.
            // FIXME Crashes if we enable this due to: <https://github.com/ramosbugs/openidconnect-rs/issues/23>
            // .add_scope(Scope::new("profile".to_string()))
            .url();

        let mut response = Response::builder(StatusCode::Found)
            .header(tide::http::headers::LOCATION, authorize_url.to_string())
            .build();

        let secure_cookie = req.url().scheme() == "https";

        let openid_csrf_cookie = build_cookie(secure_cookie, CSRF_COOKIE_KEY, csrf_state.secret());
        response.insert_cookie(openid_csrf_cookie);

        let openid_nonce_cookie = build_cookie(secure_cookie, NONCE_COOKIE_KEY, nonce.secret());
        response.insert_cookie(openid_nonce_cookie);

        Ok(response)
    }

    async fn handle_callback<State>(&self, mut req: Request<State>) -> tide::Result
    where
        State: Clone + Send + Sync + 'static,
    {
        // Get the auth CSRF and Nonce values from the cookies.
        let openid_csrf_cookie = req.cookie(CSRF_COOKIE_KEY).unwrap();
        let csrf_state = CsrfToken::new(openid_csrf_cookie.value().to_string());

        let openid_nonce_cookie = req.cookie(NONCE_COOKIE_KEY).unwrap();
        let nonce = Nonce::new(openid_nonce_cookie.value().to_string());

        // Extract the OpenID callback information and verify the CSRF
        // cookie.
        let callback_data: OpenIdCallback = req.query()?;
        if &callback_data.state != csrf_state.secret() {
            return Err(tide::http::Error::from_str(
                StatusCode::Unauthorized,
                "Invalid CSRF state.",
            ));
        }

        // Exchange the code for a token.
        // TODO Needs to use an async HTTP client, which means we need to
        // build an openidconnect adapter to surf (which uses async-std,
        // just like Tide).
        let token_response = self
            .client
            .exchange_code(callback_data.code)
            .request(http_client)
            .unwrap();
        println!("Access token: {}", token_response.access_token().secret());
        println!("Scopes: {:?}", token_response.scopes());

        // Get the claims and verify the nonce.
        let claims = token_response
            .extra_fields()
            .id_token()
            .expect("Server did not return an ID token")
            .claims(&self.client.id_token_verifier(), &nonce)
            .unwrap();
        println!("ID token: {:?}", claims);
        println!("User id: {}", claims.subject().as_str());

        // Add the user id to the session state in order to mark this
        // session as authenticated.
        req.session_mut()
            .insert(USERID_SESSION_KEY, claims.subject().as_str())
            .unwrap();

        // The user has logged in; redirect them to the main site using
        // a *client-side* redirect. This is the only way to A) ensure
        // that the (new, with this request!) session cookie has the
        // "authenticated" state, and B) keep the session cookie as a
        // SameSite::Strict cookie. Browsers will not preserve cookies
        // across 302 Found redirects, so none of the cookies we set
        // would be preserved if we did a standard redirect. Instead,
        // our best option is to use an HTML/client-side redirect. Note
        // that whatever session the user might have started with will
        // be replaced by this session, since the session id cookie for
        // that initial session was not preserved across all of the
        // (auth) redirects.
        // TODO Make this configurable; by default we do client-side redirects,
        // but if the user switches their session to SameSite::Lax then
        // they can use normal redirects (and thus retain a single session
        // across auth, which would be the only reason to go with that
        // approach; presumably because you have some state prior to the
        // auth that you want to retain).
        // TODO In addition, make the HTML response configurable so that
        // sites could implement a prettier layout given that people will
        // see this page for the briefest time.
        let mut response = Response::builder(StatusCode::Ok)
            .content_type(mime::HTML)
            .body(format!("<!DOCTYPE html><html><head><title>Login Successful</title><meta http-equiv=\"refresh\" content=\"0;URL='{0}'\" /></head><body></body></html>", self.landing_path))
            .build();

        let secure_cookie = req.url().scheme() == "https";

        let openid_csrf_cookie = build_cookie(secure_cookie, CSRF_COOKIE_KEY, "");
        response.remove_cookie(openid_csrf_cookie);

        let openid_nonce_cookie = build_cookie(secure_cookie, NONCE_COOKIE_KEY, "");
        response.remove_cookie(openid_nonce_cookie);

        Ok(response)
    }
}

/// Builds a response that redirects the browser to the given path, using
/// a 302 Found response and the Location header.
pub fn build_redirect_response(path: &str) -> Response {
    Redirect::new(path).into()
}

/// Builds a response that redirects the browser to the given path, using
/// the HTMX HX-Redirect header (in a 200 OK, text/html response).
pub fn build_htmx_redirect_response(path: &str) -> Response {
    // This is the only way to get an HTMX AJAX request to
    // silently go through the auth process. That is because HTMX
    // is (sometimes) doing a POST, which we are redirecting to
    // the OpenID Connect provider, and thus requires that provider
    // to expose the proper CORS headers. But it doesn't, so we
    // get a CORS error. Using a client-side redirect (by way of
    // the HX-Redirect header *and a 200 OK, not 302 Found* response),
    // prevents the CORS check because the client is just navigating
    // to another location on its own.
    // TODO Add the above to our "Everything I know about CSRF" blog post.
    Response::builder(200)
        .body("")
        .content_type(mime::HTML)
        .header("HX-Redirect", path)
        .build()
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
            // Augment the request with the authentication status, then
            // forward the request on to the remainder of the middleware
            // chain (which then has the option of using that status to
            // accept/reject the request.
            req.set_ext(OpenIdConnectRequestExtData {
                user_id: req.session().get::<String>(USERID_SESSION_KEY),
                redirect_strategy: self.redirect_strategy.clone(),
            });

            // Call the downstream middleware.
            Ok(next.run(req).await)
        }
    }
}

struct MustAuthenticateMiddleware;

#[tide::utils::async_trait]
impl<State> Middleware<State> for MustAuthenticateMiddleware
where
    State: Clone + Send + Sync + 'static,
{
    async fn handle(&self, req: Request<State>, next: Next<'_, State>) -> tide::Result {
        // Is the request authenticated? If so, forward the request to
        // the next item in the middleware chain. Otherwise, redirect the
        // browser to the login page.
        if req.user_id().is_some() {
            tide::log::debug!(
                "Authenticated request; forwarding request to next item in middleware chain."
            );
            Ok(next.run(req).await)
        } else {
            tide::log::debug!("Unauthenticated request; redirecting browser to login page.");
            Ok(req.build_redirect())
        }
    }
}

/// Extends Tide's Route trait to add an `authenticated()` function, which
/// can be used to require authentication on specific routes/HTTP methods.
pub trait OpenIdConnectRouteExt {
    /// Requires authentication on the subsequent portions of this route,
    /// redirecting the browser to the login page if the request is not
    /// authenticated.
    fn authenticated(&mut self) -> &mut Self;
}

impl<'a, State: Clone + Send + Sync + 'static> OpenIdConnectRouteExt for Route<'a, State> {
    fn authenticated(&mut self) -> &mut Self {
        println!("authenticated() called on {}", self.path());
        self.with(MustAuthenticateMiddleware {})
    }
}

fn build_cookie(secure: bool, name: &str, value: &str) -> Cookie<'static> {
    // Note that these cookies *must* use SameSite::Lax since the
    // redirect from the auth provider will arrive as a GET request,
    // and SameSite::Strict cookies, by definition, are not sent on
    // a GET redirect from a third-party site. Normally that is what
    // you want when implementing CSRF protection, just in case your
    // GET requests mutate state (since many forms of CSRF protection
    // will avoid validating GET requests), but here we know we will
    // receive GET requests and so we need the cookies in order to
    // actually implement the CSRF protection.
    Cookie::build(name.to_string(), value.to_string())
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .secure(secure)
        .finish()
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use tide::Request;
    // use tide_testing::{surf::Response, TideTestingExt};
}
