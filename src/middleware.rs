use std::sync::Arc;

use crate::isahc;
use crate::redirect_strategy::{HttpRedirect, RedirectStrategy};
use crate::request_ext::OpenIdConnectRequestExtData;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, RedirectUrl, SubjectIdentifier,
};
use serde::{Deserialize, Serialize};
use tide::{http::Method, Middleware, Next, Redirect, Request, StatusCode};

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
        let provider_metadata =
            CoreProviderMetadata::discover_async(issuer_url, isahc::http_client)
                .await
                .unwrap();

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

    async fn generate_redirect<State>(&self, mut req: Request<State>) -> tide::Result
    where
        State: Clone + Send + Sync + 'static,
    {
        let (authorize_url, csrf_token, nonce) = self
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

        // Initialize the middleware's session state so that we can
        // validate the login after the user completes the authentication
        // flow.
        req.session_mut()
            .insert(
                SESSION_KEY,
                MiddlewareSessionState::PreAuth(csrf_token, nonce),
            )
            .unwrap();

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
                .request_async(isahc::http_client)
                .await
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
                .insert(
                    SESSION_KEY,
                    MiddlewareSessionState::PostAuth(claims.subject().clone()),
                )
                .unwrap();

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
mod tests {
    // use super::*;
    // use tide::Request;
    // use tide_testing::{surf::Response, TideTestingExt};
}
