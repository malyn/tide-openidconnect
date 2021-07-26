use crate::request_ext::{OpenIdConnectRequestExtData, OpenIdConnectRequestExtInternal};
use tide::{Middleware, Next, Request, Route};

/// Authorization extensions to Tide [Route](tide::Route) handles.
///
/// Adds an [`authenticated()`](OpenIdConnectRouteExt::authenticated)
/// function to Tide's Route handles which can be used to require
/// authentication on specific routes/HTTP methods. Without this
/// extension, users must manually navigate to the login path in order
/// to begin the authentication process. This extension can be placed
/// before any route in order to force unauthenticated requests to that
/// route to go through the login process. This is an easy way to
/// protect your routes without requiring that they individually check
/// the request's authentication status.
///
/// By default, the `authenticated()` route extension uses the standard
/// HTTP redirect process -- `302 Found` with a `Location` header. This
/// works well for user navigation, but may run afoul of HTTP
/// [Cross-Origin Resource Sharing] (CORS) protections if the request
/// was initiated by a client-side `XMLHttpRequest` or `fetch`.
///
/// For example, redirecting certain forms of `POST` requests requires
/// that the *Identity Provider's* authorization endpoint return the
/// proper CORS headers during the "preflight" phase of the HTTP
/// request, otherwise the request will be blocked by the browser and
/// the authentication process will fail.
///
/// In those situations your client-side application will need to
/// perform the redirect. See the
/// [`redirect_strategy`](crate::redirect_strategy) module for more
/// information.
///
/// [Cross-Origin Resource Sharing]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
///
/// # Example
///
/// ```no_run
/// use tide_openidconnect::{self, OpenIdConnectRouteExt};
/// # type Request = tide::Request<()>;
/// # async_std::task::block_on(async {
/// # let mut app = tide::new();
///
/// app.at("/").get(|req: Request| async { Ok("Unprotected route") });
///
/// app.at("/secret")
///     .authenticated()
///     .get(|req: Request| async { Ok("Protected GET") })
///     .post(|req: Request| async { Ok("Protected POST") });
///
/// app.at("/semi-secret")
///     .get(|req: Request| async { Ok("*Unprotected* GET") })
///     .authenticated()
///     .post(|req: Request| async { Ok("Protected POST") });
///
/// # })
/// ```
pub trait OpenIdConnectRouteExt {
    /// Requires authentication on the subsequent portions of this
    /// route, redirecting the browser to the login page if the request
    /// is not authenticated.
    fn authenticated(&mut self) -> &mut Self;
}

impl<'a, State: Clone + Send + Sync + 'static> OpenIdConnectRouteExt for Route<'a, State> {
    fn authenticated(&mut self) -> &mut Self {
        self.with(MustAuthenticateMiddleware {})
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
        // the next item in the middleware chain. Otherwise, redirect
        // the browser to the login page.
        match req.auth_state() {
            OpenIdConnectRequestExtData::Authenticated { .. } => {
                tide::log::debug!(
                    "Authenticated request; forwarding request to next item in middleware chain."
                );
                Ok(next.run(req).await)
            }
            OpenIdConnectRequestExtData::Unauthenticated { redirect_strategy } => {
                tide::log::debug!("Unauthenticated request; redirecting browser to login page.");
                Ok(redirect_strategy.redirect())
            }
        }
    }
}
