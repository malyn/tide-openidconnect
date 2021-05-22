use crate::request_ext::{OpenIdConnectRequestExtData, OpenIdConnectRequestExtInternal};
use tide::{Middleware, Next, Request, Route};

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
        match req.auth_state() {
            OpenIdConnectRequestExtData::Authenticated { user_id: _ } => {
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
