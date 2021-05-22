use std::sync::Arc;

use crate::redirect_strategy::RedirectStrategy;
use tide::Request;

pub(crate) enum OpenIdConnectRequestExtData {
    Authenticated {
        user_id: String,
    },
    Unauthenticated {
        redirect_strategy: Arc<dyn RedirectStrategy>,
    },
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
        match self.auth_state() {
            OpenIdConnectRequestExtData::Authenticated { user_id } => Some(user_id.clone()),
            _ => None,
        }
    }
}

pub(crate) trait OpenIdConnectRequestExtInternal {
    fn auth_state(&self) -> &OpenIdConnectRequestExtData;
}

impl<State> OpenIdConnectRequestExtInternal for Request<State>
where
    State: Send + Sync + 'static,
{
    fn auth_state(&self) -> &OpenIdConnectRequestExtData {
        self.ext()
            .expect("You must install OpenIdConnectMiddleware to access the Open ID request data.")
    }
}
