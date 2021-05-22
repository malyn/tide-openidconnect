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

mod isahc;
mod middleware;
pub mod redirect_strategy;
mod request_ext;
mod route_ext;

pub use crate::middleware::OpenIdConnectMiddleware;
pub use crate::request_ext::OpenIdConnectRequestExt;
pub use crate::route_ext::OpenIdConnectRouteExt;
pub use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};
