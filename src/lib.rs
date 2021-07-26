//! OpenID Connect authentication middleware for Tide.
//!
//! This crate provides middleware that can be used to authenticate the
//! users of a Tide application, optionally preventing access to certain
//! routes unless the request has been authenticated. The middleware does
//! not interact with, store, or otherwise process user credentials, but
//! instead relies on an [OpenID Connect] Identity Provider to authenticate
//! the user.
//!
//! Identity Providers manage user credentials, may or may not allow
//! user sign ups, and use the [OAuth 2.0] framework to allow
//! applications to request tokens. Those tokens can then be used to
//! identify users and grant them access to the application. This crate
//! provides the functionality necessary to integrate with Identity
//! Providers, perform token exchanges, and make the results available
//! to Tide requests.
//!
//! [Auth0], [Azure], and [Google] are just a few examples of OpenID
//! Connect-compatible identity providers
//!
//! ## Login Flow
//!
//! This middleware uses the OAuth 2.0 [Authorization Code Grant] flow,
//! which is a redirection-based flow: the user navigates to the login
//! path (`/login` [by
//! default](OpenIdConnectMiddleware::with_login_path)) and then the
//! middleware redirects the browser to the Identity Provider's
//! authorization endpoint. After a successful sign in, the browser will
//! be redirected to the [login landing
//! path](OpenIdConnectMiddleware::with_login_landing_path).
//!
//! One way to initiate this process is to check
//! the authentication status of each request using the
//! [`is_authenticated()`](OpenIdConnectRequestExt::is_authenticated)
//! request extension and then display a link to the login path if the
//! request is not authenticated.
//!
//! This crate also provides a [route extension](OpenIdConnectRouteExt)
//! that can force unauthenticated requests to go through the login
//! process. This is an easy way to protect your routes without
//! requiring that they individually check the request's authentication
//! status. Using this route extension, an unauthenticated request will
//! automatically redirect the browser to the login path, and then to
//! the Identity Provider.
//!
//! Note that using this route extension comes with certain caveats;
//! see the [`OpenIdConnectRouteExt`] docs for more information.
//!
//! ## Logout Flow
//!
//! Users can log out of the application by navigating to the logout
//! path (which [defaults](OpenIdConnectMiddleware::with_logout_path) to
//! `/logout`); this destroys their entire Tide session and returns them
//! to the [logout landing
//! path](OpenIdConnectMiddleware::with_logout_landing_path). You can
//! optionally [configure the logout
//! process](OpenIdConnectMiddleware::with_logout_destroys_session) to
//! only clear the authentication state from the session, leaving the
//! remainder of the session data intact.
//!
//! Some Identity Providers also support clearing the browser state
//! related to the provider, and your application can optionally enable
//! that functionality by setting the
//! [`idp_logout_url`](Config::idp_logout_url) when configuring the
//! middleware.
//!
//! ## Tide Route Interception
//!
//! There are three routes used by this middleware in order to perform
//! the functions of the OAuth 2.0 flow. Here are the default values for
//! these paths, two of which have already been described above, and all
//! of which can be changed:
//!
//! - `/login` -- Initiates the OAuth 2.0 login process.
//! - `/logout` -- Destroys the session state and optionally clears
//!   the Identity Provider's state as well.
//! - `/callback` -- The "Redirect URL" to which the Identity Provider
//!   will send the browser after a successful sign in.
//!
//! You do *not* have to define these routes in your Tide server; the
//! middleware intercepts `GET` requests to those paths and handles them
//! on its own. Because of this behavior, those paths are *not*
//! available for use in your application.
//!
//! ## Session Middleware Requirements
//!
//! The primary output of the OpenID Connect middleware is to augment
//! the Tide request object with information about the authentication
//! state of the request. Tide's [session middleware](tide::sessions) is
//! used to track that state, and so the OpenID Connect middleware
//! *requires* that you install and configure session middleware in your
//! Tide application. This middleware will panic on the first login
//! request if the session middleware is not present.
//!
//! Furthermore, because of the various HTTP redirects in the OAuth 2.0
//! flow, the session cookie needs to be configured with the
//! [`SameSite::Lax`](tide::http::cookies::SameSite) security policy.
//! This is safe as long as your `GET` (and `HEAD`, `OPTIONS`, and
//! `TRACE`) requests do *not* mutate state or perform side-effecting
//! operations as part of processing the request. Protecting requests to
//! "safe" (read-only) HTTP methods that are not actually safe is the
//! primary reason to use the default session cookie policy of
//! `SameSite::Strict`. Attacks that target unsafe HTTP APIs using
//! cookies are known as Cross-Site Request Forgery (CSRF) attacks, and
//! `SameSite::Strict` is one of the easiest ways to defend against
//! those attacks, but `SameSite::Lax` is safe to use as long as your
//! `GET` (and `HEAD` and ...) requests are exclusively tasked with
//! returning data.
//!
//! Note that the OpenID Connect middleware *does* mutate auth state as
//! part of processing OAuth 2.0 `GET` requests, but it also implements
//! multiple levels of CSRF protection in order to protect those `GET`
//! requests from malicious attacks.
//!
//! ## Example
//!
//! ```no_run
//! use tide_openidconnect::{self, OpenIdConnectRequestExt, OpenIdConnectRouteExt};
//!
//! # async_std::task::block_on(async {
//! let mut app = tide::new();
//!
//! // OpenID Connect middleware *requires* session storage. Note that the
//! // cookies must be configured with `SameSite::Lax`.
//! app.with(
//!     tide::sessions::SessionMiddleware::new(
//!         tide::sessions::MemoryStore::new(),
//!         b"don't actually use a hardcoded secret",
//!     )
//!     .with_same_site_policy(tide::http::cookies::SameSite::Lax),
//! );
//!
//! // Initialize the OpenID Connect middleware; normally all of these
//! // configuration values would come from an environment-specific config
//! // file, and in fact that is why they are in their own struct (so that
//! // you can deserialize that struct from a file or environment variables).
//! app.with(
//!     tide_openidconnect::OpenIdConnectMiddleware::new(
//!         &tide_openidconnect::Config {
//!             issuer_url: tide_openidconnect::IssuerUrl::new("https://your-tenant-name.us.auth0.com/".to_string()).unwrap(),
//!             client_id: tide_openidconnect::ClientId::new("app-id-goes-here".to_string()),
//!             client_secret: tide_openidconnect::ClientSecret::new("app-secret-goes-here".to_string()),
//!             redirect_url: tide_openidconnect::RedirectUrl::new("http://your.cool.site/callback".to_string()).unwrap(),
//!             idp_logout_url: None,
//!         }
//!     )
//!     .await,
//! );
//!
//! // Define a basic Tide route, but protect it with the middleware's
//! // `.authenticated()` route extension.
//! app.at("/").authenticated().get(|req: tide::Request<()>| async move {
//!     Ok(format!(
//!         "If you got this far, then the request is authenticated, and your user id is {:?}",
//!         req.user_id()
//!     ))
//! });
//!
//! # })
//! ```
//!
//! [Auth0]: https://auth0.com/
//! [Authorization Code Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
//! [Azure]: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc
//! [Google]: https://developers.google.com/identity/protocols/oauth2/openid-connect
//! [OAuth 2.0]: https://datatracker.ietf.org/doc/html/rfc6749
//! [OpenID Connect]: https://openid.net/specs/openid-connect-core-1_0.html

#![forbid(unsafe_code, future_incompatible)]
#![deny(
    missing_debug_implementations,
    nonstandard_style,
    missing_docs,
    unreachable_pub,
    missing_copy_implementations,
    unused_qualifications,
    clippy::unwrap_in_result,
    clippy::unwrap_used
)]

mod isahc;
mod middleware;
pub mod redirect_strategy;
mod request_ext;
mod route_ext;

pub use crate::middleware::Config;
pub use crate::middleware::OpenIdConnectMiddleware;
pub use crate::request_ext::OpenIdConnectRequestExt;
pub use crate::route_ext::OpenIdConnectRouteExt;

#[doc(no_inline)]
pub use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};
