//! Browser redirect strategies.
//!
//! Provides multiple browser redirect strategies for use by the
//! [`authenticated()`](crate::OpenIdConnectRouteExt::authenticated)
//! route extension:
//!
//! - [`HttpRedirect`] is a standard HTTP redirect that uses a `302
//!   Found` response with a `Location` header. This strategy works well
//!   if all of your requests are `GET` operations, or if your Identity
//!   Provider returns the proper CORS preflight headers.
//! - [`ClientSideRefresh`] allows you to use *client-side* code to
//!   redirect the browser and can be used to avoid CORS issues, but may
//!   add additional latency and browser window flashing.

use tide::{
    http::{
        headers::{HeaderName, HeaderValues, ToHeaderValues},
        mime,
    },
    Redirect, Response,
};

/// Redirect the browser to another location.
pub trait RedirectStrategy: Send + Sync {
    /// Redirects the browser to the location configured in the
    /// strategy.
    fn redirect(&self) -> Response;
}

/// HTTP-level redirect: `302 Found` with a `Location` header.
#[derive(Debug)]
pub struct HttpRedirect {
    path: String,
}

impl HttpRedirect {
    /// Create a new instance, with the location to which this strategy
    /// will redirect the browser.
    pub fn new(path: impl AsRef<str>) -> Self {
        Self {
            path: path.as_ref().to_string(),
        }
    }
}

impl RedirectStrategy for HttpRedirect {
    fn redirect(&self) -> Response {
        Redirect::new(self.path.clone()).into()
    }
}

/// Client-side "redirect:" by default, a meta refresh tag, but can be
/// configured to return a custom response.
#[derive(Debug)]
pub struct ClientSideRefresh {
    body: String,
    headers: Vec<(HeaderName, HeaderValues)>,
}

impl ClientSideRefresh {
    /// Create a new instance, with the location to which this strategy
    /// will redirect the browser.
    ///
    /// The redirect will be implemented as client-side "Meta Refresh"
    /// that instructs the browser to navigate to the given path
    /// immediately after loading the page.
    pub fn from_path(path: impl AsRef<str>) -> Self {
        let body = format!("<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0;URL='{0}'\" /></head><body></body></html>", path.as_ref());
        ClientSideRefresh::from_body(body)
    }

    /// Create a new instance, with the raw HTML body that will be
    /// returned to the browser in order to trigger the refresh.
    pub fn from_body(body: impl AsRef<str>) -> Self {
        Self {
            body: body.as_ref().to_string(),
            headers: Vec::new(),
        }
    }

    /// Adds a header to the client-side refresh response, usually in
    /// cases where a client-side framework is using the
    /// `XMLHttpRequest` or `fetch` APIs to send requests, and watches
    /// for a specific response header in order to effect a client-side
    /// redirect.
    pub fn with_header(mut self, name: impl Into<HeaderName>, values: impl ToHeaderValues) -> Self {
        self.headers.push((
            name.into(),
            values
                .to_header_values()
                .expect("Invalid header value.")
                .collect(),
        ));
        self
    }
}

impl RedirectStrategy for ClientSideRefresh {
    fn redirect(&self) -> Response {
        let mut res = Response::builder(200)
            .body(self.body.clone())
            .content_type(mime::HTML);

        for (name, values) in self.headers.iter() {
            res = res.header(name, values);
        }

        res.build()
    }
}
