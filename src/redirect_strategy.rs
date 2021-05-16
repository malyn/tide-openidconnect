//! Strategies for different forms of browser redirects.

use tide::{
    http::{
        headers::{HeaderName, HeaderValues, ToHeaderValues},
        mime,
    },
    Redirect, Response,
};

/// Strategy for redirecting the browser to a (login) path after receiving
/// an unauthenticated request to an authenticated route.
pub trait RedirectStrategy: Send + Sync {
    /// Gets the provider-specific user id of the authenticated user, or
    /// None if the request has not been authenticated.
    fn redirect(&self) -> Response;
}

/// Redirects the browser using an HTTP-level ("302 Found" with "Location"
/// header) redirect.
#[derive(Debug)]
pub struct HttpRedirect {
    path: String,
}

impl HttpRedirect {
    /// Creates a new HttpDirect with a mandatory path to which the browser
    /// will be redirected.
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

/// Redirects the browser using a client-side refresh; by default, a
/// "meta refresh" tag.
#[derive(Debug)]
pub struct ClientSideRefresh {
    body: String,
    headers: Vec<(HeaderName, HeaderValues)>,
}

impl ClientSideRefresh {
    /// Creates a new ClientSideRefresh that redirects the browser to the
    /// given path.
    pub fn from_path(path: impl AsRef<str>) -> Self {
        let body = format!("<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0;URL='{0}'\" /></head><body></body></html>", path.as_ref());
        ClientSideRefresh::from_body(body)
    }

    /// Creates a new ClientSideRefresh that redirects the browser to the
    /// using the contents of the given response body.
    pub fn from_body(body: impl AsRef<str>) -> Self {
        Self {
            body: body.as_ref().to_string(),
            headers: Vec::new(),
        }
    }

    /// Adds a header to the client-side refresh response, usually in
    /// cases where a client-side framework is sending AJAX requests and
    /// will use the presence of a specific header as a signal that to
    /// issue a client-side redirect.
    pub fn with_header(mut self, name: impl Into<HeaderName>, values: impl ToHeaderValues) -> Self {
        self.headers
            .push((name.into(), values.to_header_values().unwrap().collect()));
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
