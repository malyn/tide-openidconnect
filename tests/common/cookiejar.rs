use std::sync::Arc;

use async_lock::Mutex;
use tide::http::headers::{COOKIE, SET_COOKIE};

pub struct SessionCookieJarMiddleware {
    session_cookie: Arc<Mutex<Option<tide::http::Cookie<'static>>>>,
}

impl Default for SessionCookieJarMiddleware {
    fn default() -> Self {
        Self {
            session_cookie: Arc::new(Mutex::new(None)),
        }
    }
}

#[surf::utils::async_trait]
impl surf::middleware::Middleware for SessionCookieJarMiddleware {
    async fn handle(
        &self,
        mut req: surf::Request,
        client: surf::Client,
        next: surf::middleware::Next<'_>,
    ) -> surf::Result<surf::Response> {
        // Add the session cookie, if we have one, to the request.
        if let Some(cookie) = &*self.session_cookie.lock().await {
            tide::log::trace!("Adding session cookie to request.");
            req.set_header(COOKIE, cookie.to_string());
        }

        // Continue the request and collect the response.
        let res = next.run(req, client).await?;

        // Did we get a session cookie back? If so, either replace our
        // current session cookie, or clear the existing session cookie
        // if the new one has already expired (which is how servers
        // ask the browser to delete a cookie).
        if let Some(values) = res.header(SET_COOKIE) {
            if let Some(value) = values.get(0) {
                let mut session_cookie_guard = self.session_cookie.lock().await;

                let cookie = tide::http::Cookie::parse(value.to_string()).unwrap();
                if cookie
                    .expires()
                    .unwrap()
                    .ge(&time::OffsetDateTime::now_utc())
                {
                    tide::log::trace!("Received new/updated session cookie from server.");
                    *session_cookie_guard = Some(cookie);
                } else {
                    tide::log::trace!("Server removed session cookie.");
                    *session_cookie_guard = None;
                }
            }
        }

        // Pass the response back up the middleware chain.
        Ok(res)
    }
}
