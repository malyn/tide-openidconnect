use std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub struct ParsedAuthorizeUrl {
    pub host: String,
    pub path: String,
    pub response_type: String,
    pub client_id: String,
    pub scopes: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub redirect_uri: String,
}

impl ParsedAuthorizeUrl {
    pub fn default() -> Self {
        Self {
            host: "localhost".to_owned(),
            path: "/authorization".to_owned(),
            response_type: "code".to_owned(),
            client_id: "CLIENT-ID".to_string(),
            scopes: "openid".to_owned(),
            state: None,
            nonce: None,
            redirect_uri: "http://localhost/callback".to_string(),
        }
    }

    pub fn from_url(s: impl AsRef<str>) -> Self {
        let url = openidconnect::url::Url::parse(s.as_ref()).unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();

        Self {
            host: url.host_str().unwrap().to_owned(),
            path: url.path().to_owned(),
            response_type: query.get("response_type").unwrap().to_owned(),
            client_id: query.get("client_id").unwrap().to_owned(),
            scopes: query.get("scope").unwrap().to_owned(),
            state: Some(query.get("state").unwrap().to_owned()),
            nonce: Some(query.get("nonce").unwrap().to_owned()),
            redirect_uri: query.get("redirect_uri").unwrap().to_owned(),
        }
    }

    pub fn with_nonce(self, nonce: Option<String>) -> Self {
        Self { nonce, ..self }
    }

    pub fn with_scopes(self, scopes: impl AsRef<str>) -> Self {
        Self {
            scopes: scopes.as_ref().to_owned(),
            ..self
        }
    }

    pub fn with_state(self, state: Option<String>) -> Self {
        Self { state, ..self }
    }
}
