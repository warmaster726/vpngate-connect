use futures::future::{select, Either};
use gloo_timers::future::TimeoutFuture;
use std::pin::pin;
use wasm_bindgen::JsValue;
use worker::{Fetch, Headers, Method, Request, RequestInit};

use crate::model::USER_AGENT;

pub struct FetchText {
    pub text: String,
    pub cookie: String,
    pub url: String,
}

fn cookie_from(headers: &Headers) -> String {
    headers
        .get("set-cookie")
        .ok()
        .flatten()
        .map(|c| c.split(';').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_default()
}

pub async fn fetch_text_timeout(
    url: &str,
    timeout_ms: u32,
    method: Method,
    body: Option<String>,
    extra: &[(&str, &str)],
) -> Option<FetchText> {
    let url_owned = url.to_string();
    let extra_owned: Vec<(String, String)> = extra
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    let fetch_fut = async move {
        let mut headers = Headers::new();
        let _ = headers.set("User-Agent", USER_AGENT);
        for (k, v) in &extra_owned {
            let _ = headers.set(k, v);
        }
        let mut init = RequestInit::new();
        init.method = method;
        init.headers = headers;
        if let Some(b) = body {
            init.body = Some(JsValue::from_str(&b));
        }
        let req = Request::new_with_init(&url_owned, &init).ok()?;
        let mut resp = Fetch::Request(req).send().await.ok()?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return None;
        }
        let cookie = cookie_from(resp.headers());
        let text = resp.text().await.ok()?;
        if text.len() < 32 {
            return None;
        }
        Some(FetchText {
            text,
            cookie,
            url: url_owned,
        })
    };
    let mut fetch_f = pin!(fetch_fut);
    let mut to = pin!(TimeoutFuture::new(timeout_ms));
    match select(fetch_f, to).await {
        Either::Left((v, _)) => v,
        Either::Right(_) => None,
    }
}

pub async fn fetch_get(url: &str, timeout_ms: u32) -> Option<FetchText> {
    fetch_text_timeout(url, timeout_ms, Method::Get, None, &[]).await
}
