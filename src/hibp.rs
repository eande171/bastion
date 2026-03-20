use worker::{Fetch, Headers, Request, RequestInit, Result};

use sha1::{Digest, Sha1};

pub struct BreachResult {
    pub breached: bool,
    pub breach_count: u64,
}

pub async fn check_breach(password: &str) -> Result<BreachResult> {
    // Hash Password
    let mut hasher = Sha1::new();
    hasher.update(password);

    let hash_hex = hex::encode(hasher.finalize()).to_uppercase();

    let prefix = &hash_hex[..5];
    let suffix = &hash_hex[5..];

    // Handle Request
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

    let headers = Headers::new();
    headers.set("Add-Padding", "true")?; 

    let mut init = RequestInit::new();
    init.with_method(worker::Method::Get);
    init.with_headers(headers);

    let request = Request::new_with_init(&url, &init)?;

    let mut response = Fetch::Request(request).send().await?;

    let body = response.text().await?;

    // Parse Lines
    for line in body.lines() {
        if let Some((line_suffix, count)) = line.split_once(":") {
            if line_suffix == suffix {
                return Ok(BreachResult { 
                    breached: true, 
                    breach_count: count.trim().parse().unwrap_or(0)
                });
            }
        }
    }

    Ok(BreachResult {
        breached: false,
        breach_count: 0
    })
}