/* 
 * Bastion Password Audit API
 * Copyright (C) 2026 Eden Anderson
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 * 
 */

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

    let mut response = match Fetch::Request(request).send().await {
        Ok(res) => res,
        Err(_) => return Err(worker::Error::from("HIBP API Request Failed")),
    };

    if response.status_code() != 200 {
        return Err(worker::Error::from(format!("HIBP API Error: {}", response.status_code())));
    }

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