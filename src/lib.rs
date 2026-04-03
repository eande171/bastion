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

use worker::{Context, Cors, Env, Method, Request, Response, Result, RouteContext, Router, event};
use serde::Deserialize;
use zeroize::Zeroize;

use crate::evaluation::EvaluationResult;

mod auth;
mod durable_objects;
mod evaluation;
mod hibp;

pub use durable_objects::{KeyState, EmailIndex, DemoRateLimit};

#[derive(Deserialize, Debug)]
pub struct EvaluationRequest {
    pub password: String,
}

#[derive(Deserialize, Debug)]
pub struct RegisterRequest {
    pub email: String,
}

#[derive(Deserialize, Debug)]
pub struct RegenerateRequest {
    pub email: String,
    pub regen_token: String,
}

#[derive(Deserialize, Debug)]
pub struct SetHardLimitRequest {
    pub hard_limit: Option<u64>,
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let response = Router::new()
        .options_async("/v1/evaluate", |_, _| async move {
            Response::empty()?.with_cors(&build_cors())
        })
        .post_async("/v1/evaluate", |req, ctx| async move {
            handle_evaluate(req, ctx).await?.with_cors(&build_cors())
        })

        .options_async("/v1/demo", |_, _| async move {
            Response::empty()?.with_cors(&build_demo_cors())
        })
        .post_async("/v1/demo", |req, ctx| async move {
            handle_demo(req, ctx).await?.with_cors(&build_demo_cors())
        })

        .options_async("/v1/demo/usage", |_, _| async move {
            Response::empty()?.with_cors(&build_demo_cors())
        })
        .get_async("/v1/demo/usage", |req, ctx| async move {
            handle_demo_usage(req, ctx).await?.with_cors(&build_demo_cors())
        })

        .options_async("/v1/keys/register", |_, _| async move {
            Response::empty()?.with_cors(&build_cors())
        })
        .post_async("/v1/keys/register", |req, ctx| async move {
            handle_register(req, ctx).await?.with_cors(&build_cors())
        })

        .options_async("/v1/keys/regenerate", |_, _| async move {
            Response::empty()?.with_cors(&build_cors())
        })
        .post_async("/v1/keys/regenerate", |req, ctx| async move {
            handle_regenerate(req, ctx).await?.with_cors(&build_cors())
        })

        .options_async("/v1/keys/usage", |_, _| async move {
            Response::empty()?.with_cors(&build_cors())
        })
        .get_async("/v1/keys/usage", |req, ctx| async move {
            handle_usage(req, ctx).await?.with_cors(&build_cors())
        })

        .options_async("/v1/keys/hard-limit", |_, _| async move {
            Response::empty()?.with_cors(&build_cors())
        })
        .patch_async("/v1/keys/hard-limit", |req, ctx| async move {
            handle_set_hard_limit(req, ctx).await?.with_cors(&build_cors())
        })

        .options_async("/v1/health", |_, _| async move {
            Response::empty()?.with_cors(&build_cors())
        })
        .get_async("/v1/health", |_, _| async move {
            Response::ok("ok")?.with_cors(&build_cors())
        }) 
        .run(req, env)
        .await?;


    let headers = response.headers().clone();
    
    headers.set("Cache-Control", "no-store, no-cache, must-revalidate")?;
    headers.set("Pragma", "no-cache")?;
    headers.set("Expires", "0")?;
    headers.set("X-Content-Type-Options", "nosniff")?;

    Ok(response.with_headers(headers))
}

async fn handle_evaluate(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Determine Origin
    let proxy_secret = ctx.env.secret("RAPIDAPI_PROXY_SECRET")?.to_string();
    let incoming_secret = req.headers().get("X-RapidAPI-Proxy-Secret")?;

    let is_rapidapi = matches!(incoming_secret, Some(secret) if secret == proxy_secret);

    if !is_rapidapi {
        // Validate API Key
        let api_key = extract_api_key(&req)?;
        auth::process_request(&api_key, &ctx.env).await?;
    }

    let mut body: EvaluationRequest = match req.json().await {
        Ok(data) => data,
        Err(_) => return Response::error("Invalid JSON Body", 400),
    };

    let skip_hibp = req.url()?
        .query_pairs()
        .any(|(key, value)| key == "hibp" && value == "false");

    let result = match run_password_audit(&body.password, skip_hibp).await {
        Ok(res) => res,
        Err(e) => return Response::error(e.to_string(), 400),
    };
    body.password.zeroize(); // Clear Password from Memory

    Response::from_json(&result)
}

async fn handle_register(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: RegisterRequest = match req.json().await {
        Ok(data) => data,
        Err(_) => return Response::error("Invalid JSON Body", 400),
    };

    let (api_key, regen_token) = auth::register(&body.email, &ctx.env).await?;

    Response::from_json(&serde_json::json!({
        "api_key": api_key,
        "regen_token": regen_token
    }))
}

async fn handle_regenerate(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: RegenerateRequest = match req.json().await {
        Ok(data) => data,
        Err(_) => return Response::error("Invalid JSON Body", 400),
    };

    let (new_api_key, new_regen_token) = auth::regenerate(&body.email, &body.regen_token, &ctx.env).await?;

    Response::from_json(&serde_json::json!({
        "api_key": new_api_key,
        "regen_token": new_regen_token
    }))
}

async fn handle_usage(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Validate API Key
    let api_key = extract_api_key(&req)?;

    let Ok(metadata) = auth::authenticate(&api_key, &ctx.env).await else {
        return Response::error("Invalid API Key", 401);
    };

    Response::from_json(&serde_json::json!({
        "tier": metadata.tier,
        "usage": metadata.usage,
        "limit": metadata.limit,
        "hard_limit": metadata.hard_limit,
        "reset_at": metadata.reset_at
    }))
}

async fn handle_demo(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let ip = req
        .headers()
        .get("CF-Connecting-IP")?
        .ok_or(worker::Error::from("Unable to determine IP address"))?;

    let demo_data = auth::check_demo(&ip, &ctx.env).await?;
    if demo_data.usage >= 10 {
        return Response::error("Demo limit reached. Sign up for a free API key.", 429);
    }

    let mut body: EvaluationRequest = match req.json().await {
        Ok(data) => data,
        Err(_) => return Response::error("Invalid JSON Body", 400),
    };

    let skip_hibp = req.url()?
        .query_pairs()
        .any(|(key, value)| key == "hibp" && value == "false");

    let result = run_password_audit(&body.password, skip_hibp).await?;
    body.password.zeroize(); // Clear Password from Memory

    auth::increment_demo(&ip, &ctx.env).await?;

    Response::from_json(&result)
}

async fn handle_demo_usage(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let ip = req
        .headers()
        .get("CF-Connecting-IP")?
        .ok_or(worker::Error::from("Unable to determine IP address"))?;

    let metadata = auth::check_demo(&ip, &ctx.env).await?;

    Response::from_json(&serde_json::json!({
        "usage": metadata.usage
    }))
}

async fn handle_set_hard_limit(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Validate API Key
    let api_key = extract_api_key(&req)?;
    let Ok(mut data) = auth::authenticate(&api_key, &ctx.env).await else {
        return Response::error("Invalid API Key", 401);
    };

    let body: SetHardLimitRequest = match req.json().await {
        Ok(data) => data,
        Err(_) => return Response::error("Invalid JSON Body", 400),
    };

    if let Some(limit) = body.hard_limit {
        if limit < data.limit {
            return Response::error("Hard limit cannot be less than current tier limit", 400);
        }
        data.hard_limit = Some(limit);
    }
    else {
        data.hard_limit = None;
    }

    auth::put_metadata(&api_key, &ctx.env, &data).await?;    

    Response::from_json(&serde_json::json!({
        "hard_limit": data.hard_limit,
        "limit": data.limit,
        "tier": data.tier
    }))
}

async fn run_password_audit(password: &str, skip_hibp: bool) -> Result<EvaluationResult> {
    if password.len() > 128 {
        return Err(worker::Error::from("Password cannot exceed 128 characters"));
    }

    if password.trim().is_empty() {
        return Err(worker::Error::from("Password cannot be empty"));
    }

    let mut result = evaluation::evaluate(password);

    if !skip_hibp {
        if let Ok(breach) = hibp::check_breach(password).await {
            result.breached = Some(breach.breached);
            result.breach_count = Some(breach.breach_count);
        }
        else {
            result.breached = None;
            result.breach_count = Some(0);
        }
    }

    Ok(result)
}

fn build_cors() -> Cors {
    Cors::new()
        .with_origins(["*"])
        .with_methods([Method::Options, Method::Post, Method::Get, Method::Patch])
        .with_allowed_headers(["Content-Type", "Authorization"])
}

fn build_demo_cors() -> Cors {
    Cors::new()
        .with_origins(["https://eande171.github.io"])
        .with_methods([Method::Options, Method::Post])
        .with_allowed_headers(["Content-Type"])
}

fn extract_api_key(req: &Request) -> Result<String> {
    let api_key = req.headers().get("Authorization")?
        .ok_or(worker::Error::from("Missing Authorization Header"))?
        .strip_prefix("Bearer ")
        .ok_or(worker::Error::from("Invalid Authorization Header"))?
        .to_string();

    if !api_key.starts_with("bsn_live_") {
        return Err(worker::Error::from("Invalid API Key Format"));
    }

    Ok(api_key)
}