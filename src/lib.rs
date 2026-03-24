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
 */

use worker::{Context, Cors, Date, Env, Method, Request, Response, Result, RouteContext, Router, event};
use serde::{Deserialize, Serialize};

mod auth;
mod evaluation;
mod hibp;

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

#[derive(Serialize, Deserialize, Debug)]
pub struct DemoMetadata {
    pub usage: u64,
    pub reset_at: u64
}

#[derive(Deserialize, Debug)]
pub struct SetHardLimitRequest {
    pub hard_limit: Option<u64>,
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
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
        .run(req, env)
        .await
}

async fn handle_evaluate(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Validate API Key
    let api_key = extract_api_key(&req)?;
    let kv = ctx.kv("API_KEYS")?;
    auth::validate(&api_key, &kv).await?;    

    let body: EvaluationRequest = match req.json().await {
        Ok(data) => data,
        Err(_) => return Response::error("Invalid JSON Body", 400),
    };

    if body.password.trim().is_empty() {
        return Response::error("Password cannot be empty", 400);
    }

    let mut result = evaluation::evaluate(&body.password);
    
    // Skips HIBP if ?hibp=false
    let skip_hibp = req.url()?
        .query_pairs()
        .any(|(key, value)| key == "hibp" && value == "false");

    if !skip_hibp {
        let breach = hibp::check_breach(&body.password).await?;
        result.breached = Some(breach.breached);
        result.breach_count = Some(breach.breach_count);
    }

    auth::increment_usage(&api_key, &kv).await?;

    Response::from_json(&result)
}

async fn handle_register(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: RegisterRequest = match req.json().await {
        Ok(data) => data,
        Err(_) => return Response::error("Invalid JSON Body", 400),
    };

    let kv = ctx.kv("API_KEYS")?;
    let (api_key, regen_token) = auth::register(&body.email, &kv).await?;

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

    let kv = ctx.kv("API_KEYS")?;
    let (new_api_key, new_regen_token) = auth::regenerate(&body.email, &body.regen_token, &kv).await?;

    Response::from_json(&serde_json::json!({
        "api_key": new_api_key,
        "regen_token": new_regen_token
    }))
}

async fn handle_usage(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Validate API Key
    let api_key = extract_api_key(&req)?;

    let kv = ctx.kv("API_KEYS")?;
    let metadata = auth::authenticate(&api_key, &kv).await?;

    Response::from_json(&serde_json::json!({
        "tier": metadata.tier,
        "usage": metadata.usage,
        "limit": metadata.limit,
        "hard_limit": metadata.hard_limit,
        "reset_at": metadata.reset_at
    }))
}

async fn handle_demo(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Extract IP Address
    let ip = req
        .headers()
        .get("CF-Connecting-IP")?
        .ok_or(worker::Error::from("Unable to determine IP address"))?;

    let kv = ctx.kv("API_KEYS")?;
    let kv_key = format!("demo:{}", ip);
    let now = Date::now().as_millis();

    // Load or Create Metadata
    let mut metadata = match kv.get(&kv_key).json::<DemoMetadata>().await? {
        Some(data) => data,
        None => DemoMetadata { 
            usage: 0, 
            reset_at: now + 86400000 // 24 hours
        } 
    };

    // Apply Reset
    if now >= metadata.reset_at {
        metadata.usage = 0;
        metadata.reset_at = now + 86400000;
    }

    // Enforce Limit
    if metadata.usage >= 10 {
        return Response::error("Demo limit reached. Sign up for a free API key.", 429);
    }

    // Process Request
    let body: EvaluationRequest = match req.json().await {
        Ok(data) => data,
        Err(_) => return Response::error("Invalid JSON Body", 400),
    };

    if body.password.trim().is_empty() {
        return Response::error("Password cannot be empty", 400);
    }

    let mut result = evaluation::evaluate(&body.password);

    // Skips HIBP if ?hibp=false
    let skip_hibp = req.url()?
        .query_pairs()
        .any(|(key, value)| key == "hibp" && value == "false");

    if !skip_hibp {
        let breach = hibp::check_breach(&body.password).await?;
        result.breached = Some(breach.breached);
        result.breach_count = Some(breach.breach_count);
    }

    // Increment Usage + Store Metadata
    metadata.usage += 1;
    kv.put(&kv_key, serde_json::to_string(&metadata)?)?
        .execute().await?;

    Response::from_json(&result)
}

async fn handle_set_hard_limit(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Validate API Key
    let api_key = extract_api_key(&req)?;
    let kv = ctx.kv("API_KEYS")?;
    let mut data = auth::authenticate(&api_key, &kv).await?;

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

    auth::put_metadata(&api_key, &kv, &data).await?;    

    Response::from_json(&serde_json::json!({
        "hard_limit": data.hard_limit,
        "limit": data.limit,
        "tier": data.tier
    }))
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

    Ok(api_key)
}