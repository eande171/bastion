use worker::{Context, Cors, Env, Method, Request, Response, Result, RouteContext, Router, event};

mod auth;
mod evaluation;
mod hibp;
mod models;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .options_async("/v1/evaluate", |_, _| async move {
            Response::empty()?.with_cors(&build_cors())
        })
        .post_async("/v1/evaluate", |req, ctx| async move {
            handle_evaluate(req, ctx).await?.with_cors(&build_cors())
        })
        .post_async("/v1/keys/register", |req, ctx| async move {
            handle_register(req, ctx).await?.with_cors(&build_cors())
        })
        .post_async("/v1/keys/regenerate", |req, ctx| async move {
            handle_regenerate(req, ctx).await?.with_cors(&build_cors())
        })
        .get_async("/v1/keys/usage", |req, ctx| async move {
            handle_usage(req, ctx).await?.with_cors(&build_cors())
        })
        .run(req, env)
        .await
}

async fn handle_evaluate(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Validate API Key
    let api_key = extract_api_key(&req)?;
    let kv = ctx.kv("API_KEYS")?;
    auth::validate(&api_key, &kv).await?;    

    let body: models::EvaluationRequest = match req.json().await {
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
    let body: models::RegisterRequest = match req.json().await {
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
    let body: models::RegenerateRequest = match req.json().await {
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
    let metadata = auth::validate(&api_key, &kv).await
        .map_err(|e| worker::Error::from(e.to_string()))?;

    Response::from_json(&serde_json::json!({
        "tier": metadata.tier,
        "usage": metadata.usage,
        "limit": metadata.limit,
        "hard_limit": metadata.hard_limit,
        "reset_at": metadata.reset_at
    }))
}

fn build_cors() -> Cors {
    Cors::new()
        .with_origins(["*"])
        .with_methods([Method::Options, Method::Post])
        .with_allowed_headers(["Content-Type", "Authorization"])
}

fn extract_api_key(req: &Request) -> Result<String> {
    let api_key = req.headers().get("Authorization")?
        .ok_or(worker::Error::from("Missing Authorization Header"))?
        .strip_prefix("Bearer ")
        .ok_or(worker::Error::from("Invalid Authorization Header"))?
        .to_string();

    Ok(api_key)
}