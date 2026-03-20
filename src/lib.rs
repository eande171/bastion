use worker::{Context, Cors, Env, Method, Request, Response, Result, RouteContext, Router, event};

mod models;
mod evaluation;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .options_async("/v1/evaluate", |_, _| async move {
            Response::empty()?.with_cors(&build_cors())
        })
        .post_async("/v1/evaluate", |req, ctx| async move {
            handle_evaluate(req, ctx).await?.with_cors(&build_cors())
        })
        .run(req, env)
        .await
}

async fn handle_evaluate(mut req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    let body: models::EvaluationRequest = match req.json().await {
        Ok(data) => data,
        Err(_) => return Response::error("Invalid JSON Body", 400),
    };

    if body.password.trim().is_empty() {
        return Response::error("Password cannot be empty", 400);
    }

    let result = evaluation::evaluate(&body.password);

    Response::from_json(&result)
}

fn build_cors() -> Cors {
    Cors::new()
        .with_origins(["*"])
        .with_methods([Method::Options, Method::Post])
        .with_allowed_headers(["Content-Type", "Authorization"])
}