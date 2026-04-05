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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use web_sys::{self, Crypto};
use worker::{Env, Response, Stub};

use crate::error::{AppError, BastionError};

#[derive(Serialize, Deserialize)]
pub enum Tier {
    Free,
    Starter,
    Pro
}

impl Tier {
    pub fn limit(&self) -> u64 {
        match self {
            Tier::Free => 100,
            Tier::Starter => 10000,
            Tier::Pro => 100_000
        }
    }

    pub fn default_hard_limit(&self) -> Option<u64> {
        match self {
            Tier::Free => Some(100),
            Tier::Starter | Tier::Pro => None
        }
    }

    pub fn reset_interval_ms(&self) -> u64 {
        match self {
            Tier::Free => 24 * 3600 * 1000,                        // 24 hours
            Tier::Starter | Tier::Pro => 30 * 24 * 3600 * 1000     // 30 days
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct KeyMetadata {
    pub email:              String,
    pub tier:               Tier,
    pub usage:              u64,
    pub limit:              u64,            // Base Tier Limit
    pub hard_limit:         Option<u64>,    // User Defined Ceiling; None = No Cap
    pub reset_at:           u64,
    pub regen_token:        String,
    pub subscription_id:    Option<String>  // None for Free Tier
}

impl KeyMetadata {
    pub fn new(email: String, regen_token: String) -> Self {
        KeyMetadata {
            email,
            tier: Tier::Free,
            usage: 0,
            limit: Tier::Free.limit(),
            hard_limit: Tier::Free.default_hard_limit(),
            reset_at: next_reset_timestamp(&Tier::Free),
            regen_token,
            subscription_id: None
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EmailPut {
    pub email_hash: String,
    pub api_hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DemoMetadata {
    pub usage: u64
}

// Helper Functions
fn hash_credential(credential: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(credential);
    hex::encode(hasher.finalize())
}

pub fn next_reset_timestamp(tier: &Tier) -> u64 {
    worker::Date::now().as_millis() + tier.reset_interval_ms()
}

fn get_crypto() -> Result<Crypto, AppError> {
    let global = worker::js_sys::global();
    let crypto = worker::js_sys::Reflect::get(&global, &"crypto".into())
        .map_err(|_| worker::Error::from("Failed to get crypto"))?;
    
    Ok(crypto.into())
}

fn generate_token(prefix: &str) -> Result<String, AppError> {
    let crypto = get_crypto()?;
    
    let uuid1 = crypto.random_uuid();
    let uuid2 = crypto.random_uuid();

    let token = format!("{}{}", uuid1.replace('-', ""), uuid2.replace('-', ""));

    Ok(format!("{prefix}_{token}"))
}

fn require_ok(response: Response) -> Result<Response, AppError> {
    if response.status_code() == 200 {
        Ok(response)
    } else {
        Err(AppError::Response(response))
    }
}

// Stub Helpers
fn get_key_stub(env: &Env, api_hash: &str) -> Result<Stub, AppError> {
    Ok(env.durable_object("KEY_STATE")?.id_from_name(api_hash)?.get_stub()?)
}

fn get_email_stub(env: &Env) -> Result<Stub, AppError> {
    Ok(env.durable_object("EMAIL_INDEX")?.id_from_name("global")?.get_stub()?)
}

fn get_demo_stub(env: &Env) -> Result<Stub, AppError> {
    Ok(env.durable_object("DEMO_RATE_LIMIT")?.id_from_name("global")?.get_stub()?)
}

// Stub Interactions
async fn stub_get(stub: Stub, path: &str) -> Result<Response, AppError> {
    let response = stub
        .fetch_with_str(&format!("http://do{path}"))
        .await?;

    Ok(response)
}

async fn stub_post(stub: Stub, path: &str, body: String) -> Result<Response, AppError> {
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post).with_body(Some(body.into()));

    let request = worker::Request::new_with_init(&format!("http://do{path}"), &init)?;

    let response = stub.fetch_with_request(request).await?;

    Ok(response)
}

async fn stub_delete(stub: Stub, path: &str) -> Result<Response, AppError> {
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Delete);

    let request = worker::Request::new_with_init(&format!("http://do{path}"), &init)?;

    let response = stub.fetch_with_request(request).await?;

    Ok(response)
}

// API Functions
pub async fn put_metadata(api_hash: &str, env: &Env, data: &KeyMetadata) -> Result<(), AppError> {
    let key_stub = get_key_stub(env, api_hash)?;
    require_ok(stub_post(key_stub, "/put", serde_json::to_string(&data)?).await?)?;
    Ok(())
}

pub async fn register(email: &str, env: &Env) -> Result<(String, String), AppError> {
    let email = email.trim().to_lowercase();

    // Validate Email
    if !email.contains('@') || !email.contains('.') {
        return Err(BastionError::InvalidEmail.into())
    }

    let email_hash = hash_credential(&email);

    // Check if Email Already Exists
    let email_check = stub_post(get_email_stub(env)?, "/get", email_hash.clone()).await?;
    if email_check.status_code() == 200 {
        return Err(BastionError::EmailAlreadyExists.into())
    }

    // Generate Tokens
    let api_key = generate_token("bsn_live")?;
    let regen_token = generate_token("bsn_regen")?;
    let api_hash = hash_credential(&api_key);
    let regen_hash = hash_credential(&regen_token);

    let metadata = KeyMetadata::new(email_hash.clone(), regen_hash);

    // Store Metadata
    let key_stub = get_key_stub(env, &api_hash)?;
    require_ok(stub_post(key_stub, "/put", serde_json::to_string(&metadata)?).await?)?;

    // Store Email
    require_ok(stub_post(get_email_stub(env)?, "/put", serde_json::to_string(&EmailPut { email_hash, api_hash })? ).await?)?;

    Ok((api_key, regen_token))
}

pub async fn authenticate(api_key: &str, env: &Env) -> Result<KeyMetadata, AppError> {
    let api_hash = hash_credential(api_key);
    let key_stub = get_key_stub(env, &api_hash)?;

    let mut response = require_ok(stub_get(key_stub, "/authenticate").await?)?;

    Ok(response.json::<KeyMetadata>().await?)
}

pub async fn process_request(api_key: &str, env: &Env) -> Result<KeyMetadata, AppError> {
    let api_hash = hash_credential(api_key);
    let key_stub = get_key_stub(env, &api_hash)?;

    let mut response = require_ok(stub_get(key_stub, "/process").await?)?;

    Ok(response.json::<KeyMetadata>().await?)
}

pub async fn regenerate(email: &str, regen_token: &str, env: &Env) -> Result<(String, String), AppError> {
    let email = email.trim().to_lowercase();
    let email_hash = hash_credential(&email);

    // Validate Email
    let mut email_response = require_ok(stub_post(get_email_stub(env)?, "/get", email_hash.clone()).await?)?;
    let api_hash = email_response.text().await?;

    // Get Metadata
    let key_stub = get_key_stub(env, &api_hash)?;
    let mut response = require_ok(stub_get(key_stub, "/get").await?)?;

    let mut data = response.json::<KeyMetadata>().await?;

    // Validate Regen Token
    if data.regen_token != hash_credential(regen_token) {
        return Err(BastionError::InvalidRegenToken.into());
    }

    // Invalidate Old Key
    require_ok(stub_delete(get_key_stub(env, &api_hash)?, "/delete").await?)?;
    require_ok(stub_post(get_email_stub(env)?, "/delete", email_hash.clone()).await?)?;

    // Generate New Key
    let new_api_key = generate_token("bsn_live")?;
    let new_regen_token = generate_token("bsn_regen")?;
    let new_api_hash = hash_credential(&new_api_key);
    let new_regen_hash = hash_credential(&new_regen_token);

    // Update + Store Data
    data.regen_token = new_regen_hash.clone();

    let key_stub = get_key_stub(env, &new_api_hash)?;
    require_ok(stub_post(key_stub, "/put", serde_json::to_string(&data)?).await?)?;

    // Store Email + Key
    require_ok(stub_post(get_email_stub(env)?, "/put", serde_json::to_string(&EmailPut { email_hash, api_hash: new_api_hash })? ).await?)?;

    Ok((new_api_key, new_regen_token))
}

// Demo Functions
pub async fn check_demo(ip: &str, env: &Env) -> Result<DemoMetadata, AppError> {
    let ip_hash = hash_credential(ip);
    let demo_stub = get_demo_stub(env)?;

    let mut response = require_ok(stub_post(demo_stub, "/check", ip_hash).await?)?;

    Ok(response.json::<DemoMetadata>().await?)
}

pub async fn increment_demo(ip: &str, env: &Env) -> Result<(), AppError> {
    let ip_hash = hash_credential(ip);
    let demo_stub = get_demo_stub(env)?;

    require_ok(stub_post(demo_stub, "/increment", ip_hash).await?)?;

    Ok(())
}