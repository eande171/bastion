use serde::{Deserialize, Serialize};
use serde_json;
use web_sys::{self, Crypto};
use worker::{KvStore, Result, ok::Ok};

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
            Tier::Pro => 100000
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

fn next_reset_timestamp(tier: &Tier) -> u64 {
    worker::Date::now().as_millis() + tier.reset_interval_ms()
}

fn get_crypto() -> Result<Crypto> {
    let global = worker::js_sys::global();
    let crypto = worker::js_sys::Reflect::get(&global, &"crypto".into())
        .map_err(|_| worker::Error::from("Failed to get crypto"))?;
    
    Ok(crypto.into())
}

fn generate_token(prefix: &str) -> Result<String> {
    let crypto = get_crypto()?;
    
    let uuid1 = crypto.random_uuid();
    let uuid2 = crypto.random_uuid();

    let token = format!("{}{}", uuid1.replace("-", ""), uuid2.replace("-", ""));

    Ok(format!("{}_{}", prefix, token))
}

pub async fn register(email: &str, kv: &KvStore) -> Result<(String, String)> {
    // Check Email
    if !email.contains('@') || !email.contains('.') {
        return Err(worker::Error::from("Invalid Email"))
    }

    if kv.get(&format!("email:{}", email)).text().await?.is_some() {
        return Err(worker::Error::from("Email Already Exists"))
    }

    // Ensure No Duplicate Keys
    let api_key = loop {
        let candidate = generate_token("bsn_live")?;
        let existing = kv.get(&format!("key:{}", candidate)).text().await?;

        if existing.is_none() {
            break candidate
        }
    };

    let regen_token = generate_token("bsn_regen")?;

    // Build + Store Data
    let metadata = KeyMetadata::new(email.to_string(), regen_token.clone());
    kv.put(&format!("key:{}", api_key), serde_json::to_string(&metadata)?)?
        .execute().await?;

    // Store Email + Key
    kv.put(&format!("email:{}", email), &api_key)?
        .execute().await?;

    // Return Key
    Ok((api_key, regen_token))
}