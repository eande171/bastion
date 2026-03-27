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
use serde_json;
use sha2::{Digest, Sha256};
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

fn hash_credential(credential: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(credential);
    hex::encode(hasher.finalize())
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

async fn get_metadata(api_hash: &str, kv: &KvStore) -> Result<KeyMetadata> {
    let data = kv.get(&format!("key:{}", api_hash)).json::<KeyMetadata>().await?;

    match data {
        Some(data) => Ok(data),
        None => return Err(worker::Error::from("API Key Does Not Exist"))
    }
}

pub async fn put_metadata(api_hash: &str, kv: &KvStore, data: &KeyMetadata) -> Result<()> {
    kv.put(&format!("key:{}", api_hash), serde_json::to_string(&data)?)?
        .execute().await?;

    Ok(())
}

pub async fn register(email: &str, kv: &KvStore) -> Result<(String, String)> {
    let email = email.trim().to_lowercase();
    let email_hash = hash_credential(&email);

    // Check Email
    if !email.contains('@') || !email.contains('.') {
        return Err(worker::Error::from("Invalid Email"))
    }

    if kv.get(&format!("email:{}", email_hash)).text().await?.is_some() {
        return Err(worker::Error::from("Email Already Exists"))
    }
    
    let api_key = generate_token("bsn_live")?;
    let regen_token = generate_token("bsn_regen")?;

    // Hash Credentials
    let api_hash = hash_credential(&api_key);
    let regen_hash = hash_credential(&regen_token);

    // Build + Store Data
    let metadata = KeyMetadata::new(email_hash.clone(), regen_hash);
    kv.put(&format!("key:{}", api_hash), serde_json::to_string(&metadata)?)?
        .execute().await?;

    // Store Email + Key
    kv.put(&format!("email:{}", email_hash), &api_hash)?
        .execute().await?;

    // Return Key
    Ok((api_key, regen_token))
}

pub async fn authenticate(api_key: &str, kv: &KvStore) -> Result<KeyMetadata> {
    let mut data = get_metadata(&hash_credential(api_key), kv).await?;

    // Update Reset Window
    if worker::Date::now().as_millis() >= data.reset_at {
        data.usage = 0;
        data.reset_at = next_reset_timestamp(&data.tier);

        put_metadata(&hash_credential(api_key), kv, &data).await?;
    }

    Ok(data)
}

pub async fn process_request(api_key: &str, kv: &KvStore) -> Result<KeyMetadata> {
    let mut data = get_metadata(&hash_credential(api_key), kv).await?;

    // Update Reset Window
    if worker::Date::now().as_millis() >= data.reset_at {
        data.usage = 0;
        data.reset_at = next_reset_timestamp(&data.tier);
    }

    // Enforce Hard Limit
    if let Some(hard_limit) = data.hard_limit {
        if data.usage >= hard_limit {
            return Err(worker::Error::from("Hard Limit Reached"))
        }
    }

    // Handle Tier Limits
    match data.tier {
        Tier::Free => {
            if data.usage >= data.limit {
                return Err(worker::Error::from("Rate Limit Exceeded"))
            }
        }
        Tier::Starter | Tier::Pro => {
            // Handle Overage
            todo!()
        }
    }

    // Increment Usage
    data.usage += 1;
    put_metadata(&hash_credential(api_key), kv, &data).await?;

    Ok(data)
}

pub async fn regenerate(email: &str, regen_token: &str, kv: &KvStore) -> Result<(String, String)> {
    // Validate Email
    let email = email.trim().to_lowercase();
    let email_hash = hash_credential(&email);

    let api_hash = kv.get(&format!("email:{}", email_hash)).text().await?
        .ok_or(worker::Error::from("Email Not Found"))?;

    let mut data = get_metadata(&api_hash, kv).await?;

    // Validate Regen Token
    if data.regen_token != hash_credential(regen_token) {
        return Err(worker::Error::from("Invalid Regeneration Token"))
    }

    // Invalidate Old Key
    kv.delete(&format!("key:{}", api_hash)).await?;
    kv.delete(&format!("email:{}", email_hash)).await?;

    // Generate New Key
    let new_api_key = generate_token("bsn_live")?;
    let new_regen_token = generate_token("bsn_regen")?;

    // Hash Credentials
    let new_api_hash = hash_credential(&new_api_key);
    let new_regen_hash = hash_credential(&new_regen_token);

    // Update + Store Data
    data.regen_token = new_regen_hash.clone();
    put_metadata(&new_api_hash, kv, &data).await?;

    // Store Email + Key
    kv.put(&format!("email:{}", email_hash), &new_api_hash)?
        .execute().await?;

    Ok((new_api_key, new_regen_token))
}