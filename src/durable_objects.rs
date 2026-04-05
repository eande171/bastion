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

use std::time::Duration;

use crate::{auth::{DemoMetadata, EmailPut, KeyMetadata, Tier, next_reset_timestamp}, error::{AppError, BastionError}};
use worker::{DurableObject, Env, Request, Response, Result, State, durable_object, wasm_bindgen};

// KeyState
#[durable_object(fetch)]
pub struct KeyState {
    state: State,
    _env: Env,
}

impl DurableObject for KeyState {
    fn new(state: State, env: Env) -> Self {
        Self { state, _env: env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        match req.path().as_str() {
            "/get" => self.handle_get().await
                .or_else(|e| e.into_response()),
            "/put" => self.handle_put(req).await,
            "/authenticate" => self.handle_authenticate().await
                .or_else(|e| e.into_response()),
            "/process" => self.handle_process().await
                .or_else(|e| e.into_response()),
            "/delete" => self.handle_delete().await,
            _ => Response::error("Not Found", 404),
        }
    }
}

impl KeyState {
    // Helper Functions
    async fn load(&self) -> Result<KeyMetadata, AppError> {
        self.state
            .storage()
            .get::<KeyMetadata>("metadata")
            .await?
            .ok_or(AppError::Bastion(BastionError::ApiKeyNotFound))
    }

    async fn save(&self, data: &KeyMetadata) -> Result<()> {
        self.state
            .storage()
            .put("metadata", data)
            .await
    }

    // Fetch Handlers
    async fn handle_get(&self) -> Result<Response, AppError> {
        let data = self.load().await?;
        Ok(Response::from_json(&data)?)
    }

    async fn handle_put(&self, mut req: Request) -> Result<Response> {
        let new_data: KeyMetadata = req.json().await?;
        self.save(&new_data).await?;
        Response::ok("Metadata Updated")
    }

    async fn handle_authenticate(&self) -> Result<Response, AppError> {
        let Ok(mut data) = self.load().await else {
            return Err(AppError::Bastion(BastionError::ApiKeyNotFound));
        };

        if worker::Date::now().as_millis() >= data.reset_at {
            data.usage = 0;
            data.reset_at = next_reset_timestamp(&data.tier);
            self.save(&data).await?;
        }

        Ok(Response::from_json(&data)?)
    }

    async fn handle_process(&self) -> Result<Response, AppError> {
        let Ok(mut data) = self.load().await else {
            return Err(AppError::Bastion(BastionError::ApiKeyNotFound));
        };
    
        if worker::Date::now().as_millis() >= data.reset_at {
            data.usage = 0;
            data.reset_at = next_reset_timestamp(&data.tier);
        }

        if let Some(hard_limit) = data.hard_limit 
            && data.usage >= hard_limit {
            return Err(AppError::Bastion(BastionError::HardLimitExceeded));
        }

        match data.tier {
            Tier::Free => {
                if data.usage >= data.limit {
                    return Err(AppError::Bastion(BastionError::RateLimitExceeded));
                }
            }
            Tier::Starter | Tier::Pro => {
                // Handle Overage Logic Here
                // todo!()
                return Err(AppError::Bastion(BastionError::PaidTierNotImplemented));
            }
        }
    
        data.usage += 1;
        self.save(&data).await?;
    
        Ok(Response::from_json(&data)?)
    }

    async fn handle_delete(&self) -> Result<Response> {
        self.state.storage().delete("metadata").await?;
        Response::ok("API Key Deleted")
    }
}

// EmailIndex
#[durable_object(fetch)]
pub struct EmailIndex{
    state: State,
    _env: Env,
}

impl DurableObject for EmailIndex {
    fn new(state: State, env: Env) -> Self {
        Self { state, _env: env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let body = req.text().await?;
        
        match req.path().as_str() {
            // POST /get | email_hash -> api_hash
            "/get" => {
                match self.state.storage().get::<String>(&body).await? {
                    Some(api_hash) => Response::ok(api_hash),
                    None => Response::error("Email Not Found", 404),
                }
            }

            // POST /put | { email_hash, api_hash }
            "/put" => {
                let Ok(ep) = serde_json::from_str::<EmailPut>(&body) else {
                    return Response::error("Invalid Request Body", 400);
                };

                self.state.storage().put(&ep.email_hash, &ep.api_hash).await?;
                Response::ok("Email Indexed")
            }

            // POST /delete | email_hash
            "/delete" => {
                self.state.storage().delete(&body).await?;
                Response::ok("Email Deleted")
            },
            _ => Response::error("Not Found", 404),
        }
    }
}

// DemoRateLimit
#[durable_object]
pub struct DemoRateLimit {
    state: State,
    _env: Env,
}

impl DurableObject for DemoRateLimit {
    fn new(state: State, env: Env) -> Self {
        Self { state, _env: env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let ip_hash = req.text().await?;

        if self.state.storage().get_alarm().await?.is_none() {
            self.state.storage().set_alarm(Duration::from_hours(24)).await?;
        }

        match req.path().as_str() {
            // POST /check | ip_hash -> DemoMetadata
            "/check" => {
                Response::from_json(&match self.state.storage().get::<DemoMetadata>(&ip_hash).await? {
                    Some(data) => data,
                    None => DemoMetadata {
                        usage: 0,
                    }
                })
            }

            // POST /increment | ip_hash
            "/increment" => {
                let mut data = match self.state.storage().get::<DemoMetadata>(&ip_hash).await? {
                    Some(data) => data,
                    None => DemoMetadata {
                        usage: 0,
                    }
                };
                
                data.usage += 1;
                self.state.storage().put(&ip_hash, &data).await?;

                Response::ok("Usage Incremented")
            }

            _ => Response::error("Not Found", 404),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        // Delete All Keys On Alarm (Every 24 Hours)
        self.state.storage().delete_all().await?;

        self.state.storage().set_alarm(Duration::from_hours(24)).await?;
        
        Response::ok("Demo Rate Limits Reset")
    }
}