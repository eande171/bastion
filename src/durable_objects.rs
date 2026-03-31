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

use crate::auth::{DemoMetadata, EmailPut, KeyMetadata, Tier, next_reset_timestamp};
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
            "/get" => self.handle_get().await,
            "/put" => self.handle_put(req).await,
            "/authenticate" => self.handle_authenticate().await,
            "/process" => self.handle_process().await,
            "/delete" => self.handle_delete().await,
            _ => Response::error("Not Found", 404),
        }
    }
}

impl KeyState {
    // Helper Functions
    async fn load(&self) -> Result<KeyMetadata> {
        self.state
            .storage()
            .get::<KeyMetadata>("metadata")
            .await?
            .ok_or(worker::Error::from("API Key Does Not Exist"))
    }

    async fn save(&self, data: &KeyMetadata) -> Result<()> {
        self.state
            .storage()
            .put("metadata", data)
            .await
    }

    // Fetch Handlers
    async fn handle_get(&self) -> Result<Response> {
        let data = self.load().await?;
        Response::from_json(&data)
    }

    async fn handle_put(&self, mut req: Request) -> Result<Response> {
        let new_data: KeyMetadata = req.json().await?;
        self.save(&new_data).await?;
        Response::ok("Metadata Updated")
    }

    async fn handle_authenticate(&self) -> Result<Response> {
        let Ok(mut data) = self.load().await else {
            return Response::error("API Key Does Not Exist", 404);
        };

        if worker::Date::now().as_millis() >= data.reset_at {
            data.usage = 0;
            data.reset_at = next_reset_timestamp(&data.tier);
            self.save(&data).await?;
        }

        Response::from_json(&data)
    }

    async fn handle_process(&self) -> Result<Response> {
        let Ok(mut data) = self.load().await else {
            return Response::error("API Key Does Not Exist", 404);
        };
    
        if worker::Date::now().as_millis() >= data.reset_at {
            data.usage = 0;
            data.reset_at = next_reset_timestamp(&data.tier);
        }

        if let Some(hard_limit) = data.hard_limit 
            && data.usage >= hard_limit {
            return Response::error("API Key Usage Limit Exceeded", 429);
        }

        match data.tier {
            Tier::Free => {
                if data.usage >= data.limit {
                    return Response::error("API Key Rate Limit Exceeded", 429);
                }
            }
            Tier::Starter | Tier::Pro => {
                // Handle Overage Logic Here
                // todo!()
                return Response::error("Paid tier billing not implemented yet", 501);
            }
        }
    
        data.usage += 1;
        self.save(&data).await?;
    
        Response::from_json(&data)
    }

    async fn handle_delete(&self) -> Result<Response> {
        self.state.storage().delete("metadata").await?;
        Response::ok("API Key Deleted")
    }
}

// EmailIndex
const DEMO_RESET_INTERVAL_MS: u64 = 24 * 3600 * 1000; // 24 hours

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
#[durable_object(fetch)]
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

        match req.path().as_str() {
            // POST /check | ip_hash -> DemoMetadata
            "/check" => {
                Response::from_json(&match self.state.storage().get::<DemoMetadata>(&ip_hash).await? {
                    Some(data) => data,
                    None => DemoMetadata {
                        usage: 0,
                        reset_at: worker::Date::now().as_millis() + DEMO_RESET_INTERVAL_MS
                    }
                })
            }

            // POST /increment | ip_hash
            "/increment" => {
                let mut data = match self.state.storage().get::<DemoMetadata>(&ip_hash).await? {
                    Some(data) => data,
                    None => DemoMetadata {
                        usage: 0,
                        reset_at: worker::Date::now().as_millis() + DEMO_RESET_INTERVAL_MS
                    }
                };

                if worker::Date::now().as_millis() >= data.reset_at {
                    data.usage = 0;
                    data.reset_at = worker::Date::now().as_millis() + DEMO_RESET_INTERVAL_MS;
                }
                
                data.usage += 1;
                self.state.storage().put(&ip_hash, &data).await?;

                Response::ok("Usage Incremented")
            }

            _ => Response::error("Not Found", 404),
        }
    }
}