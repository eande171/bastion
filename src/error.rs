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

use worker::{Response, Result};

#[derive(Debug)]
pub enum BastionError {
    MissingAuthHeader,
    InvalidAuthHeader,
    InvalidApiKey,
    ApiKeyNotFound,
    InvalidEmail,
    EmailAlreadyExists,
    InvalidRegenToken,
    RateLimitExceeded,
    DemoLimitExceeded,
    HardLimitExceeded,
    HardLimitTooLow,
    InvalidJsonBody,
    PasswordEmpty,
    PasswordTooLong,
    PaidTierNotImplemented,
}

impl BastionError {
    pub fn into_response(self) -> Result<Response> {
        let (code, message, status) = match self {
            Self::MissingAuthHeader => ("MISSING_AUTH_HEADER", "No Authorization header provided", 401),
            Self::InvalidAuthHeader => ("INVALID_AUTH_HEADER", "Authorization header is not in the correct format", 401),
            Self::InvalidApiKey => ("INVALID_API_KEY", "Key does not have a valid bsn_live_ prefix", 401),
            Self::ApiKeyNotFound => ("API_KEY_NOT_FOUND", "Key is valid but not registered", 401),
            Self::InvalidEmail => ("INVALID_EMAIL", "Email is not in a valid format", 400),
            Self::EmailAlreadyExists => ("EMAIL_ALREADY_EXISTS", "Email is already registered", 400),
            Self::InvalidRegenToken => ("INVALID_REGEN_TOKEN", "Provided regeneration token is invalid", 401),
            Self::RateLimitExceeded => ("RATE_LIMIT_EXCEEDED", "API rate limit exceeded", 429),
            Self::DemoLimitExceeded => ("DEMO_LIMIT_EXCEEDED", "Demo limit reached. Sign up for a free API key.", 429),
            Self::HardLimitExceeded => ("HARD_LIMIT_EXCEEDED", "User-defined hard limit exceeded", 429),
            Self::HardLimitTooLow => ("HARD_LIMIT_TOO_LOW", "Provided hard limit is below the usage limit", 400),            
            Self::InvalidJsonBody => ("INVALID_JSON_BODY", "Request body is missing or malformed", 400),
            Self::PasswordEmpty => ("PASSWORD_EMPTY", "Password cannot be empty", 400),
            Self::PasswordTooLong => ("PASSWORD_TOO_LONG", "Password cannot exceed 128 characters", 400),
            Self::PaidTierNotImplemented => ("PAID_TIER_NOT_IMPLEMENTED", "Features for paid tiers are not implemented yet", 501),
        };

        Ok(Response::from_json(&serde_json::json!({
            "error": code,
            "message": message
        }))?.with_status(status))
    }
}

pub enum AppError {
    Bastion(BastionError),
    Worker(worker::Error),
    Response(Response)
}

impl From<BastionError> for AppError {
    fn from(err: BastionError) -> Self {
        Self::Bastion(err)
    }
}

impl From<worker::Error> for AppError {
    fn from(err: worker::Error) -> Self {
        Self::Worker(err)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        Self::Worker(worker::Error::RustError(err.to_string()))
    }
}

impl AppError {
    pub fn into_response(self) -> Result<Response> {
        match self {
            Self::Bastion(err) => err.into_response(),
            Self::Worker(err) => Ok(Response::from_json(&serde_json::json!({
                "error": "INTERNAL_SERVER_ERROR",
                "message": format!("An unexpected error occurred: {}", err.to_string())
            }))?.with_status(500)),
            Self::Response(resp) => Ok(resp),
        }
    }
}