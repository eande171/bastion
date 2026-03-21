use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
pub struct CrackTimes {
    pub online_throttled:   String,
    pub online_unthrottled: String,
    pub offline_slow_hash:  String,
    pub offline_fast_hash:  String,
}

impl CrackTimes {
    pub fn new(
        online_throttled:   String,
        online_unthrottled: String,
        offline_slow_hash:  String,
        offline_fast_hash:  String,
    ) -> Self {
        CrackTimes {
            online_throttled,
            online_unthrottled,
            offline_slow_hash,
            offline_fast_hash,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct EvaluationRequest {
    pub password: String,
}

#[derive(Deserialize, Debug)]
pub struct RegisterRequest {
    pub email: String,
}

#[derive(Serialize, Debug)]
pub struct EvaluationResult {
    pub score:          u8,
    pub strength:       String,
    pub entropy_bits:   f64,
    pub crack_times:    CrackTimes,
    pub breached:       Option<bool>,
    pub breach_count:   Option<u64>,
    pub warning:        Option<String>,
    pub suggestions:    Option<Vec<String>>,
}

impl EvaluationResult {
    pub fn new(
        score: u8, 
        strength: String, 
        entropy_bits: f64, 
        crack_times: CrackTimes, 
        breached: Option<bool>, 
        breach_count: Option<u64>, 
        warning: Option<String>, 
        suggestions: Option<Vec<String>>
    ) -> Self {
        EvaluationResult {
            score,
            strength,
            entropy_bits,
            crack_times,
            breached,
            breach_count,
            warning,
            suggestions,
        }
    }
}