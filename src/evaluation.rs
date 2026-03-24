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

use std::f64::consts::LOG2_10;
use serde::Serialize;

use zxcvbn::{Score, zxcvbn};

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

pub fn evaluate(password: &str) -> EvaluationResult {
    let result = zxcvbn(password, &[]);

    let score = result.score();
    let strength = strength(score);
    let entropy_bits = result.guesses_log10() * LOG2_10;

    let times = result.crack_times();
    let crack_times = CrackTimes::new(
        times.online_throttling_100_per_hour().to_string(),
        times.online_no_throttling_10_per_second().to_string(),
        times.offline_slow_hashing_1e4_per_second().to_string(),
        times.offline_fast_hashing_1e10_per_second().to_string(),
    );

    let feedback = result.feedback();

    let warning = feedback
        .and_then(|f| f.warning())
        .map(|s| s.to_string());

    let suggestions = feedback
        .map(|f| f.suggestions()
            .iter()
            .map(|s| s.to_string())
            .collect()
        );

    let breached = None;
    let breach_count = None;

    EvaluationResult::
        new(score as u8, 
            strength, 
            entropy_bits, 
            crack_times, 
            breached, 
            breach_count, 
            warning, 
            suggestions
        )
}

fn strength(score: Score) -> String {
    match score {
        Score::Zero => "Very Weak".to_string(),
        Score::One => "Weak".to_string(),
        Score::Two => "Fair".to_string(),
        Score::Three => "Strong".to_string(),
        Score::Four => "Very Strong".to_string(),
        _ => "Unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn very_weak_password() {
        let result = evaluate("password");
        assert_eq!(result.score, 0);
        assert_eq!(result.strength, "Very Weak");
        assert!(result.warning.is_some());
    }

    #[test]
    fn strong_passphrase() {
        let result = evaluate("correct-horse-battery-staple-42!");
        assert!(result.score >= 3);
        assert!(result.breach_count.is_none());
    }
}