use std::f64::consts::LOG2_10;

use zxcvbn::{Score, zxcvbn};
use super::models::EvaluationResult;
use super::models::CrackTimes;

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