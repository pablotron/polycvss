//! Print base, temporal, and environmental scores for a [CVSS v3][cvss-v3]
//! vector string.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example v3-scores
//! ```
//!
//! [cvss-v3]: https://www.first.org/cvss/v3-1/specification-document
//!   "CVSS v3.1 Specification"

use polycvss::{Err, v3::{Scores, Vector}};

fn main() -> Result<(), Err> {
	// CVSS v3 vector string
	let s = "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H/E:H/RL:W/AR:L/MAC:H/MA:L";

  let vector: Vector = s.parse()?; // parse string
  let scores = Scores::from(vector); // get scores

  // convert temporal score to string (or "n/a" if it's undefined)
  let temporal = match scores.temporal {
    Some(score) => score.to_string(),
    None => "n/a".to_string(),
  };

  // convert environmental score to string (or "n/a" if it's undefined)
  let environmental = match scores.environmental {
    Some(score) => score.to_string(),
    None => "n/a".to_string(),
  };

  // print results
  println!("base score = {}", scores.base);
  println!("temporal score = {}", temporal);
  println!("environmental score = {}", environmental);

  Ok(())
}
