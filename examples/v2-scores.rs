//! Print base, temporal, and environmental scores for a [CVSS v2][]
//! vector string.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example v2-scores
//! ```
//! 
//! [cvss v2]: https://www.first.org/cvss/v2/guide
//!   "CVSS v2.0 Documentation"

use polycvss::{Err, v2::{Scores, Vector}};

fn main() -> Result<(), Err> {
	// CVSS v2 vector string
	let s = "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L";

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
