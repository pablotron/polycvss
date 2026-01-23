//! Print score, macrovector, and nomenclature for a [CVSS v4][cvss-v4]
//! vector string.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example v4-scores
//! ```
//!
//! [cvss-v4]: https://www.first.org/cvss/v4-0/specification-document
//!   "CVSS v4.0 Specification"

use polycvss::{Err, v4::{Nomenclature, Scores, Vector}};

fn main() -> Result<(), Err> {
  // CVSS v4 vector string
  let s = "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:M/AR:M";

  let vector: Vector = s.parse()?; // parse string
  let scores = Scores::from(vector); // get scores
  let nomenclature = Nomenclature::from(vector); // get nomenclature

  // print results
  println!("score = {}", scores.score);
  println!("macrovector = {}", scores.macrovector);
  println!("nomenclature = {}", nomenclature);

  Ok(())
}
