//! Minimal command-line [CVSS][] score calculator.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example cvss-score [VECTOR]
//! ```
//!
//! # Examples
//!
//! Score CVSS v2 vector string:
//!
//! ```sh
//! $ cargo run -q --example cvss-score "AV:A/AC:H/Au:N/C:C/I:C/A:C"
//! 6.8 MEDIUM
//! ```
//! Score CVSS v3 vector string:
//!
//! ```sh
//! $ cargo run -q --example cvss-score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
//! 9.8 CRITICAL
//! ```
//!
//! Score CVSS v4 vector string:
//!
//! ```sh
//! $ cargo run -q --example cvss-score "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H"
//! 5.2 MEDIUM
//! ```
//!
//! [cvss]: https://first.org/cvss/
//!   "Common Vulnerability Scoring System (CVSS)"

use polycvss::{Err, Score, Severity, Vector};

fn main() -> Result<(), Err> {
  let args: Vec<String> = std::env::args().collect(); // get cli args

  if args.len() == 2 {
    let vec: Vector = args[1].parse()?; // parse string
    let score = Score::from(vec); // get score
    let severity = Severity::from(score); // get severity
    println!("{score} {severity}"); // print score and severity
  } else {
    let name = args.first().map_or("app", |s| s); // get app name
    eprintln!("Usage: {name} [VECTOR]"); // print usage
  }

  Ok(())
}
