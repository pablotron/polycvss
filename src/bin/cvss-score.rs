//! Minimal command-line [CVSS][] score calculator.
//!
//! # Usage
//!
//! ```sh
//! cvss-score [VECTOR]
//! ```
//!
//! # Examples
//!
//! Score CVSS v2 vector string:
//!
//! ```sh
//! $ cvss-score "AV:N/AC:L/Au:N/C:C/I:C/A:C"
//! 10.0
//! ```
//! Score CVSS v3 vector string:
//!
//! ```sh
//! $ cvss-score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
//! 9.8
//! ```
//!
//! Score CVSS v4 vector string:
//!
//! ```sh
//! $ cvss-score "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
//! 9.4
//! ```
//! 
//! [cvss]: https://first.org/cvss/
//!   "Common Vulnerability Scoring System (CVSS)"

use std::env;
use polycvss::{Err, Score, Vector};

fn main() -> Result<(), Err> {
  let args: Vec<String> = env::args().collect(); // get cli args

  if args.len() == 2 {
    let vec: Vector = args[1].parse()?; // parse string
    println!("{}", Score::from(vec)); // print score
  } else {
    let name = args.first().map_or("app", |s| s); // get app name
    eprintln!("Usage: {name} [VECTOR]"); // print usage
  }

  Ok(())
}
