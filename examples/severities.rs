//! Parse [CVSS][] vector strings and print their severities.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example severities
//! ```
//! 
//! [cvss]: https://first.org/cvss/
//!   "Common Vulnerability Scoring System (CVSS)"

use polycvss::{Err, Score, Severity, Vector};

fn main() -> Result<(), Err> {
  // vector strings
  let strs = vec!(
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:N/E:P/RL:T/RC:R/IR:H/AR:M",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
  );

  for s in strs {
    let vec: Vector = s.parse()?; // parse vector string
    let severity = Severity::from(Score::from(vec)); // get severity
    println!("{severity} {s}"); // print severity and vector string
  }

  Ok(())
}
