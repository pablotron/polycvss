//! Print macro vectors for [CVSS v4][] vector strings.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example v4-macrovectors
//! ```
//!
/// [cvss v4]: https://www.first.org/cvss/v4-0/specification-document
///   "CVSS v4.0 Specification"

use polycvss::{Err, v4::{MacroVector, Vector}};

fn main() -> Result<(), Err> {
  // vector strings
  let strs = vec!(
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/CR:M/IR:L/MAC:H/MAT:P/S:N/AU:N/R:U/RE:L/U:Clear",
  );

  for s in strs {
    let vec: Vector = s.parse()?; // parse vector string
    let mv = MacroVector::from(vec); // get macrovector
    println!("{mv} {s}"); // print macrovector and vector string
  }

  Ok(())
}
