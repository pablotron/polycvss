//! Print nomenclature for [CVSS v4][cvss-v4] vector strings.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example v4-nomenclatures
//! ```
//!
//! [cvss-v4]: https://www.first.org/cvss/v4-0/specification-document
//!   "CVSS v4.0 Specification"

use polycvss::{Err, v4::{Nomenclature, Vector}};

fn main() -> Result<(), Err> {
  // vector strings
  let strs = vec!(
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/MAV:N",
  );

  for s in strs {
    let vec: Vector = s.parse()?; // parse vector string
    let nom = Nomenclature::from(vec); // get nomenclature
    println!("{nom} {s}"); // print nomenclature and vector string
  }

  Ok(())
}
