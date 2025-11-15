//! Parse [CVSS][] vector strings and print their version.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example versions
//! ```
use polycvss::{Err, Version, Vector};

fn main() -> Result<(), Err> {
  // vector strings
  let strs = vec!(
    "AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
  );

  for s in strs {
    let vec: Vector = s.parse()?; // parse vector string
    let version = Version::from(vec); // get version
    println!("{version} {s}"); // print version and string
  }

  Ok(())
}
