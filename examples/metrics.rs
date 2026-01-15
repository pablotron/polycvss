//! Parse [CVSS][] vector string, then iterate over vector metrics and
//! print the metric, metric name, and metric group.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example metrics
//! ```
//!
//! [cvss]: https://first.org/cvss/
//!   "Common Vulnerability Scoring System (CVSS)"

use polycvss::{Err, Group, Name, Vector};

fn main() -> Result<(), Err> {
  // vector string
  let s = "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/CR:H/IR:H/E:A/S:N";

  // parse vector string
  let vector: Vector = s.parse()?;

  for metric in vector {
    let name = Name::from(metric); // get metric name
    let group = Group::from(metric); // get metric group
    println!("{metric} {name} {group}"); // print metric, name, and group
  }

  Ok(())
}
