//! Print score and base score for several vectors.
//!
//! # Description
//!
//! The `base_score()` method allows you to get the base score for [CVSS
//! v2][cvss-v2] and [CVSS v3][cvss-v3] vectors.  For [CVSS v4][cvss-v4]
//! vectors the score returned by `base_score()` is identical to the
//! score returned by `Score::from()`.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example base-score
//! ```
//!
//! [cvss-v2]: https://www.first.org/cvss/v2/guide
//!   "CVSS v2.0 Documentation"
//! [cvss-v3]: https://www.first.org/cvss/v3-1/specification-document
//!   "CVSS v3.1 Specification"
//! [cvss-v4]: https://www.first.org/cvss/v4-0/specification-document
//!   "CVSS v4.0 Specification"

use polycvss::{Err, Vector, Score};

fn main() -> Result<(), Err> {
  // vector strings
  let strs = vec!(
	  "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L",
    "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H/E:H/RL:W/AR:L/MAC:H/MA:L",
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
  );

  for s in strs {
    let vec: Vector = s.parse()?; // parse vector string
    let score = Score::from(vec); // get score
    let base_score = vec.base_score(); // get base score
    println!("{score} {base_score} {s}"); // print score, base score, and string
  }

  Ok(())
}
