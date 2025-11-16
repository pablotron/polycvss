//! Sort vector strings by score.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example sort-by-score
//! ```

use polycvss::{Vector, Score};

fn main() {
  // vector strings
  let strs = vec!(
    "AV:N/AC:L/Au:N/C:C/I:N/A:N",
    "AV:N/AC:M/Au:S/C:P/I:C/A:N/E:U/RL:OF/RC:UC/CDP:H/CR:M",
    "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H/E:U/RL:U/CR:L/IR:L",
    "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N/E:P/RL:O/RC:U/CR:M/IR:L/AR:M",
    "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:H/E:P/RL:O/RC:U/CR:L/AR:H",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:H",
    "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:L/SA:H/E:A/CR:M/IR:H",
  );

  // sort vector strings by score
  let sorted = {
    // parse and score vector strings
    let mut scored: Vec<(&str, Score)> = strs.into_iter().map(
      |s| (s, Score::from(s.parse::<Vector>().unwrap()))
    ).collect();

    // sort vector strings by score
    scored.sort_by(|a, b| a.1.cmp(&b.1));

    // return sorted vector
    scored
  };

  for (s, score) in sorted {
    println!("{score} {s}"); // print score and string
  }
}
