# polycvss

[Rust][] library to parse and score [CVSS][] vector strings.

Features:

- [CVSS v2][doc-v2], [CVSS v3][doc-v3], and [CVSS v4][doc-v4] support.
- Memory efficient: Parsed vectors are 8 bytes. Scores and severities are
  1 byte.
- Extensive tests.  *TODO* wordify this.

Example (included as [`src/bin/cvss-score.rs`][cvss-score]):

```rust
use std::env;
use polycvss::{Err, Score, Severity, Vector};

fn main() -> Result<(), Err> {
  let args: Vec<String> = env::args().collect(); // get cli args

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
```

Output:

```sh
# test with cvss v2 vector string
$ cvss-score "AV:A/AC:H/Au:N/C:C/I:C/A:C"
6.8 MEDIUM

# test with cvss v3 vector string
$ cvss-score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
9.8 CRITICAL

# test with cvss v4 vector string
$ cvss-score "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H"
5.2 MEDIUM
```

## Build

TODO: `cargo build`

## Documentation

TODO: `cargo doc --no-deps --lib`

## Tests

TODO: `cargo test`

[html]: https://en.wikipedia.org/wiki/HTML
  "HyperText Markup Language"
[rust]: https://rust-lang.org/
  "Rust programming language."
[cvss]: https://www.first.org/cvss/
  "Common Vulnerability Scoring System (CVSS)"
[doc-v2]: https://www.first.org/cvss/v2/guide
  "CVSS v2.0 Documentation"
[doc-v3]: https://www.first.org/cvss/v3-1/specification-document
  "CVSS v3.1 Specification"
[doc-v4]: https://www.first.org/cvss/v4-0/specification-document
  "Common Vulnerability Scoring System (CVSS) version 4.0 Specification"
[bit-field]: https://en.wikipedia.org/wiki/Bit_field
  "Bit field (Wikipedia)"
[cvss-score]: src/bin/cvss-score.rs
  "Example command-line tool which parses a CVSS vector and prints the score and severity to standard output."
[git repository]: https://github.com/pablotron/polycvss
  "polycvss git repository"
