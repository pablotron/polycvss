# polycvss

[Rust][] library to parse and score [CVSS][] vector strings.

Features:

- [CVSS v2][doc-v2], [CVSS v3][doc-v3], and [CVSS v4][doc-v4] support.
- Version-agnostic parsing and scoring [API][].
- Memory efficient: Vectors are 8 bytes. Scores and severities are 1 byte.
- No dependencies by default except the standard library.
- Optional [serde][] integration via the `serde` build feature.
- Extensive tests: Tested against thousands of vectors and scores from
  the [NVD][] [CVSS][] calculators.

Links:

- [polycvss package on crates.io][crates-io-polycvss]
- [polycvss API Documentation on docs.rs][docs-rs-polycvss]

Here is an example tool which parses the first command-line argument as
a [CVSS][] vector string, then prints the score and severity:

```rust
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
```

Here is the example tool output for a [CVSS v2][doc-v2] vector string, a
[CVSS v3][doc-v3] vector string, and a [CVSS v4][doc-v4] vector string:

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

This example tool is included in the [Git repository][] as
[`src/bin/cvss-score.rs`][cvss-score].

## Install

[polycvss package page on crates.io][crates-io-polycvss]

Run `cargo add polycvss` to add [polycvss][] as a dependency to an
exiting [Rust][] project:

```sh
$ cargo add polycvss
```

Run `cargo install polycvss` to install the example `cvss-score` tool:

```sh
# install cvss-score in cargo bin dir (e.g. `~/.cargo/bin`)
$ cargo install polycvss
```

## Build

Run `cargo build` to create a debug build of the example tool in
`target/debug`:

```sh
$ cargo build
...
$ target/debug/cvss-score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
9.8 CRITICAL
```

Run `cargo build --release` to create a release build of the example
tool in `target/release`:

```sh
$ cargo build --release
...
$ target/release/cvss-score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
9.8 CRITICAL
```

You can also build the example `cvss-score` tool in a container using
[Podman][] or [Docker][] like this:

```sh
$ podman run --rm -t -v "$PWD":/src -w /src docker.io/rust cargo build --release
...
$ target/release/cvss-score "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H"
5.2 MEDIUM
```

To build a static binary of the example `cvss-score` tool in a container:

```sh
$ podman run --rm -it -v .:/src -w /src rust sh -c "rustup target add $(arch)-unknown-linux-musl && cargo build --release --target $(arch)-unknown-linux-musl"
...
$ ldd target/$(arch)-unknown-linux-musl/release/cvss-score
        statically linked
$ du -sh target/$(arch)-unknown-linux-musl/release/cvss-score
604K    target/x86_64-unknown-linux-musl/release/cvss-score
```

## Documentation

[polycvss API documentation on docs.rs][docs-rs-polycvss]

Run `cargo doc` to build the [API][] documentation locally in
`target/doc/polycvss/`:

```sh
$ cargo doc
...
$ ls target/doc/polycvss/index.html
target/doc/polycvss/index.html
```

Run `cargo doc --lib` build the library documentation and exclude the
example tool documentation:

```sh
# remove generated docs
# (needed to clean up stale artifacts)
$ cargo clean --doc

# generate library-only docs
$ cargo doc --lib
```

## Tests

Use `cargo test` to run the test suite:

```sh
$ cargo test
...
test result: ok. 369 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
$
```

Use `cargo clippy` to run the [linter][]:

```sh
$ cargo clippy
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.04s
$
```

The test suite includes a large number of scored [CVSS][] vector string
test cases.  The test cases were generated using [cvss-calcs][].

The generated test cases can be found in [`src/v3.rs`][src-v2-rs],
[`src/v3.rs`][src-v3-rs], and [`src/v4.rs`][src-v4-rs].

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
[polycvss]: https://github.com/pablotron/polycvss
  "polycvss Rust library"
[v2-calc]: https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator
  "NVD CVSS v2 calculator"
[v3-calc]: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
  "NVD CVSS v3 calculator"
[v4-calc]: https://nvd.nist.gov/site-scripts/cvss-v4-calculator-main/
  "NVD CVSS v4 calculator"
[cargo]: https://doc.rust-lang.org/cargo/
  "Rust package manager"
[podman]: https://podman.io/
  "Podman container management tool"
[docker]: https://docker.com/
  "Docker container management tool"
[api]: https://en.wikipedia.org/wiki/API
  "Application Programming Interface (API)"
[linter]: https://en.wikipedia.org/wiki/Lint_(software)
  "Static code analysis tool to catch common mistakes"
[src-v2-rs]: src/v2.rs
  "CVSS v2 parsing and scoring"
[src-v3-rs]: src/v3.rs
  "CVSS v3 parsing and scoring"
[src-v4-rs]: src/v4.rs
  "CVSS v4 parsing and scoring"
[nvd]: https://nvd.nist.gov/
  "National Vulnerability Database (NVD)"
[cvss-calcs]: https://github.com/pablotron/cvss-calcs
  "Generate random CVSS vector strings and score them."
[crates.io]: https://crates.io/
  "Rust package registry"
[docs-rs-polycvss]: https://docs.rs/polycvss
  "polycvss API documentation on docs.rs"
[crates-io-polycvss]: https://crates.io/crates/polycvss
  "polycvss on crates.io"
[serde]: https://serde.rs/
  "Rust serializing and deserializing framework."
