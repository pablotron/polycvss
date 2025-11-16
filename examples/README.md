# Examples

[polycvss][] examples:

- `cvss-score.rs`: Parse command line argument as vector, then print the
  score and severity.
- `errors.rs`: Show various errors.
- `metrics.rs`: Iterate over vector metrics and print the metric, metric
  name, and metric group.
- `severity.rs`: Print severity of several vector strings.
- `sort-by-score.rs`: Sort vector strings by score.
- `version.rs`: Print version of several vector strings.
- `v2-scores.rs`: Print base, temporal, and environmental scores for
  [CVSS v2][] vector string.
- `v4-macrovector.rs`: Print [macro vector][] for [CVSS v4][] vector strings.
- `v4-nomenclature.rs`: Print [nomenclature][] for [CVSS v4][] vector strings.

Each example can be run with `cargo run --example NAME`, like this:

```sh
# run "metrics" example
$ cargo run --example metrics
```

[polycvss]: https://github.com/pablotron/polycvss
  "polycvss Rust library"
[cvss v2]: https://www.first.org/cvss/v2/guide
  "CVSS v2.0 Documentation"
[cvss v4]: https://www.first.org/cvss/v4-0/specification-document
  "CVSS v4.0 Specification"
[nomenclature]: https://www.first.org/cvss/v4-0/specification-document#Nomenclature
  "CVSS v4.0 Specification, Section 1.3: Nomenclature"
[macro vector]: https://www.first.org/cvss/v4-0/specification-document#CVSS-v4-0-Scoring
  "CVSS v4.0 Specification, Section 8: CVSS v4.0 Scoring"
