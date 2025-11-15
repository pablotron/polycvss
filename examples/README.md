# Examples

[polycvss] examples.

- `cvss-score.rs`: Parse command line argument as vector, then print the
  score and severity.
- `metrics.rs`: Iterate over vector metrics and print the metric, metric
  name, and metric group.
- `severities.rs`: Print severity of several vector strings.
- `versions.rs`: Print version of several vector strings.
- `v2-scores.rs`: Print base, temporal, and environmental scores for a
  [CVSS v2][] vector string.

[polycvss]: https://github.com/pablotron/polycvss
  "polycvss Rust library"
[cvss v2]: https://www.first.org/cvss/v2/guide
  "CVSS v2.0 Documentation"
