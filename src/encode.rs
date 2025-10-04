//! [bit field][bit-field] encoding for [CVSS][] metrics.
//!
//! [cvss]: https://www.first.org/cvss
//!   "Common Vulnerability Scoring System (CVSS)"
//! [bit-field]: https://en.wikipedia.org/wiki/Bit_field
//!   "Bit field (Wikipedia)"

/// Encoded metric value.
pub enum EncodedVal {
  /// Encoded value for CVSS v4 metrics with a 2 or 4 possible values
  /// and CVSS v3 metrics with 3 or 5 possible values.
  Shift(u64),

  /// Encoded value for CVSS v4 metrics with a 3 or 5
  /// possible values.  Not used for CVSS v3 metrics.
  ///
  /// **Note:** This encoding is not used for CVSS v3 metrics because:
  ///
  /// 1. CVSS v3 vectors use only 44 bits with `Shift` encoding; this
  ///    encoding is not needed to fit in 64 bits.
  /// 2. This encoding would save about 4 bits for CVSS v3 vectors.
  Arith(u64),
}

/// Encoded metric.
pub struct EncodedMetric {
  /// Name bit. Used to check for duplicate metrics and to check for
  /// mssing mandatory metrics.
  pub bit: u32,

  /// Encoded value.
  pub val: EncodedVal,
}
