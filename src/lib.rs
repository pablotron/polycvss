//! [CVSS][cvss] [v2][doc-v2], [v3][doc-v3], and [v4][doc-v4] vector
//! string parser and score calculator.
//!
//! Parse a vector string:
//!
//! ```
//! # use polycvss::{Err, Vector};
//! # fn main() -> Result<(), Err> {
//! let vec: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
//! # Ok(())
//! # }
//! ```
//!
//! Calculate vector score:
//!
//! ```
//! # use polycvss::{Err, Score, Vector};
//! # fn main() -> Result<(), Err> {
//! # let vec: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
//! let score = Score::from(vec);
//! # Ok(())
//! # }
//! ```
//!
//! Get score severity:
//!
//! ```
//! # use polycvss::{Err, Score, Severity};
//! # fn main() -> Result<(), Err> {
//! # let score = Score::from(9.3);
//! let severity = Severity::from(score);
//! # Ok(())
//! # }
//! ```
//!
//! Vectors, scores, and severities are very small (see ["Internal
//! Representation"][ir]):
//!
//! ```
//! # use polycvss::{Score, Severity, Vector};
//! # fn main() {
//! assert_eq!(size_of::<Score>(), size_of::<u8>()); // 1 byte
//! assert_eq!(size_of::<Severity>(), size_of::<u8>()); // 1 byte
//! assert_eq!(size_of::<Vector>(), size_of::<u64>()); // 8 bytes
//! # }
//! ```
//!
//! # Examples
//!
//! Parse vector strings:
//!
//! ```
//! # use polycvss::{Err, Vector};
//! # fn main() -> Result<(), Err> {
//! // parse CVSS v2 vector string
//! let v2: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
//!
//! // parse CVSS v3 vector string
//! let v3: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
//!
//! // parse CVSS v4 vector string
//! let v4: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
//! # Ok(())
//! # }
//! ```
//!
//! Get vector score:
//!
//! ```
//! # use polycvss::{Err, Score, Vector};
//! # fn main() -> Result<(), Err> {
//! // parse CVSS v4 vector string
//! let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
//!
//! // get score
//! let score = Score::from(v);
//!
//! // check result
//! assert_eq!(score, Score::from(10.0));
//! # Ok(())
//! # }
//! ```
//!
//! Compare scores:
//!
//! ```
//! # use polycvss::{Err, Score};
//! # fn main() -> Result<(), Err> {
//! let a = Score::from(1.2); // first score
//! let b = Score::from(3.5); // second score
//! assert!(a < b); // compare scores
//! # Ok(())
//! # }
//! ```
//!
//! Get score severity:
//!
//! ```
//! # use polycvss::{Err, Score, Severity};
//! # fn main() -> Result<(), Err> {
//! let severity = Severity::from(Score::from(2.3));
//! assert_eq!(severity, Severity::Low);
//! # Ok(())
//! # }
//! ```
//!
//! Compare severities:
//!
//! ```
//! # use polycvss::{Err, Severity};
//! # fn main() -> Result<(), Err> {
//! let a = Severity::Low; // first severity
//! let b = Severity::High; // second severity
//! assert!(a < b); // compare severities
//! # Ok(())
//! # }
//! ```
//!
//! Get metric from vector by name:
//!
//! ```
//! # use polycvss::{Err, Vector, Metric, Name, v4};
//! # fn main() -> Result<(), Err> {
//! // parse CVSS v4 vector string
//! let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
//!
//! // get metric
//! let metric = v.get(Name::V4(v4::Name::AttackVector))?;
//!
//! // check result
//! assert_eq!(metric, Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Network)));
//! # Ok(())
//! # }
//! ```
//!
//! Iterate over vector metrics:
//!
//! ```
//! # use polycvss::{Err, Vector};
//! # fn main() -> Result<(), Err> {
//! // parse CVSS v4 vector string
//! let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
//!
//! // print metrics
//! for m in v {
//!   println!("metric: {m}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Show that metrics are always sorted in specification order when
//! converting a [`Vector`][] to a string. In other words, the original
//! metric order is **not** preserved:
//!
//! ```
//! # use polycvss::{Err, Vector};
//! # fn main() -> Result<(), Err> {
//! // parse v3 vector string with PR metric BEFORE AV and AC metric
//! let v: Vector = "CVSS:3.1/PR:N/AV:N/AC:L/UI:N/S:U/C:H/I:H/A:H".parse()?;
//!
//! // check result; output string has PR metric AFTER AV and AC metric
//! assert_eq!(v.to_string(), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
//! # Ok(())
//! # }
//! ```
//!
//! Show that metrics with a value of `Not Defined (X)` are omitted when
//! converting a [`Vector`][] to a string:
//!
//! ```
//! # use polycvss::{Err, Vector};
//! # fn main() -> Result<(), Err> {
//! // parse v3 vector string with MAV:X metric
//! let v: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:X".parse()?;
//!
//! // check result; output string does NOT include MAV:X
//! assert_eq!(v.to_string(), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
//! # Ok(())
//! # }
//! ```
//!
//! # Internal Representation
//!
//! A [`Vector`] is represented internally as a [bit field][bit-field]
//! within a [`u64`].  Metric values are packed in the lower 60 bits
//! and the [CVSS][] version is packed in the in the upper 4 bits:
//!
//! | Bit Range | Description      |
//! | --------- | ---------------- |
//! | `0..60`   | Metric values    |
//! | `60..64`  | [CVSS][] version |
//!
//! The bit packing varies by [CVSS][] version:
//!
//! | Version | Module | Metric Bits | Unused Bits | Version Bits |
//! | ------------ | ------ | ----------- | ----------- | ------------ |
//! | [CVSS v2][doc-v2] | [`polycvss::v2`][v2] | `0..32` | `32..60` | `60..64` |
//! | [CVSS v3][doc-v3] | [`polycvss::v3`][v3] | `0..44` | `44..60` | `60..64` |
//! | [CVSS v4][doc-v4] | [`polycvss::v4`][v4] | `0..59` | `59..60` | `60..64` |
//!
//! See [`v2::Vector`], [`v3::Vector`], and [`v4::Vector`] for additional details.
//!
//! [cvss]: https://www.first.org/cvss/
//!   "Common Vulnerability Scoring System (CVSS)"
//! [doc-v2]: https://www.first.org/cvss/v2/guide
//!   "CVSS v2.0 Documentation"
//! [doc-v3]: https://www.first.org/cvss/v3-1/specification-document
//!   "CVSS v3.1 Specification"
//! [doc-v4]: https://www.first.org/cvss/v4-0/specification-document
//!   "Common Vulnerability Scoring System (CVSS) version 4.0 Specification"
//! [bit-field]: https://en.wikipedia.org/wiki/Bit_field
//!   "Bit field (Wikipedia)"
//! [ir]: #internal-representation
//!   "Internal Representation section"

#![deny(missing_docs)]

// TODO:
// - README.md: intro: s/rust library to (.*)/$1 in Rust/
// - README.md: intro: document explicit v3.0 vs v3.1 scoring
// - README.md: badges, gh action for tests

pub mod v2;
pub mod v3;
pub mod v4;
pub mod encode;

/// Parse or conversion error.
///
/// # Example
///
/// ```
/// # use polycvss::{Err, Vector};
/// # fn main() {
/// // parse invalid string as vector
/// let err = "asdf".parse::<Vector>();
///
/// // check result
/// assert_eq!(err, Err(Err::Len));
/// # }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Err {
  /// String is too short.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, v4::Vector};
  /// # fn main() {
  /// // parse invalid string as vector, then check result
  /// assert_eq!("asdf".parse::<Vector>(), Err(Err::Len));
  /// # }
  /// ```
  Len,

  /// String does not begin with a CVSS prefix.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, v4::Vector};
  /// # fn main() {
  /// // parse invalid string as vector, then check result
  /// assert_eq!("CVSS:foo/".parse::<Vector>(), Err(Err::Prefix));
  /// # }
  /// ```
  Prefix,

  /// Vector string contains a duplicate metric.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, v4::Vector};
  /// # fn main() {
  /// // parse invalid string as vector, then check result
  /// assert_eq!("CVSS:4.0/AV:N/AV:N".parse::<Vector>(), Err(Err::DuplicateName));
  /// # }
  /// ```
  DuplicateName,

  /// Unknown metric name.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, v4::Name};
  /// # fn main() {
  /// // parse unknown metric name, check result
  /// assert_eq!("asdf".parse::<Name>(), Err(Err::UnknownName));
  /// # }
  /// ```
  UnknownName,

  /// String contains a metric with an unknown value.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, v4::Vector};
  /// # fn main() {
  /// // parse vector string with unknown metric value, then check result
  /// assert_eq!("CVSS:4.0/AV:Z".parse::<Vector>(), Err(Err::UnknownMetric));
  ///
  /// // parse vector string with unknown metric name, then check result
  /// assert_eq!("CVSS:4.0/ZZ:Z".parse::<Vector>(), Err(Err::UnknownMetric));
  /// # }
  /// ```
  UnknownMetric,

  /// Vector string is missing mandatory metrics.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, v4::Vector};
  /// # fn main() {
  /// // vector string missing mandatory metric
  /// let s = "CVSS:4.0/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";
  ///
  /// // parse string, check result
  /// assert_eq!(s.parse::<Vector>(), Err(Err::MissingMandatoryMetrics));
  /// # }
  /// ```
  MissingMandatoryMetrics,

  /// Unknown severity name.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, Severity};
  /// # fn main() {
  /// // vector string missing mandatory metric
  /// let s = "asdf";
  ///
  /// // parse string, check result
  /// assert_eq!(s.parse::<Severity>(), Err(Err::UnknownSeverity));
  /// # }
  /// ```
  UnknownSeverity,

  /// Invalid [`v4::MacroVector`] digit.
  ///
  /// A digit of a [`v4::MacroVector`] is out of range.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, v4::MacroVector};
  /// # fn main() {
  /// // parse unknown CVSS version, check result
  /// assert_eq!(MacroVector::try_from(123456), Err(Err::InvalidMacroVector));
  /// # }
  /// ```
  InvalidMacroVector,

  /// Unknown version.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, Version};
  /// # fn main() {
  /// // parse unknown CVSS version, check result
  /// assert_eq!("asdf".parse::<Version>(), Err(Err::UnknownVersion));
  /// # }
  /// ```
  UnknownVersion,
}

impl std::fmt::Display for Err {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{self:?}")
  }
}

// value mask.  used to exclude top 4 version bits
const VAL_MASK: u64 = 0x0fff_ffff_ffff_ffff;

/// [CVSS][] major version (e.g. 2.x, 3.x, or 4.x).
///
/// Used by [`Vector`] to dispatch to correct version-specific method.
///
/// [cvss]: https://www.first.org/cvss/
///   "Common Vulnerability Scoring System (CVSS)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum MajorVersion {
  /// [CVSS v2][doc-v2]
  ///
  /// [doc-v2]: https://www.first.org/cvss/v2/guide
  ///   "CVSS v2.0 Documentation"
  V2,

  /// [CVSS v3][doc-v3]
  ///
  /// [doc-v3]: https://www.first.org/cvss/v3-1/specification-document
  ///   "CVSS v3.1 Specification"
  V3,

  /// [CVSS v4][doc-v4]
  ///
  /// [doc-v4]: https://www.first.org/cvss/v4-0/specification-document
  ///   "Common Vulnerability Scoring System (CVSS) version 4.0 Specification"
  V4,
}

impl From<Vector> for MajorVersion {
  fn from(vec: Vector) -> MajorVersion {
    match Version::from(vec) {
      Version::V20 | Version::V21 | Version::V22 | Version::V23 => MajorVersion::V2,
      Version::V30 | Version::V31 => MajorVersion::V3,
      Version::V40 => MajorVersion::V4,
    }
  }
}

/// [CVSS][] version.
///
/// # Examples
///
/// Check version:
///
/// ```
/// # use polycvss::{Err, Vector, Version};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v2 vector string, check version
/// let v2: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
/// assert_eq!(Version::from(v2), Version::V23);
///
/// // parse CVSS v3 vector string, check version
/// let v3: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
/// assert_eq!(Version::from(v3), Version::V31);
///
/// // parse CVSS v4 vector string, check version
/// let v4: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
/// assert_eq!(Version::from(v4), Version::V40);
/// # Ok(())
/// # }
/// ```
///
/// Compare versions:
///
/// ```
/// # use polycvss::{Err, Version};
/// # fn main() -> Result<(), Err> {
/// let a = Version::V30; // first version
/// let b = Version::V40; // second version
/// assert!(a < b); // compare versions
/// # Ok(())
/// # }
/// ```
///
/// Convert version to string:
///
/// ```
/// # use polycvss::{Err, Version};
/// # fn main() -> Result<(), Err> {
/// let version = Version::V31;
/// assert_eq!(version.to_string(), "3.1");
/// # Ok(())
/// # }
/// ```
///
/// Convert string to version:
///
/// ```
/// # use polycvss::{Err, Version};
/// # fn main() -> Result<(), Err> {
/// let version: Version = "3.0".parse()?;
/// assert_eq!(version, Version::V30);
/// # Ok(())
/// # }
/// ```
///
/// [cvss]: https://www.first.org/cvss/
///   "Common Vulnerability Scoring System (CVSS)"
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
#[repr(u8)]
pub enum Version {
  /// CVSS v2.0
  V20 = 0,

  /// CVSS v2.1
  V21 = 1,

  /// CVSS v2.2
  V22 = 2,

  /// CVSS v2.3
  V23 = 3,

  /// CVSS v3.0
  V30 = 4,

  /// CVSS v3.1
  V31 = 5,

  /// CVSS v4.0
  V40 = 6,
}

impl std::fmt::Display for Version {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{}", match self {
      Version::V20 => "2.0",
      Version::V21 => "2.1",
      Version::V22 => "2.2",
      Version::V23 => "2.3",
      Version::V30 => "3.0",
      Version::V31 => "3.1",
      Version::V40 => "4.0",
    })
  }
}

impl std::str::FromStr for Version {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "2.0" => Ok(Version::V20),
      "2.1" => Ok(Version::V21),
      "2.2" => Ok(Version::V22),
      "2.3" => Ok(Version::V23),
      "3.0" => Ok(Version::V30),
      "3.1" => Ok(Version::V31),
      "4.0" => Ok(Version::V40),
      _ => Err(Err::UnknownVersion),
    }
  }
}

impl From<Version> for u64 {
  fn from(v: Version) -> u64 {
    (v as u64) << 60
  }
}

impl From<Vector> for Version {
  fn from(vec: Vector) -> Version {
    match Version::try_from(vec.0) {
      Ok(version) => version,

      // should never happen; it means we have a vector with a
      // corrupt version component
      Err(err) => panic!("{err}"),
    }
  }
}

impl TryFrom<u64> for Version {
  type Error = Err;

  fn try_from(val: u64) -> Result<Version, Self::Error> {
    match val >> 60 {
      0 => Ok(Version::V20),
      1 => Ok(Version::V21),
      2 => Ok(Version::V22),
      3 => Ok(Version::V23),
      4 => Ok(Version::V30),
      5 => Ok(Version::V31),
      6 => Ok(Version::V40),
      _ => Err(Err::UnknownVersion),
    }
  }
}

/// [`Metric`] name.
///
/// # Examples
///
/// Get metric name:
///
/// ```
/// # use polycvss::{Metric, Name, v4};
/// # fn main() {
/// // get metric name
/// let name = Name::from(v4::Metric::AttackVector(v4::AttackVector::Local));
///
/// // check result
/// assert_eq!(name, Name::V4(v4::Name::AttackVector));
/// # }
/// ```
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Name {
  /// [CVSS v2][doc-v2] metric name.  See [`v2::Name`].
  ///
  /// [doc-v2]: https://www.first.org/cvss/v2/guide
  ///   "CVSS v2.0 Documentation"
  V2(v2::Name),

  /// [CVSS v3][doc-v3] metric name.  See [`v3::Name`].
  ///
  /// [doc-v3]: https://www.first.org/cvss/v3-1/specification-document
  ///   "CVSS v3.1 Specification"
  V3(v3::Name),

  /// [CVSS v4][doc-v4]] metric name.  See [`v4::Name`].
  ///
  /// [doc-v4]: https://www.first.org/cvss/v4-0/specification-document
  ///   "Common Vulnerability Scoring System (CVSS) version 4.0 Specification"
  V4(v4::Name),
}

impl From<Metric> for Name {
  fn from(m: Metric) -> Name {
    match m {
      Metric::V2(m) => Name::V2(v2::Name::from(m)),
      Metric::V3(m) => Name::V3(v3::Name::from(m)),
      Metric::V4(m) => Name::V4(v4::Name::from(m)),
    }
  }
}

impl From<v2::Metric> for Name {
  fn from(m: v2::Metric) -> Name {
    Name::V2(v2::Name::from(m))
  }
}

impl From<v3::Metric> for Name {
  fn from(m: v3::Metric) -> Name {
    Name::V3(v3::Name::from(m))
  }
}

impl From<v4::Metric> for Name {
  fn from(m: v4::Metric) -> Name {
    Name::V4(v4::Name::from(m))
  }
}

impl From<v2::Name> for Name {
  fn from(m: v2::Name) -> Name {
    Name::V2(m)
  }
}

impl From<v3::Name> for Name {
  fn from(m: v3::Name) -> Name {
    Name::V3(m)
  }
}

impl From<v4::Name> for Name {
  fn from(m: v4::Name) -> Name {
    Name::V4(m)
  }
}

impl std::fmt::Display for Name {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    match self {
      Name::V2(name) => v2::Name::fmt(name, f),
      Name::V3(name) => v3::Name::fmt(name, f),
      Name::V4(name) => v4::Name::fmt(name, f),
    }
  }
}

/// [`Vector`] component.
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, Metric, v4};
/// # fn main() -> Result<(), Err> {
/// // parse string as CVSS v4 metric
/// let metric = Metric::from("AV:N".parse::<v4::Metric>()?);
///
/// // check result
/// assert_eq!(metric, Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Network)));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::{Metric, v4};
/// # fn main() {
/// // convert CVSS v4 metric to string
/// let s = Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Adjacent)).to_string();
///
/// // check result
/// assert_eq!(s, "AV:A");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::{Metric, Name, v4};
/// # fn main() {
/// // get metric name
/// let name = Name::from(v4::Metric::AttackVector(v4::AttackVector::Local));
///
/// // check result
/// assert_eq!(name, Name::V4(v4::Name::AttackVector));
/// # }
/// ```
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Metric {
  /// [CVSS v2][doc-v2] metric.  See [`v2::Metric`].
  ///
  /// [doc-v2]: https://www.first.org/cvss/v2/guide
  ///   "CVSS v2.0 Documentation"
  V2(v2::Metric),

  /// [CVSS v3][doc-v3] metric.  See [`v3::Metric`].
  ///
  /// [doc-v3]: https://www.first.org/cvss/v3-1/specification-document
  ///   "CVSS v3.1 Specification"
  V3(v3::Metric),

  /// [CVSS v4][doc-v4] metric.  See [`v4::Metric`].
  ///
  /// [doc-v4]: https://www.first.org/cvss/v4-0/specification-document
  ///   "Common Vulnerability Scoring System (CVSS) version 4.0 Specification"
  V4(v4::Metric),
}

impl From<v2::Metric> for Metric {
  fn from(m: v2::Metric) -> Metric {
    Metric::V2(m)
  }
}

impl From<v3::Metric> for Metric {
  fn from(m: v3::Metric) -> Metric {
    Metric::V3(m)
  }
}

impl From<v4::Metric> for Metric {
  fn from(m: v4::Metric) -> Metric {
    Metric::V4(m)
  }
}

impl std::fmt::Display for Metric {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    match self {
      Metric::V2(m) => v2::Metric::fmt(m, f),
      Metric::V3(m) => v3::Metric::fmt(m, f),
      Metric::V4(m) => v4::Metric::fmt(m, f),
    }
  }
}

/// [`Vector`] iterator.
///
/// # Description
///
/// Iterate over [`Metric`s][Metric] in a [`Vector`].
///
/// Notes:
/// - [`Metrics`][Metric] with a value of `Not Defined (X)` are skipped.
/// - [`Metrics`][Metric] are sorted in specification order.
/// - Created by [`Vector::into_iter()`].
///
/// # Examples
///
/// Iterate over [`Vector`] and appending each [`Metric`]
/// to a [`std::vec::Vec`]:
///
/// ```
/// # use polycvss::{Err, Metric, Vector, v4};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v4 vector string
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
///
/// // build ordered list (std::vec::Vec) of metrics
/// let mut metrics = Vec::new();
/// for metric in v {
///   metrics.push(metric);
/// }
///
/// // check result
/// assert_eq!(metrics, vec!(
///   Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Network)),
///   Metric::V4(v4::Metric::AttackComplexity(v4::AttackComplexity::Low)),
///   Metric::V4(v4::Metric::AttackRequirements(v4::AttackRequirements::None)),
///   Metric::V4(v4::Metric::PrivilegesRequired(v4::PrivilegesRequired::None)),
///   Metric::V4(v4::Metric::UserInteraction(v4::UserInteraction::None)),
///   Metric::V4(v4::Metric::VulnerableSystemConfidentialityImpact(v4::Impact::High)),
///   Metric::V4(v4::Metric::VulnerableSystemIntegrityImpact(v4::Impact::High)),
///   Metric::V4(v4::Metric::VulnerableSystemAvailabilityImpact(v4::Impact::High)),
///   Metric::V4(v4::Metric::SubsequentSystemConfidentialityImpact(v4::Impact::High)),
///   Metric::V4(v4::Metric::SubsequentSystemIntegrityImpact(v4::Impact::High)),
///   Metric::V4(v4::Metric::SubsequentSystemAvailabilityImpact(v4::Impact::High)),
/// ));
/// # Ok(())
/// # }
/// ```
///
/// Create a explicit iterator over [`Vector`] and get the first
/// [`Metric`]:
///
/// ```
/// # use polycvss::{Err, Metric, Vector, v4};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v4 vector string
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
///
/// // create iterator
/// let mut iter = v.into_iter();
///
/// // get first metric
/// let metric = iter.next();
///
/// // check result
/// assert_eq!(metric, Some(Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Network))));
/// # Ok(())
/// # }
/// ```
pub enum VectorIterator {
  /// [CVSS v2][doc-v2] vector iterator.  See [`v2::VectorIterator`].
  ///
  /// [doc-v2]: https://www.first.org/cvss/v2/guide
  ///   "CVSS v2.0 Documentation"
  V2(v2::VectorIterator),

  /// [CVSS v3][doc-v3] vector iterator.  See [`v3::VectorIterator`].
  ///
  /// [doc-v3]: https://www.first.org/cvss/v3-1/specification-document
  ///   "CVSS v3.1 Specification"
  V3(v3::VectorIterator),

  /// [CVSS v4][doc-v4] vector iterator.  See [`v4::VectorIterator`].
  ///
  /// [doc-v4]: https://www.first.org/cvss/v4-0/specification-document
  ///   "Common Vulnerability Scoring System (CVSS) version 4.0 Specification"
  V4(v4::VectorIterator),
}

impl Iterator for VectorIterator {
  type Item = Metric;

  fn next(&mut self) -> Option<Metric> {
    match self {
      VectorIterator::V2(iter) => iter.next().map(Metric::V2),
      VectorIterator::V3(iter) => iter.next().map(Metric::V3),
      VectorIterator::V4(iter) => iter.next().map(Metric::V4),
    }
  }
}

/// [CVSS][cvss] vector.
///
/// Notes:
///
/// - Parses [CVSS][] [v2][v2], [v3][v3], and [v4][v4] vector strings.
/// - Represented internally as a `u64` (8 bytes).  See "Internal
///   Representation" below.
/// - Metrics are sorted in specification order when iterating a
///   [`Vector`] or converting a [`Vector`] to a string; the order
///   of metrics in the original vector string is **not** preserved. See
///   "Examples" below.
/// - Optional metrics with a value of `Not Defined (X)` are skipped
///   when iterating a [`Vector`] or converting a [`Vector`] to a
///   string. See "Examples" below.
///
/// # Examples
///
/// Parse vector string:
///
/// ```
/// # use polycvss::{Err, Vector};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v2 vector string
/// let v2: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
///
/// // parse CVSS v3 vector string
/// let v3: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
///
/// // parse CVSS v4 vector string
/// let v4: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
/// # Ok(())
/// # }
/// ```
///
/// Iterate over vector metrics:
///
/// ```
/// # use polycvss::{Err, Vector};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v4 vector string
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
///
/// // print metrics
/// for m in v {
///   println!("metric: {m}");
/// }
/// # Ok(())
/// # }
/// ```
///
/// Get metric from vector:
///
/// ```
/// # use polycvss::{Err, Vector, Metric, Name, v4};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v4 vector string
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
///
/// // get metric
/// let metric = v.get(Name::V4(v4::Name::AttackVector))?;
///
/// // check result
/// assert_eq!(metric, Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Network)));
/// # Ok(())
/// # }
/// ```
///
/// Get score for several vector strings:
///
/// ```
/// # use polycvss::{Err, Score, Vector};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v2 vector string, get score
/// let v2: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
/// assert_eq!(Score::from(v2), Score::from(10.0));
///
/// // parse CVSS v3 vector string, get score
/// let v3: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
/// assert_eq!(Score::from(v3), Score::from(9.8));
///
/// // parse CVSS v4 vector string, get score
/// let v4: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
/// assert_eq!(Score::from(v4), Score::from(10.0));
/// # Ok(())
/// # }
/// ```
///
/// Get base score for several vector strings:
///
/// ```
/// # use polycvss::{Err, Score, Vector};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v2 vector string, get base score
/// let v2: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
/// assert_eq!(v2.base_score(), Score::from(10.0));
///
/// // parse CVSS v3 vector string, get base score
/// let v3: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
/// assert_eq!(v3.base_score(), Score::from(9.8));
///
/// // parse CVSS v4 vector string, get base score
/// let v4: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
/// assert_eq!(v4.base_score(), Score::from(10.0));
/// # Ok(())
/// # }
/// ```
///
/// Show that the order of metrics within a vector string is **not**
/// preserved when parsing a vector string and then converting the
/// [`Vector`] back to a string:
///
/// ```
/// # use polycvss::{Err, Vector};
/// # fn main() -> Result<(), Err> {
/// // vector string with first two metrics (AV and AC) swapped
/// let s = "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";
///
/// // expected result after parsing vector string above and converting
/// // the parsed vector back to a vector string
/// let exp = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";
///
/// // parse vector string, then convert parsed vector back to vector string
/// let got = s.parse::<Vector>()?.to_string();
///
/// // check result
/// assert_eq!(got, exp);
/// # Ok(())
/// # }
/// ```
///
/// Show that optional metrics with a value of `Not Defined (X)` are
/// **not** preserved when parsing a vector string and then converting the
/// [`Vector`] back to a string:
///
/// ```
/// # use polycvss::{Err, Vector};
/// # fn main() -> Result<(), Err> {
/// // vector string which contains an optional metric (MAV) with a
/// // value of `Not Defined (X)`
/// let s = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:X";
///
/// // expected result after parsing vector string above and converting
/// // the parsed vector back to a vector string
/// let exp = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";
///
/// // parse vector string, then convert parsed vector back to vector string
/// let got = s.parse::<Vector>()?.to_string();
///
/// // check result
/// assert_eq!(got, exp);
/// # Ok(())
/// # }
/// ```
///
/// Verify that a [`Vector`] is the same size as a `u64`:
///
/// ```
/// # use polycvss::Vector;
/// # fn main() {
/// assert_eq!(size_of::<Vector>(), size_of::<u64>());
/// # }
/// ```
///
/// Verify that a [`v4::Vector`] is the same size as one `u64`:
///
/// ```
/// # use polycvss::v4;
/// # fn main() {
/// assert_eq!(size_of::<v4::Vector>(), size_of::<u64>());
/// # }
/// ```
///
/// # Internal Representation
///
/// A [`Vector`] is represented internally as a [bit field][bit-field]
/// within a [`u64`],  The lower 60 bits contain encoded metric
/// values, and the upper 4 bits contain the vector version:
/// A [`Vector`] is represented internally as a [bit
/// field][bit-field] within a `u64`.  Metric values are stored in the
/// lower 60 bits (bits `0..60`) and the CVSS version is stored in the
/// upper 4 bits (bits `60..64`):
///
/// | Bit Range | Description    |
/// | --------- | -------------- |
/// | `0..60`   | Metric values. |
/// | `60..64`  | CVSS version.  |
///
/// The metric value encoding method is version-specific.  See the
/// version-specific vector representations for more information:
///
/// - [`v2::Vector`]
/// - [`v3::Vector`]
/// - [`v4::Vector`]
///
/// [cvss]: https://www.first.org/cvss/
///   "Common Vulnerability Scoring System (CVSS)"
/// [v2]: https://www.first.org/cvss/v2/guide
///   "CVSS v2.0 Documentation"
/// [v3]: https://www.first.org/cvss/v3-1/specification-document
///   "CVSS v3.1 Specification"
/// [v4]: https://www.first.org/cvss/v4-0/specification-document
///   "CVSS v4.0 Specification"
/// [bit-field]: https://en.wikipedia.org/wiki/Bit_field
///   "Bit field (Wikipedia)"
/// [vector-string]: https://www.first.org/cvss/v4-0/specification-document#Vector-String
///   "CVSS v4.0 Specification, Section 7: Vector String"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Vector(u64);

impl Vector {
  /// Get [`Metric`] from [`Vector`] by [`Name`].
  ///
  /// Returns [`Err::UnknownName`] if there is a mismatch between the
  /// version of the vector and the version of the given [`Name`].
  ///
  /// # Example
  ///
  /// Get metric from vector by name:
  ///
  /// ```
  /// # use polycvss::{Err, Vector, Metric, Name, v4};
  /// # fn main() -> Result<(), Err> {
  /// // parse CVSS v4 vector string
  /// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
  ///
  /// // get metric
  /// let metric = v.get(Name::V4(v4::Name::AttackVector))?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Network)));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Example of error when there is a mismatch between the version of
  /// the vector and the version of the given [`Name`]:
  ///
  /// ```
  /// # use polycvss::{Err, Vector, Metric, Name, v4};
  /// # fn main() -> Result<(), Err> {
  /// // parse CVSS v3 vector string
  /// let v: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
  ///
  /// // try to get v4 metric from v3 vector
  /// let got = v.get(Name::V4(v4::Name::AttackVector));
  ///
  /// // check result
  /// assert_eq!(got, Err(Err::UnknownName));
  /// # Ok(())
  /// # }
  /// ```
  ///
  pub fn get(self, name: Name) -> Result<Metric, Err> {
    match (MajorVersion::from(self), name) {
      (MajorVersion::V2, Name::V2(name)) => Ok(Metric::V2(v2::Vector::from(self).get(name))),
      (MajorVersion::V3, Name::V3(name)) => Ok(Metric::V3(v3::Vector::from(self).get(name))),
      (MajorVersion::V4, Name::V4(name)) => Ok(Metric::V4(v4::Vector::from(self).get(name))),
      _ => Err(Err::UnknownName),
    }
  }

  /// Get [`Vector`] base score.
  ///
  /// For [CVSS v2][v2] and [CVSS v3][v3] vectors this method returns the
  /// base score, excluding the effect of temporal and environmental
  /// metrics.
  ///
  /// For [CVSS v4][v4] vectors this method returns the score.
  ///
  /// # Example
  ///
  /// Get base score for several vector strings:
  ///
  /// ```
  /// # use polycvss::{Err, Score, Vector};
  /// # fn main() -> Result<(), Err> {
  /// // parse CVSS v2 vector string, get base score
  /// let v2: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
  /// assert_eq!(v2.base_score(), Score::from(10.0));
  ///
  /// // parse CVSS v3 vector string, get base score
  /// let v3: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
  /// assert_eq!(v3.base_score(), Score::from(9.8));
  ///
  /// // parse CVSS v4 vector string, get base score
  /// let v4: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
  /// assert_eq!(v4.base_score(), Score::from(10.0));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// [v2]: https://www.first.org/cvss/v2/guide
  ///   "CVSS v2.0 Documentation"
  /// [v3]: https://www.first.org/cvss/v3-1/specification-document
  ///   "CVSS v3.1 Specification"
  /// [v4]: https://www.first.org/cvss/v4-0/specification-document
  ///   "CVSS v4.0 Specification"
  pub fn base_score(&self) -> Score {
    match MajorVersion::from(*self) {
      MajorVersion::V2 => v2::Scores::from(v2::Vector::from(*self)).base,
      MajorVersion::V3 => v3::Scores::from(v3::Vector::from(*self)).base,
      MajorVersion::V4 => Score::from(v4::Vector::from(*self)),
    }
  }
}

// TODO
// impl std::ops::Index<Name> for Vector {
//   type Output = Metric;
//
//   fn index(&self, name: Name) -> Self::Output {
//     match self.get(name) {
//       Ok(metric) => metric,
//       _ => panic!("unknown name"),
//     }
//   }
// }

impl IntoIterator for Vector {
  type Item = Metric;
  type IntoIter = VectorIterator;

  // Create iterator from vector.
  fn into_iter(self) -> Self::IntoIter {
    match MajorVersion::from(self) {
      MajorVersion::V2 => Self::IntoIter::V2(v2::Vector::from(self).into_iter()),
      MajorVersion::V3 => Self::IntoIter::V3(v3::Vector::from(self).into_iter()),
      MajorVersion::V4 => Self::IntoIter::V4(v4::Vector::from(self).into_iter()),
    }
  }
}

impl std::str::FromStr for Vector {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    // check string length
    if s.len() < 9 {
      return Err(Err::Len);
    }

    // check string prefix
    Ok(Vector(match &s[0..9] {
      "CVSS:4.0/" => u64::from(v4::Vector::from_str(s)?),
      "CVSS:3.0/" | "CVSS:3.1/" => u64::from(v3::Vector::from_str(s)?),
      _ => u64::from(v2::Vector::from_str(s)?),
    }))
  }
}

impl TryFrom<String> for Vector {
  type Error = Err;

  fn try_from(s: String) -> Result<Self, Self::Error> {
    s.parse::<Vector>()
  }
}

impl From<Vector> for Score {
  fn from(vec: Vector) -> Score {
    match MajorVersion::from(vec) {
      MajorVersion::V2 => Score::from(v2::Vector::from(vec)),
      MajorVersion::V3 => Score::from(v3::Vector::from(vec)),
      MajorVersion::V4 => Score::from(v4::Vector::from(vec)),
    }
  }
}

impl std::fmt::Display for Vector {
  // Format CVSSv4.0 vector as a string.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    match MajorVersion::from(*self) {
      MajorVersion::V2 => v2::Vector::fmt(&v2::Vector::from(*self), f),
      MajorVersion::V3 => v3::Vector::fmt(&v3::Vector::from(*self), f),
      MajorVersion::V4 => v4::Vector::fmt(&v4::Vector::from(*self), f),
    }
  }
}

/// [CVSS][] score.
///
/// Value in the range `[0.0, 10.0]`.
///
/// Represented internally as a [`u8`].
///
/// # Examples
///
/// Create [`Score`] from [`f32`]:
///
/// ```
/// # use polycvss::Score;
/// # fn main() {
/// // create score from f32
/// let score = Score::from(9.6_f32);
///
/// // check result
/// assert_eq!(score.to_string(), "9.6");
/// # }
/// ```
///
/// Create [`Score`] from [`f64`]:
///
/// ```
/// # use polycvss::Score;
/// # fn main() {
/// // create score from f64
/// let score = Score::from(8.7_f64);
///
/// // check result
/// assert_eq!(score.to_string(), "8.7");
/// # }
/// ```
///
/// Convert [`Score`] to [`f32`]:
///
/// ```
/// # use polycvss::Score;
/// # fn main() {
/// assert_eq!(f32::from(Score::from(5.2)), 5.2_f32);
/// # }
/// ```
///
/// Convert [`Score`] to [`f64`]:
///
/// ```
/// # use polycvss::Score;
/// # fn main() {
/// assert_eq!(f64::from(Score::from(6.3)), 6.3_f64);
/// # }
/// ```
///
/// Convert [`Score`] to [`String`]:
///
/// ```
/// # use polycvss::Score;
/// # fn main() {
/// assert_eq!(Score::from(7.4).to_string(), "7.4");
/// # }
/// ```
///
/// Show that a [`Score`] is 1 byte in size:
///
/// ```
/// # use polycvss::Score;
/// # fn main() {
/// assert_eq!(size_of::<Score>(), size_of::<u8>()); // 1 byte
/// # }
/// ```
///
/// [cvss]: https://www.first.org/cvss/
///   "Common Vulnerability Scoring System (CVSS)"
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub struct Score(u8);

impl From<f32> for Score {
  fn from(val: f32) -> Score {
    Score((val * 10.0).round() as u8)
  }
}

impl From<f64> for Score {
  fn from(val: f64) -> Score {
    Score((val * 10.0).round() as u8)
  }
}

impl From<Score> for f32 {
  fn from(score: Score) -> f32 {
    (score.0 as f32) / 10.0
  }
}

impl From<Score> for f64 {
  fn from(score: Score) -> f64 {
    (score.0 as f64) / 10.0
  }
}

impl std::fmt::Display for Score {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{:1.1}", f32::from(*self))
  }
}

impl std::ops::Add for Score {
  type Output = Self;
  fn add(self, other: Self) -> Self {
    Self(self.0 + other.0).clamp(Self(0), Self(100))
  }
}

impl std::ops::Sub for Score {
  type Output = Self;
  fn sub(self, other: Self) -> Self {
    Self(self.0 - other.0).clamp(Self(0), Self(100))
  }
}

/// Qualitative severity rating.
///
/// | Severity | Score Range |
/// | -------- | ----------- |
/// | None     | 0.0         |
/// | Low      | 0.1 - 3.9   |
/// | Medium   | 4.0 - 6.9   |
/// | High     | 7.0 - 8.9   |
/// | Critical | 9.0 - 10.0  |
///
/// # References
///
/// - [CVSS v3.1 Specification, Section 5: Qualitative Severity Rating Scale][doc-v3]
/// - [CVSS v4.0 Specification, Section 6: Qualitative Severity Rating Scale][doc-v4]
///
/// # Examples
///
/// Create [`Severity`] from [`Score`]:
///
/// ```
/// # use polycvss::{Score, Severity};
/// # fn main() {
/// // create severity from score
/// let severity = Severity::from(Score::from(8.7));
///
/// // check result
/// assert_eq!(severity, Severity::High);
/// # }
/// ```
///
/// Create [`Severity`] from [`String`]:
///
/// ```
/// # use polycvss::{Err, Severity};
/// # fn main() -> Result<(), Err> {
/// // create severity from string
/// let severity: Severity = "MEDIUM".parse()?;
///
/// // check result
/// assert_eq!(severity, Severity::Medium);
/// # Ok(())
/// # }
/// ```
///
/// Compare severities:
///
/// ```
/// # use polycvss::{Err, Severity};
/// # fn main() -> Result<(), Err> {
/// let a = Severity::Low;
/// let b = Severity::High;
///
/// // compare severities
/// assert!(a < b);
/// # Ok(())
/// # }
/// ```
///
/// [doc-v3]: https://www.first.org/cvss/v3-1/specification-document#Qualitative-Severity-Rating-Scale
///   "CVSS v3.1 Specification, Section 5: Qualitative Severity Rating Scale"
/// [doc-v4]: https://www.first.org/cvss/v4-0/specification-document#Qualitative-Severity-Rating-Scale
///   "CVSS v4.0 Specification, Section 6: Qualitative Severity Rating Scale"
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
#[repr(u8)]
pub enum Severity {
  /// None.  Score = `0.0`.
  None,

  /// Low.  Score in range `[0.1, 3.9]`.
  Low,

  /// Medium.  Score in range `[4.0, 6.9]`.
  Medium,

  /// High.  Score in range `[7.0, 8.9]`.
  High,

  /// Critical. Score in range `[9.0, 10.0]`.
  Critical,
}

impl From<Score> for Severity {
  fn from(score: Score) -> Severity {
    match score.0 {
      0 => Severity::None,
      1..40 => Severity::Low,
      40..70 => Severity::Medium,
      70..90 => Severity::High,
      _ => Severity::Critical,
    }
  }
}

impl std::str::FromStr for Severity {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "NONE" => Ok(Severity::None),
      "LOW" => Ok(Severity::Low),
      "MEDIUM" => Ok(Severity::Medium),
      "HIGH" => Ok(Severity::High),
      "CRITICAL" => Ok(Severity::Critical),
      _ => Err(Err::UnknownSeverity),
    }
  }
}

impl std::fmt::Display for Severity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{}", match self {
      Severity::None => "NONE",
      Severity::Low => "LOW",
      Severity::Medium => "MEDIUM",
      Severity::High => "HIGH",
      Severity::Critical => "CRITICAL",
    })
  }
}

#[cfg(test)]
mod tests {
  mod version {
    use super::super::{Err, Version};

    #[test]
    fn test_from_str_fail() {
      let tests = vec!(
        "",
        "asdf",
        "1.0",
      );

      for t in tests {
        assert_eq!(t.parse::<Version>(), Err(Err::UnknownVersion), "{t}");
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        ("2.0", Version::V20),
        ("2.1", Version::V21),
        ("2.2", Version::V22),
        ("2.3", Version::V23),
        ("3.0", Version::V30),
        ("3.1", Version::V31),
        ("4.0", Version::V40),
      );

      for (s, exp) in tests {
        assert_eq!(s.parse::<Version>(), Ok(exp), "{s}");
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Version::V20, "2.0"),
        (Version::V21, "2.1"),
        (Version::V22, "2.2"),
        (Version::V23, "2.3"),
        (Version::V30, "3.0"),
        (Version::V31, "3.1"),
        (Version::V40, "4.0"),
      );

      for (v, exp) in tests {
        assert_eq!(v.to_string(), exp, "{exp}");
      }
    }

    #[test]
    fn test_try_from_u64_fail() {
      for t in 7..16 {
        assert_eq!(Version::try_from(t << 60), Err(Err::UnknownVersion), "{t}");
      }
    }

    #[test]
    fn test_try_from_u64_pass() {
      for t in 0..7 {
        Version::try_from(t << 60).expect(&t.to_string());
      }
    }
  }

  mod name {
    use super::super::{Name, v2, v3, v4};

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Name::V2(v2::Name::AccessVector), "AV"),
        (Name::V2(v2::Name::AccessComplexity), "AC"),
        (Name::V2(v2::Name::Authentication), "Au"),
        (Name::V2(v2::Name::Confidentiality), "C"),
        (Name::V2(v2::Name::Integrity), "I"),
        (Name::V2(v2::Name::Availability), "A"),
        (Name::V2(v2::Name::Exploitability), "E"),
        (Name::V2(v2::Name::RemediationLevel), "RL"),
        (Name::V2(v2::Name::ReportConfidence), "RC"),
        (Name::V2(v2::Name::CollateralDamagePotential), "CDP"),
        (Name::V2(v2::Name::TargetDistribution), "TD"),
        (Name::V2(v2::Name::ConfidentialityRequirement), "CR"),
        (Name::V2(v2::Name::IntegrityRequirement), "IR"),
        (Name::V2(v2::Name::AvailabilityRequirement), "AR"),

        (Name::V3(v3::Name::AttackVector), "AV"),
        (Name::V3(v3::Name::AttackComplexity), "AC"),
        (Name::V3(v3::Name::PrivilegesRequired), "PR"),
        (Name::V3(v3::Name::UserInteraction), "UI"),
        (Name::V3(v3::Name::Scope), "S"),
        (Name::V3(v3::Name::Confidentiality), "C"),
        (Name::V3(v3::Name::Integrity), "I"),
        (Name::V3(v3::Name::Availability), "A"),
        (Name::V3(v3::Name::ExploitCodeMaturity), "E"),
        (Name::V3(v3::Name::RemediationLevel), "RL"),
        (Name::V3(v3::Name::ReportConfidence), "RC"),
        (Name::V3(v3::Name::ConfidentialityRequirement), "CR"),
        (Name::V3(v3::Name::IntegrityRequirement), "IR"),
        (Name::V3(v3::Name::AvailabilityRequirement), "AR"),
        (Name::V3(v3::Name::ModifiedAttackVector), "MAV"),
        (Name::V3(v3::Name::ModifiedAttackComplexity), "MAC"),
        (Name::V3(v3::Name::ModifiedPrivilegesRequired), "MPR"),
        (Name::V3(v3::Name::ModifiedUserInteraction), "MUI"),
        (Name::V3(v3::Name::ModifiedScope), "MS"),
        (Name::V3(v3::Name::ModifiedConfidentiality), "MC"),
        (Name::V3(v3::Name::ModifiedIntegrity), "MI"),
        (Name::V3(v3::Name::ModifiedAvailability), "MA"),

        (Name::V4(v4::Name::AttackVector), "AV"),
        (Name::V4(v4::Name::AttackComplexity), "AC"),
        (Name::V4(v4::Name::AttackRequirements), "AT"),
        (Name::V4(v4::Name::PrivilegesRequired), "PR"),
        (Name::V4(v4::Name::UserInteraction), "UI"),
        (Name::V4(v4::Name::VulnerableSystemConfidentialityImpact), "VC"),
        (Name::V4(v4::Name::VulnerableSystemIntegrityImpact), "VI"),
        (Name::V4(v4::Name::VulnerableSystemAvailabilityImpact), "VA"),
        (Name::V4(v4::Name::SubsequentSystemConfidentialityImpact), "SC"),
        (Name::V4(v4::Name::SubsequentSystemIntegrityImpact), "SI"),
        (Name::V4(v4::Name::SubsequentSystemAvailabilityImpact), "SA"),
        (Name::V4(v4::Name::ExploitMaturity), "E"),
        (Name::V4(v4::Name::ConfidentialityRequirement), "CR"),
        (Name::V4(v4::Name::IntegrityRequirement), "IR"),
        (Name::V4(v4::Name::AvailabilityRequirement), "AR"),
        (Name::V4(v4::Name::ModifiedAttackVector), "MAV"),
        (Name::V4(v4::Name::ModifiedAttackComplexity), "MAC"),
        (Name::V4(v4::Name::ModifiedAttackRequirements), "MAT"),
        (Name::V4(v4::Name::ModifiedPrivilegesRequired), "MPR"),
        (Name::V4(v4::Name::ModifiedUserInteraction), "MUI"),
        (Name::V4(v4::Name::ModifiedVulnerableSystemConfidentiality), "MVC"),
        (Name::V4(v4::Name::ModifiedVulnerableSystemIntegrity), "MVI"),
        (Name::V4(v4::Name::ModifiedVulnerableSystemAvailability), "MVA"),
        (Name::V4(v4::Name::ModifiedSubsequentSystemConfidentiality), "MSC"),
        (Name::V4(v4::Name::ModifiedSubsequentSystemIntegrity), "MSI"),
        (Name::V4(v4::Name::ModifiedSubsequentSystemAvailability), "MSA"),
        (Name::V4(v4::Name::Safety), "S"),
        (Name::V4(v4::Name::Automatable), "AU"),
        (Name::V4(v4::Name::Recovery), "R"),
        (Name::V4(v4::Name::ValueDensity), "V"),
        (Name::V4(v4::Name::VulnerabilityResponseEffort), "RE"),
        (Name::V4(v4::Name::ProviderUrgency), "U"),
      );

      for (name, exp) in tests {
        assert_eq!(name.to_string(), exp, "{exp}");
      }
    }
  }

  mod metric {
    use super::super::{Metric, v2, v3, v4};

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Metric::V2(v2::Metric::AccessVector(v2::AccessVector::Local)), "AV:L"),
        (Metric::V2(v2::Metric::AccessVector(v2::AccessVector::AdjacentNetwork)), "AV:A"),
        (Metric::V2(v2::Metric::AccessVector(v2::AccessVector::Network)), "AV:N"),

        (Metric::V2(v2::Metric::AccessComplexity(v2::AccessComplexity::High)), "AC:H"),
        (Metric::V2(v2::Metric::AccessComplexity(v2::AccessComplexity::Medium)), "AC:M"),
        (Metric::V2(v2::Metric::AccessComplexity(v2::AccessComplexity::Low)), "AC:L"),

        (Metric::V2(v2::Metric::Authentication(v2::Authentication::Multiple)), "Au:M"),
        (Metric::V2(v2::Metric::Authentication(v2::Authentication::Single)), "Au:S"),
        (Metric::V2(v2::Metric::Authentication(v2::Authentication::None)), "Au:N"),

        (Metric::V2(v2::Metric::Confidentiality(v2::Impact::None)), "C:N"),
        (Metric::V2(v2::Metric::Confidentiality(v2::Impact::Partial)), "C:P"),
        (Metric::V2(v2::Metric::Confidentiality(v2::Impact::Complete)), "C:C"),

        (Metric::V2(v2::Metric::Integrity(v2::Impact::None)), "I:N"),
        (Metric::V2(v2::Metric::Integrity(v2::Impact::Partial)), "I:P"),
        (Metric::V2(v2::Metric::Integrity(v2::Impact::Complete)), "I:C"),

        (Metric::V2(v2::Metric::Availability(v2::Impact::None)), "A:N"),
        (Metric::V2(v2::Metric::Availability(v2::Impact::Partial)), "A:P"),
        (Metric::V2(v2::Metric::Availability(v2::Impact::Complete)), "A:C"),

        (Metric::V2(v2::Metric::Exploitability(v2::Exploitability::NotDefined)), "E:ND"),
        (Metric::V2(v2::Metric::Exploitability(v2::Exploitability::Unproven)), "E:U"),
        (Metric::V2(v2::Metric::Exploitability(v2::Exploitability::ProofOfConcept)), "E:POC"),
        (Metric::V2(v2::Metric::Exploitability(v2::Exploitability::Functional)), "E:F"),
        (Metric::V2(v2::Metric::Exploitability(v2::Exploitability::High)), "E:H"),

        (Metric::V2(v2::Metric::RemediationLevel(v2::RemediationLevel::NotDefined)), "RL:ND"),
        (Metric::V2(v2::Metric::RemediationLevel(v2::RemediationLevel::OfficialFix)), "RL:OF"),
        (Metric::V2(v2::Metric::RemediationLevel(v2::RemediationLevel::TemporaryFix)), "RL:TF"),
        (Metric::V2(v2::Metric::RemediationLevel(v2::RemediationLevel::Workaround)), "RL:W"),
        (Metric::V2(v2::Metric::RemediationLevel(v2::RemediationLevel::Unavailable)), "RL:U"),

        (Metric::V2(v2::Metric::ReportConfidence(v2::ReportConfidence::NotDefined)), "RC:ND"),
        (Metric::V2(v2::Metric::ReportConfidence(v2::ReportConfidence::Unconfirmed)), "RC:UC"),
        (Metric::V2(v2::Metric::ReportConfidence(v2::ReportConfidence::Uncorroborated)), "RC:UR"),
        (Metric::V2(v2::Metric::ReportConfidence(v2::ReportConfidence::Confirmed)), "RC:C"),

        (Metric::V2(v2::Metric::CollateralDamagePotential(v2::CollateralDamagePotential::NotDefined)), "CDP:ND"),
        (Metric::V2(v2::Metric::CollateralDamagePotential(v2::CollateralDamagePotential::None)), "CDP:N"),
        (Metric::V2(v2::Metric::CollateralDamagePotential(v2::CollateralDamagePotential::Low)), "CDP:L"),
        (Metric::V2(v2::Metric::CollateralDamagePotential(v2::CollateralDamagePotential::LowMedium)), "CDP:LM"),
        (Metric::V2(v2::Metric::CollateralDamagePotential(v2::CollateralDamagePotential::MediumHigh)), "CDP:MH"),
        (Metric::V2(v2::Metric::CollateralDamagePotential(v2::CollateralDamagePotential::High)), "CDP:H"),

        (Metric::V2(v2::Metric::TargetDistribution(v2::TargetDistribution::NotDefined)), "TD:ND"),
        (Metric::V2(v2::Metric::TargetDistribution(v2::TargetDistribution::None)), "TD:N"),
        (Metric::V2(v2::Metric::TargetDistribution(v2::TargetDistribution::Low)), "TD:L"),
        (Metric::V2(v2::Metric::TargetDistribution(v2::TargetDistribution::Medium)), "TD:M"),
        (Metric::V2(v2::Metric::TargetDistribution(v2::TargetDistribution::High)), "TD:H"),

        (Metric::V2(v2::Metric::ConfidentialityRequirement(v2::Requirement::NotDefined)), "CR:ND"),
        (Metric::V2(v2::Metric::ConfidentialityRequirement(v2::Requirement::Low)), "CR:L"),
        (Metric::V2(v2::Metric::ConfidentialityRequirement(v2::Requirement::Medium)), "CR:M"),
        (Metric::V2(v2::Metric::ConfidentialityRequirement(v2::Requirement::High)), "CR:H"),

        (Metric::V2(v2::Metric::IntegrityRequirement(v2::Requirement::NotDefined)), "IR:ND"),
        (Metric::V2(v2::Metric::IntegrityRequirement(v2::Requirement::Low)), "IR:L"),
        (Metric::V2(v2::Metric::IntegrityRequirement(v2::Requirement::Medium)), "IR:M"),
        (Metric::V2(v2::Metric::IntegrityRequirement(v2::Requirement::High)), "IR:H"),

        (Metric::V2(v2::Metric::AvailabilityRequirement(v2::Requirement::NotDefined)), "AR:ND"),
        (Metric::V2(v2::Metric::AvailabilityRequirement(v2::Requirement::Low)), "AR:L"),
        (Metric::V2(v2::Metric::AvailabilityRequirement(v2::Requirement::Medium)), "AR:M"),
        (Metric::V2(v2::Metric::AvailabilityRequirement(v2::Requirement::High)), "AR:H"),

        (Metric::V3(v3::Metric::AttackVector(v3::AttackVector::Network)), "AV:N"),
        (Metric::V3(v3::Metric::AttackVector(v3::AttackVector::Adjacent)), "AV:A"),
        (Metric::V3(v3::Metric::AttackVector(v3::AttackVector::Local)), "AV:L"),
        (Metric::V3(v3::Metric::AttackVector(v3::AttackVector::Physical)), "AV:P"),

        (Metric::V3(v3::Metric::AttackComplexity(v3::AttackComplexity::High)), "AC:H"),
        (Metric::V3(v3::Metric::AttackComplexity(v3::AttackComplexity::Low)), "AC:L"),

        (Metric::V3(v3::Metric::PrivilegesRequired(v3::PrivilegesRequired::High)), "PR:H"),
        (Metric::V3(v3::Metric::PrivilegesRequired(v3::PrivilegesRequired::Low)), "PR:L"),
        (Metric::V3(v3::Metric::PrivilegesRequired(v3::PrivilegesRequired::None)), "PR:N"),

        (Metric::V3(v3::Metric::UserInteraction(v3::UserInteraction::None)), "UI:N"),
        (Metric::V3(v3::Metric::UserInteraction(v3::UserInteraction::Required)), "UI:R"),

        (Metric::V3(v3::Metric::Scope(v3::Scope::Unchanged)), "S:U"),
        (Metric::V3(v3::Metric::Scope(v3::Scope::Changed)), "S:C"),

        (Metric::V3(v3::Metric::Confidentiality(v3::Impact::None)), "C:N"),
        (Metric::V3(v3::Metric::Confidentiality(v3::Impact::Low)), "C:L"),
        (Metric::V3(v3::Metric::Confidentiality(v3::Impact::High)), "C:H"),

        (Metric::V3(v3::Metric::Integrity(v3::Impact::None)), "I:N"),
        (Metric::V3(v3::Metric::Integrity(v3::Impact::Low)), "I:L"),
        (Metric::V3(v3::Metric::Integrity(v3::Impact::High)), "I:H"),

        (Metric::V3(v3::Metric::Availability(v3::Impact::None)), "A:N"),
        (Metric::V3(v3::Metric::Availability(v3::Impact::Low)), "A:L"),
        (Metric::V3(v3::Metric::Availability(v3::Impact::High)), "A:H"),

        (Metric::V3(v3::Metric::ExploitCodeMaturity(v3::ExploitCodeMaturity::Unproven)), "E:U"),
        (Metric::V3(v3::Metric::ExploitCodeMaturity(v3::ExploitCodeMaturity::ProofOfConcept)), "E:P"),
        (Metric::V3(v3::Metric::ExploitCodeMaturity(v3::ExploitCodeMaturity::Functional)), "E:F"),
        (Metric::V3(v3::Metric::ExploitCodeMaturity(v3::ExploitCodeMaturity::High)), "E:H"),
        (Metric::V3(v3::Metric::ExploitCodeMaturity(v3::ExploitCodeMaturity::NotDefined)), "E:X"),

        (Metric::V3(v3::Metric::RemediationLevel(v3::RemediationLevel::OfficialFix)), "RL:O"),
        (Metric::V3(v3::Metric::RemediationLevel(v3::RemediationLevel::TemporaryFix)), "RL:T"),
        (Metric::V3(v3::Metric::RemediationLevel(v3::RemediationLevel::Workaround)), "RL:W"),
        (Metric::V3(v3::Metric::RemediationLevel(v3::RemediationLevel::Unavailable)), "RL:U"),
        (Metric::V3(v3::Metric::RemediationLevel(v3::RemediationLevel::NotDefined)), "RL:X"),

        (Metric::V3(v3::Metric::ReportConfidence(v3::ReportConfidence::Unknown)), "RC:U"),
        (Metric::V3(v3::Metric::ReportConfidence(v3::ReportConfidence::Reasonable)), "RC:R"),
        (Metric::V3(v3::Metric::ReportConfidence(v3::ReportConfidence::Confirmed)), "RC:C"),
        (Metric::V3(v3::Metric::ReportConfidence(v3::ReportConfidence::NotDefined)), "RC:X"),

        (Metric::V3(v3::Metric::ConfidentialityRequirement(v3::Requirement::Low)), "CR:L"),
        (Metric::V3(v3::Metric::ConfidentialityRequirement(v3::Requirement::Medium)), "CR:M"),
        (Metric::V3(v3::Metric::ConfidentialityRequirement(v3::Requirement::High)), "CR:H"),
        (Metric::V3(v3::Metric::ConfidentialityRequirement(v3::Requirement::NotDefined)), "CR:X"),

        (Metric::V3(v3::Metric::IntegrityRequirement(v3::Requirement::Low)), "IR:L"),
        (Metric::V3(v3::Metric::IntegrityRequirement(v3::Requirement::Medium)), "IR:M"),
        (Metric::V3(v3::Metric::IntegrityRequirement(v3::Requirement::High)), "IR:H"),
        (Metric::V3(v3::Metric::IntegrityRequirement(v3::Requirement::NotDefined)), "IR:X"),

        (Metric::V3(v3::Metric::AvailabilityRequirement(v3::Requirement::Low)), "AR:L"),
        (Metric::V3(v3::Metric::AvailabilityRequirement(v3::Requirement::Medium)), "AR:M"),
        (Metric::V3(v3::Metric::AvailabilityRequirement(v3::Requirement::High)), "AR:H"),
        (Metric::V3(v3::Metric::AvailabilityRequirement(v3::Requirement::NotDefined)), "AR:X"),

        (Metric::V3(v3::Metric::ModifiedAttackVector(v3::ModifiedAttackVector::Network)), "MAV:N"),
        (Metric::V3(v3::Metric::ModifiedAttackVector(v3::ModifiedAttackVector::Adjacent)), "MAV:A"),
        (Metric::V3(v3::Metric::ModifiedAttackVector(v3::ModifiedAttackVector::Local)), "MAV:L"),
        (Metric::V3(v3::Metric::ModifiedAttackVector(v3::ModifiedAttackVector::Physical)), "MAV:P"),
        (Metric::V3(v3::Metric::ModifiedAttackVector(v3::ModifiedAttackVector::NotDefined)), "MAV:X"),

        (Metric::V3(v3::Metric::ModifiedAttackComplexity(v3::ModifiedAttackComplexity::High)), "MAC:H"),
        (Metric::V3(v3::Metric::ModifiedAttackComplexity(v3::ModifiedAttackComplexity::Low)), "MAC:L"),
        (Metric::V3(v3::Metric::ModifiedAttackComplexity(v3::ModifiedAttackComplexity::NotDefined)), "MAC:X"),

        (Metric::V3(v3::Metric::ModifiedPrivilegesRequired(v3::ModifiedPrivilegesRequired::High)), "MPR:H"),
        (Metric::V3(v3::Metric::ModifiedPrivilegesRequired(v3::ModifiedPrivilegesRequired::Low)), "MPR:L"),
        (Metric::V3(v3::Metric::ModifiedPrivilegesRequired(v3::ModifiedPrivilegesRequired::None)), "MPR:N"),
        (Metric::V3(v3::Metric::ModifiedPrivilegesRequired(v3::ModifiedPrivilegesRequired::NotDefined)), "MPR:X"),

        (Metric::V3(v3::Metric::ModifiedUserInteraction(v3::ModifiedUserInteraction::None)), "MUI:N"),
        (Metric::V3(v3::Metric::ModifiedUserInteraction(v3::ModifiedUserInteraction::Required)), "MUI:R"),
        (Metric::V3(v3::Metric::ModifiedUserInteraction(v3::ModifiedUserInteraction::NotDefined)), "MUI:X"),

        (Metric::V3(v3::Metric::ModifiedScope(v3::ModifiedScope::Unchanged)), "MS:U"),
        (Metric::V3(v3::Metric::ModifiedScope(v3::ModifiedScope::Changed)), "MS:C"),
        (Metric::V3(v3::Metric::ModifiedScope(v3::ModifiedScope::NotDefined)), "MS:X"),

        (Metric::V3(v3::Metric::ModifiedConfidentiality(v3::ModifiedImpact::None)), "MC:N"),
        (Metric::V3(v3::Metric::ModifiedConfidentiality(v3::ModifiedImpact::Low)), "MC:L"),
        (Metric::V3(v3::Metric::ModifiedConfidentiality(v3::ModifiedImpact::High)), "MC:H"),
        (Metric::V3(v3::Metric::ModifiedConfidentiality(v3::ModifiedImpact::NotDefined)), "MC:X"),

        (Metric::V3(v3::Metric::ModifiedIntegrity(v3::ModifiedImpact::None)), "MI:N"),
        (Metric::V3(v3::Metric::ModifiedIntegrity(v3::ModifiedImpact::Low)), "MI:L"),
        (Metric::V3(v3::Metric::ModifiedIntegrity(v3::ModifiedImpact::High)), "MI:H"),
        (Metric::V3(v3::Metric::ModifiedIntegrity(v3::ModifiedImpact::NotDefined)), "MI:X"),

        (Metric::V3(v3::Metric::ModifiedAvailability(v3::ModifiedImpact::None)), "MA:N"),
        (Metric::V3(v3::Metric::ModifiedAvailability(v3::ModifiedImpact::Low)), "MA:L"),
        (Metric::V3(v3::Metric::ModifiedAvailability(v3::ModifiedImpact::High)), "MA:H"),
        (Metric::V3(v3::Metric::ModifiedAvailability(v3::ModifiedImpact::NotDefined)), "MA:X"),


        (Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Network)), "AV:N"),
        (Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Adjacent)), "AV:A"),
        (Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Local)), "AV:L"),
        (Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Physical)), "AV:P"),

        (Metric::V4(v4::Metric::AttackComplexity(v4::AttackComplexity::Low)), "AC:L"),
        (Metric::V4(v4::Metric::AttackComplexity(v4::AttackComplexity::High)), "AC:H"),

        (Metric::V4(v4::Metric::AttackRequirements(v4::AttackRequirements::None)), "AT:N"),
        (Metric::V4(v4::Metric::AttackRequirements(v4::AttackRequirements::Present)), "AT:P"),

        (Metric::V4(v4::Metric::PrivilegesRequired(v4::PrivilegesRequired::None)), "PR:N"),
        (Metric::V4(v4::Metric::PrivilegesRequired(v4::PrivilegesRequired::Low)), "PR:L"),
        (Metric::V4(v4::Metric::PrivilegesRequired(v4::PrivilegesRequired::High)), "PR:H"),

        (Metric::V4(v4::Metric::UserInteraction(v4::UserInteraction::None)), "UI:N"),
        (Metric::V4(v4::Metric::UserInteraction(v4::UserInteraction::Passive)), "UI:P"),
        (Metric::V4(v4::Metric::UserInteraction(v4::UserInteraction::Active)), "UI:A"),

        (Metric::V4(v4::Metric::VulnerableSystemConfidentialityImpact(v4::Impact::High)), "VC:H"),
        (Metric::V4(v4::Metric::VulnerableSystemConfidentialityImpact(v4::Impact::Low)), "VC:L"),
        (Metric::V4(v4::Metric::VulnerableSystemConfidentialityImpact(v4::Impact::None)), "VC:N"),

        (Metric::V4(v4::Metric::VulnerableSystemIntegrityImpact(v4::Impact::High)), "VI:H"),
        (Metric::V4(v4::Metric::VulnerableSystemIntegrityImpact(v4::Impact::Low)), "VI:L"),
        (Metric::V4(v4::Metric::VulnerableSystemIntegrityImpact(v4::Impact::None)), "VI:N"),

        (Metric::V4(v4::Metric::VulnerableSystemAvailabilityImpact(v4::Impact::High)), "VA:H"),
        (Metric::V4(v4::Metric::VulnerableSystemAvailabilityImpact(v4::Impact::Low)), "VA:L"),
        (Metric::V4(v4::Metric::VulnerableSystemAvailabilityImpact(v4::Impact::None)), "VA:N"),

        (Metric::V4(v4::Metric::SubsequentSystemConfidentialityImpact(v4::Impact::High)), "SC:H"),
        (Metric::V4(v4::Metric::SubsequentSystemConfidentialityImpact(v4::Impact::Low)), "SC:L"),
        (Metric::V4(v4::Metric::SubsequentSystemConfidentialityImpact(v4::Impact::None)), "SC:N"),

        (Metric::V4(v4::Metric::SubsequentSystemIntegrityImpact(v4::Impact::High)), "SI:H"),
        (Metric::V4(v4::Metric::SubsequentSystemIntegrityImpact(v4::Impact::Low)), "SI:L"),
        (Metric::V4(v4::Metric::SubsequentSystemIntegrityImpact(v4::Impact::None)), "SI:N"),

        (Metric::V4(v4::Metric::SubsequentSystemAvailabilityImpact(v4::Impact::High)), "SA:H"),
        (Metric::V4(v4::Metric::SubsequentSystemAvailabilityImpact(v4::Impact::Low)), "SA:L"),
        (Metric::V4(v4::Metric::SubsequentSystemAvailabilityImpact(v4::Impact::None)), "SA:N"),

        (Metric::V4(v4::Metric::ExploitMaturity(v4::ExploitMaturity::NotDefined)), "E:X"),
        (Metric::V4(v4::Metric::ExploitMaturity(v4::ExploitMaturity::Attacked)), "E:A"),
        (Metric::V4(v4::Metric::ExploitMaturity(v4::ExploitMaturity::ProofOfConcept)), "E:P"),
        (Metric::V4(v4::Metric::ExploitMaturity(v4::ExploitMaturity::Unreported)), "E:U"),

        (Metric::V4(v4::Metric::ConfidentialityRequirement(v4::Requirement::NotDefined)), "CR:X"),
        (Metric::V4(v4::Metric::ConfidentialityRequirement(v4::Requirement::High)), "CR:H"),
        (Metric::V4(v4::Metric::ConfidentialityRequirement(v4::Requirement::Medium)), "CR:M"),
        (Metric::V4(v4::Metric::ConfidentialityRequirement(v4::Requirement::Low)), "CR:L"),

        (Metric::V4(v4::Metric::IntegrityRequirement(v4::Requirement::NotDefined)), "IR:X"),
        (Metric::V4(v4::Metric::IntegrityRequirement(v4::Requirement::High)), "IR:H"),
        (Metric::V4(v4::Metric::IntegrityRequirement(v4::Requirement::Medium)), "IR:M"),
        (Metric::V4(v4::Metric::IntegrityRequirement(v4::Requirement::Low)), "IR:L"),

        (Metric::V4(v4::Metric::AvailabilityRequirement(v4::Requirement::NotDefined)), "AR:X"),
        (Metric::V4(v4::Metric::AvailabilityRequirement(v4::Requirement::High)), "AR:H"),
        (Metric::V4(v4::Metric::AvailabilityRequirement(v4::Requirement::Medium)), "AR:M"),
        (Metric::V4(v4::Metric::AvailabilityRequirement(v4::Requirement::Low)), "AR:L"),

        (Metric::V4(v4::Metric::ModifiedAttackVector(v4::ModifiedAttackVector::NotDefined)), "MAV:X"),
        (Metric::V4(v4::Metric::ModifiedAttackVector(v4::ModifiedAttackVector::Network)), "MAV:N"),
        (Metric::V4(v4::Metric::ModifiedAttackVector(v4::ModifiedAttackVector::Adjacent)), "MAV:A"),
        (Metric::V4(v4::Metric::ModifiedAttackVector(v4::ModifiedAttackVector::Local)), "MAV:L"),
        (Metric::V4(v4::Metric::ModifiedAttackVector(v4::ModifiedAttackVector::Physical)), "MAV:P"),

        (Metric::V4(v4::Metric::ModifiedAttackComplexity(v4::ModifiedAttackComplexity::NotDefined)), "MAC:X"),
        (Metric::V4(v4::Metric::ModifiedAttackComplexity(v4::ModifiedAttackComplexity::Low)), "MAC:L"),
        (Metric::V4(v4::Metric::ModifiedAttackComplexity(v4::ModifiedAttackComplexity::High)), "MAC:H"),

        (Metric::V4(v4::Metric::ModifiedAttackRequirements(v4::ModifiedAttackRequirements::NotDefined)), "MAT:X"),
        (Metric::V4(v4::Metric::ModifiedAttackRequirements(v4::ModifiedAttackRequirements::None)), "MAT:N"),
        (Metric::V4(v4::Metric::ModifiedAttackRequirements(v4::ModifiedAttackRequirements::Present)), "MAT:P"),

        (Metric::V4(v4::Metric::ModifiedPrivilegesRequired(v4::ModifiedPrivilegesRequired::NotDefined)), "MPR:X"),
        (Metric::V4(v4::Metric::ModifiedPrivilegesRequired(v4::ModifiedPrivilegesRequired::None)), "MPR:N"),
        (Metric::V4(v4::Metric::ModifiedPrivilegesRequired(v4::ModifiedPrivilegesRequired::Low)), "MPR:L"),
        (Metric::V4(v4::Metric::ModifiedPrivilegesRequired(v4::ModifiedPrivilegesRequired::High)), "MPR:H"),

        (Metric::V4(v4::Metric::ModifiedUserInteraction(v4::ModifiedUserInteraction::NotDefined)), "MUI:X"),
        (Metric::V4(v4::Metric::ModifiedUserInteraction(v4::ModifiedUserInteraction::None)), "MUI:N"),
        (Metric::V4(v4::Metric::ModifiedUserInteraction(v4::ModifiedUserInteraction::Passive)), "MUI:P"),
        (Metric::V4(v4::Metric::ModifiedUserInteraction(v4::ModifiedUserInteraction::Active)), "MUI:A"),

        (Metric::V4(v4::Metric::ModifiedVulnerableSystemConfidentiality(v4::ModifiedImpact::NotDefined)), "MVC:X"),
        (Metric::V4(v4::Metric::ModifiedVulnerableSystemConfidentiality(v4::ModifiedImpact::High)), "MVC:H"),
        (Metric::V4(v4::Metric::ModifiedVulnerableSystemConfidentiality(v4::ModifiedImpact::Low)), "MVC:L"),
        (Metric::V4(v4::Metric::ModifiedVulnerableSystemConfidentiality(v4::ModifiedImpact::None)), "MVC:N"),

        (Metric::V4(v4::Metric::ModifiedVulnerableSystemIntegrity(v4::ModifiedImpact::NotDefined)), "MVI:X"),
        (Metric::V4(v4::Metric::ModifiedVulnerableSystemIntegrity(v4::ModifiedImpact::High)), "MVI:H"),
        (Metric::V4(v4::Metric::ModifiedVulnerableSystemIntegrity(v4::ModifiedImpact::Low)), "MVI:L"),
        (Metric::V4(v4::Metric::ModifiedVulnerableSystemIntegrity(v4::ModifiedImpact::None)), "MVI:N"),

        (Metric::V4(v4::Metric::ModifiedVulnerableSystemAvailability(v4::ModifiedImpact::NotDefined)), "MVA:X"),
        (Metric::V4(v4::Metric::ModifiedVulnerableSystemAvailability(v4::ModifiedImpact::High)), "MVA:H"),
        (Metric::V4(v4::Metric::ModifiedVulnerableSystemAvailability(v4::ModifiedImpact::Low)), "MVA:L"),
        (Metric::V4(v4::Metric::ModifiedVulnerableSystemAvailability(v4::ModifiedImpact::None)), "MVA:N"),

        (Metric::V4(v4::Metric::ModifiedSubsequentSystemConfidentiality(v4::ModifiedImpact::NotDefined)), "MSC:X"),
        (Metric::V4(v4::Metric::ModifiedSubsequentSystemConfidentiality(v4::ModifiedImpact::High)), "MSC:H"),
        (Metric::V4(v4::Metric::ModifiedSubsequentSystemConfidentiality(v4::ModifiedImpact::Low)), "MSC:L"),
        (Metric::V4(v4::Metric::ModifiedSubsequentSystemConfidentiality(v4::ModifiedImpact::None)), "MSC:N"),

        (Metric::V4(v4::Metric::ModifiedSubsequentSystemIntegrity(v4::ModifiedSubsequentImpact::NotDefined)), "MSI:X"),
        (Metric::V4(v4::Metric::ModifiedSubsequentSystemIntegrity(v4::ModifiedSubsequentImpact::High)), "MSI:H"),
        (Metric::V4(v4::Metric::ModifiedSubsequentSystemIntegrity(v4::ModifiedSubsequentImpact::Low)), "MSI:L"),
        (Metric::V4(v4::Metric::ModifiedSubsequentSystemIntegrity(v4::ModifiedSubsequentImpact::None)), "MSI:N"),
        (Metric::V4(v4::Metric::ModifiedSubsequentSystemIntegrity(v4::ModifiedSubsequentImpact::Safety)), "MSI:S"),

        (Metric::V4(v4::Metric::ModifiedSubsequentSystemAvailability(v4::ModifiedSubsequentImpact::NotDefined)), "MSA:X"),
        (Metric::V4(v4::Metric::ModifiedSubsequentSystemAvailability(v4::ModifiedSubsequentImpact::High)), "MSA:H"),
        (Metric::V4(v4::Metric::ModifiedSubsequentSystemAvailability(v4::ModifiedSubsequentImpact::Low)), "MSA:L"),
        (Metric::V4(v4::Metric::ModifiedSubsequentSystemAvailability(v4::ModifiedSubsequentImpact::None)), "MSA:N"),
        (Metric::V4(v4::Metric::ModifiedSubsequentSystemAvailability(v4::ModifiedSubsequentImpact::Safety)), "MSA:S"),

        (Metric::V4(v4::Metric::Safety(v4::Safety::NotDefined)), "S:X"),
        (Metric::V4(v4::Metric::Safety(v4::Safety::Present)), "S:P"),
        (Metric::V4(v4::Metric::Safety(v4::Safety::Negligible)), "S:N"),

        (Metric::V4(v4::Metric::Automatable(v4::Automatable::NotDefined)), "AU:X"),
        (Metric::V4(v4::Metric::Automatable(v4::Automatable::No)), "AU:N"),
        (Metric::V4(v4::Metric::Automatable(v4::Automatable::Yes)), "AU:Y"),

        (Metric::V4(v4::Metric::Recovery(v4::Recovery::NotDefined)), "R:X"),
        (Metric::V4(v4::Metric::Recovery(v4::Recovery::Automatic)), "R:A"),
        (Metric::V4(v4::Metric::Recovery(v4::Recovery::User)), "R:U"),
        (Metric::V4(v4::Metric::Recovery(v4::Recovery::Irrecoverable)), "R:I"),

        (Metric::V4(v4::Metric::ValueDensity(v4::ValueDensity::NotDefined)), "V:X"),
        (Metric::V4(v4::Metric::ValueDensity(v4::ValueDensity::Diffuse)), "V:D"),
        (Metric::V4(v4::Metric::ValueDensity(v4::ValueDensity::Concentrated)), "V:C"),

        (Metric::V4(v4::Metric::VulnerabilityResponseEffort(v4::VulnerabilityResponseEffort::NotDefined)), "RE:X"),
        (Metric::V4(v4::Metric::VulnerabilityResponseEffort(v4::VulnerabilityResponseEffort::Low)), "RE:L"),
        (Metric::V4(v4::Metric::VulnerabilityResponseEffort(v4::VulnerabilityResponseEffort::Moderate)), "RE:M"),
        (Metric::V4(v4::Metric::VulnerabilityResponseEffort(v4::VulnerabilityResponseEffort::High)), "RE:H"),

        (Metric::V4(v4::Metric::ProviderUrgency(v4::ProviderUrgency::NotDefined)), "U:X"),
        (Metric::V4(v4::Metric::ProviderUrgency(v4::ProviderUrgency::Red)), "U:Red"),
        (Metric::V4(v4::Metric::ProviderUrgency(v4::ProviderUrgency::Amber)), "U:Amber"),
        (Metric::V4(v4::Metric::ProviderUrgency(v4::ProviderUrgency::Green)), "U:Green"),
        (Metric::V4(v4::Metric::ProviderUrgency(v4::ProviderUrgency::Clear)), "U:Clear"),
      );

      for (metric, exp) in tests {
        assert_eq!(metric.to_string(), exp);
      }
    }

    #[test]
    fn test_size() {
      assert_eq!(size_of::<Metric>(), 1 + size_of::<u16>());
    }
  }

  mod vector {
    use super::super::{Err, Name, Metric, Score, Vector, v2, v3, v4};

    #[test]
    fn test_from_str_fail() {
      let tests = vec!(
        ("empty", "", Err::Len),
      );

      for (name, s, exp) in tests {
        assert_eq!(s.parse::<Vector>(), Err(exp), "{name}");
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        "AV:L/AC:L/Au:N/C:C/I:C/A:C", // v2
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // v3
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // v4
      );

      for t in tests {
        t.parse::<Vector>().expect(t);
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (
          "v2-default", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "v2-everything", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H", // exp
        ),

        (
          "v3-default", // name
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "v3-everything", // name
          "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H", // val
          "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H", // exp
        ),

        (
          "v4-default", // name
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // val
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // exp
        ),

        (
          "v4-everything", // name
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

      );

      for (name, s, exp) in tests {
        assert_eq!(s.parse::<Vector>().expect(name).to_string(), exp, "{name}");
      }
    }

    #[test]
    fn test_get() {
      let tests = vec!((
        "v2, base metric", // test name
        "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
        Name::V2(v2::Name::AccessVector), // metric name
        Ok(Metric::V2(v2::Metric::AccessVector(v2::AccessVector::Network))), // exp
      ), (
        "v2, optional metric, not defined", // test name
        "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
        Name::V2(v2::Name::Exploitability), // metric name
        Ok(Metric::V2(v2::Metric::Exploitability(v2::Exploitability::NotDefined))), // exp
      ), (
        "v2, optional metric, defined", // test name
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H", // val
        Name::V2(v2::Name::Exploitability), // metric name
        Ok(Metric::V2(v2::Metric::Exploitability(v2::Exploitability::High))), // exp
      ), (
        "v2, name mismatch", // test name
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H", // val
        Name::V3(v3::Name::AttackVector), // metric name
        Err(Err::UnknownName), // exp
      ), (
        "v3, base metric", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
        Name::V3(v3::Name::AttackVector), // metric name
        Ok(Metric::V3(v3::Metric::AttackVector(v3::AttackVector::Network))), // exp
      ), (
        "v3, optional metric, not defined", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L", // val
        Name::V3(v3::Name::ModifiedAttackVector), // metric name
        Ok(Metric::V3(v3::Metric::ModifiedAttackVector(v3::ModifiedAttackVector::NotDefined))), // exp
      ), (
        "v3, optional metric, defined", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H", // val
        Name::V3(v3::Name::ModifiedAttackVector), // metric name
        Ok(Metric::V3(v3::Metric::ModifiedAttackVector(v3::ModifiedAttackVector::Physical))), // exp
      ), (
        "v3, name mismatch", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
        Name::V4(v4::Name::AttackVector), // metric name
        Err(Err::UnknownName), // exp
      ), (
        "v4, base metric", // test name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // val
        Name::V4(v4::Name::AttackVector), // metric name
        Ok(Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Network))), // exp
      ), (
        "v4, optional metric, not defined", // test name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // val
        Name::V4(v4::Name::ModifiedAttackVector), // metric name
        Ok(Metric::V4(v4::Metric::ModifiedAttackVector(v4::ModifiedAttackVector::NotDefined))), // exp
      ), (
        "v4, optional metric, defined", // test name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:A", // val
        Name::V4(v4::Name::ModifiedAttackVector), // metric name
        Ok(Metric::V4(v4::Metric::ModifiedAttackVector(v4::ModifiedAttackVector::Adjacent))), // exp
      ), (
        "v4, name mismatch", // test name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:A", // val
        Name::V3(v3::Name::AttackVector), // metric name
        Err(Err::UnknownName), // exp
      ));

      for (test_name, s, metric_name, exp) in tests {
        let v: Vector = s.parse().unwrap();
        assert_eq!(v.get(metric_name), exp, "{test_name}");
      }
    }

    #[test]
    fn test_iter_explicit() {
      let tests = vec!(
        (
          "v2, basic",
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          vec!(
            Metric::V2(v2::Metric::AccessVector(v2::AccessVector::Network)),
            Metric::V2(v2::Metric::AccessComplexity(v2::AccessComplexity::Low)),
            Metric::V2(v2::Metric::Authentication(v2::Authentication::None)),
            Metric::V2(v2::Metric::Confidentiality(v2::Impact::Complete)),
            Metric::V2(v2::Metric::Integrity(v2::Impact::Complete)),
            Metric::V2(v2::Metric::Availability(v2::Impact::Complete)),
          )
        ),

        (
          "v2, everything",
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H", // val
          vec!(
            Metric::V2(v2::Metric::AccessVector(v2::AccessVector::Network)), // AV:N
            Metric::V2(v2::Metric::AccessComplexity(v2::AccessComplexity::Low)), // AC:L
            Metric::V2(v2::Metric::Authentication(v2::Authentication::None)), // Au:N
            Metric::V2(v2::Metric::Confidentiality(v2::Impact::Complete)), // C:C
            Metric::V2(v2::Metric::Integrity(v2::Impact::Complete)), // I:C
            Metric::V2(v2::Metric::Availability(v2::Impact::Complete)), // A:C
            Metric::V2(v2::Metric::Exploitability(v2::Exploitability::High)), // E:H
            Metric::V2(v2::Metric::RemediationLevel(v2::RemediationLevel::Unavailable)), // RL:U
            Metric::V2(v2::Metric::ReportConfidence(v2::ReportConfidence::Confirmed)), // RC:C
            Metric::V2(v2::Metric::CollateralDamagePotential(v2::CollateralDamagePotential::High)), // CDP:H
            Metric::V2(v2::Metric::TargetDistribution(v2::TargetDistribution::High)), // TD:H
            Metric::V2(v2::Metric::ConfidentialityRequirement(v2::Requirement::High)), // CR:H
            Metric::V2(v2::Metric::IntegrityRequirement(v2::Requirement::High)), // IR:H
            Metric::V2(v2::Metric::AvailabilityRequirement(v2::Requirement::High)), // AR:H
          )
        ),

        (
          "v3, basic",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          vec!(
            Metric::V3(v3::Metric::AttackVector(v3::AttackVector::Network)),
            Metric::V3(v3::Metric::AttackComplexity(v3::AttackComplexity::Low)),
            Metric::V3(v3::Metric::PrivilegesRequired(v3::PrivilegesRequired::None)),
            Metric::V3(v3::Metric::UserInteraction(v3::UserInteraction::None)),
            Metric::V3(v3::Metric::Scope(v3::Scope::Unchanged)),
            Metric::V3(v3::Metric::Confidentiality(v3::Impact::High)),
            Metric::V3(v3::Metric::Integrity(v3::Impact::High)),
            Metric::V3(v3::Metric::Availability(v3::Impact::High)),
          )
        ),

        (
          "v3, everything",
          "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
          vec!(
            Metric::V3(v3::Metric::AttackVector(v3::AttackVector::Physical)),
            Metric::V3(v3::Metric::AttackComplexity(v3::AttackComplexity::High)),
            Metric::V3(v3::Metric::PrivilegesRequired(v3::PrivilegesRequired::High)),
            Metric::V3(v3::Metric::UserInteraction(v3::UserInteraction::Required)),
            Metric::V3(v3::Metric::Scope(v3::Scope::Changed)),
            Metric::V3(v3::Metric::Confidentiality(v3::Impact::None)),
            Metric::V3(v3::Metric::Integrity(v3::Impact::None)),
            Metric::V3(v3::Metric::Availability(v3::Impact::None)),
            Metric::V3(v3::Metric::ExploitCodeMaturity(v3::ExploitCodeMaturity::Unproven)),
            Metric::V3(v3::Metric::RemediationLevel(v3::RemediationLevel::OfficialFix)),
            Metric::V3(v3::Metric::ReportConfidence(v3::ReportConfidence::Unknown)),
            Metric::V3(v3::Metric::ConfidentialityRequirement(v3::Requirement::Low)),
            Metric::V3(v3::Metric::IntegrityRequirement(v3::Requirement::Low)),
            Metric::V3(v3::Metric::AvailabilityRequirement(v3::Requirement::Low)),
            Metric::V3(v3::Metric::ModifiedAttackVector(v3::ModifiedAttackVector::Physical)),
            Metric::V3(v3::Metric::ModifiedAttackComplexity(v3::ModifiedAttackComplexity::High)),
            Metric::V3(v3::Metric::ModifiedPrivilegesRequired(v3::ModifiedPrivilegesRequired::High)),
            Metric::V3(v3::Metric::ModifiedUserInteraction(v3::ModifiedUserInteraction::Required)),
            Metric::V3(v3::Metric::ModifiedScope(v3::ModifiedScope::Changed)),
            Metric::V3(v3::Metric::ModifiedConfidentiality(v3::ModifiedImpact::High)),
            Metric::V3(v3::Metric::ModifiedIntegrity(v3::ModifiedImpact::High)),
            Metric::V3(v3::Metric::ModifiedAvailability(v3::ModifiedImpact::High)),
          )
        ),

        (
          "v4, basic",
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
          vec!(
            Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Network)),
            Metric::V4(v4::Metric::AttackComplexity(v4::AttackComplexity::Low)),
            Metric::V4(v4::Metric::AttackRequirements(v4::AttackRequirements::None)),
            Metric::V4(v4::Metric::PrivilegesRequired(v4::PrivilegesRequired::None)),
            Metric::V4(v4::Metric::UserInteraction(v4::UserInteraction::None)),
            Metric::V4(v4::Metric::VulnerableSystemConfidentialityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::VulnerableSystemIntegrityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::VulnerableSystemAvailabilityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemConfidentialityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemIntegrityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemAvailabilityImpact(v4::Impact::High)),
          )
        ),

        (
          "v4, everything",
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:S/MSA:S/S:N/AU:Y/R:I/V:C/RE:H/U:Clear",
          vec!(
            Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Physical)),
            Metric::V4(v4::Metric::AttackComplexity(v4::AttackComplexity::High)),
            Metric::V4(v4::Metric::AttackRequirements(v4::AttackRequirements::Present)),
            Metric::V4(v4::Metric::PrivilegesRequired(v4::PrivilegesRequired::High)),
            Metric::V4(v4::Metric::UserInteraction(v4::UserInteraction::Active)),
            Metric::V4(v4::Metric::VulnerableSystemConfidentialityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::VulnerableSystemIntegrityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::VulnerableSystemAvailabilityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemConfidentialityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemIntegrityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemAvailabilityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::ExploitMaturity(v4::ExploitMaturity::Attacked)),
            Metric::V4(v4::Metric::ConfidentialityRequirement(v4::Requirement::High)),
            Metric::V4(v4::Metric::IntegrityRequirement(v4::Requirement::High)),
            Metric::V4(v4::Metric::AvailabilityRequirement(v4::Requirement::High)),
            Metric::V4(v4::Metric::ModifiedAttackVector(v4::ModifiedAttackVector::Physical)),
            Metric::V4(v4::Metric::ModifiedAttackComplexity(v4::ModifiedAttackComplexity::High)),
            Metric::V4(v4::Metric::ModifiedAttackRequirements(v4::ModifiedAttackRequirements::Present)),
            Metric::V4(v4::Metric::ModifiedPrivilegesRequired(v4::ModifiedPrivilegesRequired::High)),
            Metric::V4(v4::Metric::ModifiedUserInteraction(v4::ModifiedUserInteraction::Active)),
            Metric::V4(v4::Metric::ModifiedVulnerableSystemConfidentiality(v4::ModifiedImpact::None)),
            Metric::V4(v4::Metric::ModifiedVulnerableSystemIntegrity(v4::ModifiedImpact::None)),
            Metric::V4(v4::Metric::ModifiedVulnerableSystemAvailability(v4::ModifiedImpact::None)),
            Metric::V4(v4::Metric::ModifiedSubsequentSystemConfidentiality(v4::ModifiedImpact::None)),
            Metric::V4(v4::Metric::ModifiedSubsequentSystemIntegrity(v4::ModifiedSubsequentImpact::Safety)),
            Metric::V4(v4::Metric::ModifiedSubsequentSystemAvailability(v4::ModifiedSubsequentImpact::Safety)),
            Metric::V4(v4::Metric::Safety(v4::Safety::Negligible)),
            Metric::V4(v4::Metric::Automatable(v4::Automatable::Yes)),
            Metric::V4(v4::Metric::Recovery(v4::Recovery::Irrecoverable)),
            Metric::V4(v4::Metric::ValueDensity(v4::ValueDensity::Concentrated)),
            Metric::V4(v4::Metric::VulnerabilityResponseEffort(v4::VulnerabilityResponseEffort::High)),
            Metric::V4(v4::Metric::ProviderUrgency(v4::ProviderUrgency::Clear)),
          )
        ),
      );

      for (name, s, exp) in tests {
        let got: Vec<Metric> = s.parse::<Vector>().unwrap().into_iter().collect();
        assert_eq!(got, exp, "{name}");
      }
    }

    #[test]
    fn test_iter_implicit() {
      let tests = vec!(
        (
          "v2, basic",
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          vec!(
            Metric::V2(v2::Metric::AccessVector(v2::AccessVector::Network)),
            Metric::V2(v2::Metric::AccessComplexity(v2::AccessComplexity::Low)),
            Metric::V2(v2::Metric::Authentication(v2::Authentication::None)),
            Metric::V2(v2::Metric::Confidentiality(v2::Impact::Complete)),
            Metric::V2(v2::Metric::Integrity(v2::Impact::Complete)),
            Metric::V2(v2::Metric::Availability(v2::Impact::Complete)),
          )
        ),

        (
          "v2, everything",
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H", // val
          vec!(
            Metric::V2(v2::Metric::AccessVector(v2::AccessVector::Network)), // AV:N
            Metric::V2(v2::Metric::AccessComplexity(v2::AccessComplexity::Low)), // AC:L
            Metric::V2(v2::Metric::Authentication(v2::Authentication::None)), // Au:N
            Metric::V2(v2::Metric::Confidentiality(v2::Impact::Complete)), // C:C
            Metric::V2(v2::Metric::Integrity(v2::Impact::Complete)), // I:C
            Metric::V2(v2::Metric::Availability(v2::Impact::Complete)), // A:C
            Metric::V2(v2::Metric::Exploitability(v2::Exploitability::High)), // E:H
            Metric::V2(v2::Metric::RemediationLevel(v2::RemediationLevel::Unavailable)), // RL:U
            Metric::V2(v2::Metric::ReportConfidence(v2::ReportConfidence::Confirmed)), // RC:C
            Metric::V2(v2::Metric::CollateralDamagePotential(v2::CollateralDamagePotential::High)), // CDP:H
            Metric::V2(v2::Metric::TargetDistribution(v2::TargetDistribution::High)), // TD:H
            Metric::V2(v2::Metric::ConfidentialityRequirement(v2::Requirement::High)), // CR:H
            Metric::V2(v2::Metric::IntegrityRequirement(v2::Requirement::High)), // IR:H
            Metric::V2(v2::Metric::AvailabilityRequirement(v2::Requirement::High)), // AR:H
          )
        ),

        (
          "v3, basic",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          vec!(
            Metric::V3(v3::Metric::AttackVector(v3::AttackVector::Network)),
            Metric::V3(v3::Metric::AttackComplexity(v3::AttackComplexity::Low)),
            Metric::V3(v3::Metric::PrivilegesRequired(v3::PrivilegesRequired::None)),
            Metric::V3(v3::Metric::UserInteraction(v3::UserInteraction::None)),
            Metric::V3(v3::Metric::Scope(v3::Scope::Unchanged)),
            Metric::V3(v3::Metric::Confidentiality(v3::Impact::High)),
            Metric::V3(v3::Metric::Integrity(v3::Impact::High)),
            Metric::V3(v3::Metric::Availability(v3::Impact::High)),
          )
        ),

        (
          "v3, everything",
          "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
          vec!(
            Metric::V3(v3::Metric::AttackVector(v3::AttackVector::Physical)),
            Metric::V3(v3::Metric::AttackComplexity(v3::AttackComplexity::High)),
            Metric::V3(v3::Metric::PrivilegesRequired(v3::PrivilegesRequired::High)),
            Metric::V3(v3::Metric::UserInteraction(v3::UserInteraction::Required)),
            Metric::V3(v3::Metric::Scope(v3::Scope::Changed)),
            Metric::V3(v3::Metric::Confidentiality(v3::Impact::None)),
            Metric::V3(v3::Metric::Integrity(v3::Impact::None)),
            Metric::V3(v3::Metric::Availability(v3::Impact::None)),
            Metric::V3(v3::Metric::ExploitCodeMaturity(v3::ExploitCodeMaturity::Unproven)),
            Metric::V3(v3::Metric::RemediationLevel(v3::RemediationLevel::OfficialFix)),
            Metric::V3(v3::Metric::ReportConfidence(v3::ReportConfidence::Unknown)),
            Metric::V3(v3::Metric::ConfidentialityRequirement(v3::Requirement::Low)),
            Metric::V3(v3::Metric::IntegrityRequirement(v3::Requirement::Low)),
            Metric::V3(v3::Metric::AvailabilityRequirement(v3::Requirement::Low)),
            Metric::V3(v3::Metric::ModifiedAttackVector(v3::ModifiedAttackVector::Physical)),
            Metric::V3(v3::Metric::ModifiedAttackComplexity(v3::ModifiedAttackComplexity::High)),
            Metric::V3(v3::Metric::ModifiedPrivilegesRequired(v3::ModifiedPrivilegesRequired::High)),
            Metric::V3(v3::Metric::ModifiedUserInteraction(v3::ModifiedUserInteraction::Required)),
            Metric::V3(v3::Metric::ModifiedScope(v3::ModifiedScope::Changed)),
            Metric::V3(v3::Metric::ModifiedConfidentiality(v3::ModifiedImpact::High)),
            Metric::V3(v3::Metric::ModifiedIntegrity(v3::ModifiedImpact::High)),
            Metric::V3(v3::Metric::ModifiedAvailability(v3::ModifiedImpact::High)),
          )
        ),

        (
          "v4, basic",
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
          vec!(
            Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Network)),
            Metric::V4(v4::Metric::AttackComplexity(v4::AttackComplexity::Low)),
            Metric::V4(v4::Metric::AttackRequirements(v4::AttackRequirements::None)),
            Metric::V4(v4::Metric::PrivilegesRequired(v4::PrivilegesRequired::None)),
            Metric::V4(v4::Metric::UserInteraction(v4::UserInteraction::None)),
            Metric::V4(v4::Metric::VulnerableSystemConfidentialityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::VulnerableSystemIntegrityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::VulnerableSystemAvailabilityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemConfidentialityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemIntegrityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemAvailabilityImpact(v4::Impact::High)),
          )
        ),

        (
          "v4, everything",
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:S/MSA:S/S:N/AU:Y/R:I/V:C/RE:H/U:Clear",
          vec!(
            Metric::V4(v4::Metric::AttackVector(v4::AttackVector::Physical)),
            Metric::V4(v4::Metric::AttackComplexity(v4::AttackComplexity::High)),
            Metric::V4(v4::Metric::AttackRequirements(v4::AttackRequirements::Present)),
            Metric::V4(v4::Metric::PrivilegesRequired(v4::PrivilegesRequired::High)),
            Metric::V4(v4::Metric::UserInteraction(v4::UserInteraction::Active)),
            Metric::V4(v4::Metric::VulnerableSystemConfidentialityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::VulnerableSystemIntegrityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::VulnerableSystemAvailabilityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemConfidentialityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemIntegrityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::SubsequentSystemAvailabilityImpact(v4::Impact::High)),
            Metric::V4(v4::Metric::ExploitMaturity(v4::ExploitMaturity::Attacked)),
            Metric::V4(v4::Metric::ConfidentialityRequirement(v4::Requirement::High)),
            Metric::V4(v4::Metric::IntegrityRequirement(v4::Requirement::High)),
            Metric::V4(v4::Metric::AvailabilityRequirement(v4::Requirement::High)),
            Metric::V4(v4::Metric::ModifiedAttackVector(v4::ModifiedAttackVector::Physical)),
            Metric::V4(v4::Metric::ModifiedAttackComplexity(v4::ModifiedAttackComplexity::High)),
            Metric::V4(v4::Metric::ModifiedAttackRequirements(v4::ModifiedAttackRequirements::Present)),
            Metric::V4(v4::Metric::ModifiedPrivilegesRequired(v4::ModifiedPrivilegesRequired::High)),
            Metric::V4(v4::Metric::ModifiedUserInteraction(v4::ModifiedUserInteraction::Active)),
            Metric::V4(v4::Metric::ModifiedVulnerableSystemConfidentiality(v4::ModifiedImpact::None)),
            Metric::V4(v4::Metric::ModifiedVulnerableSystemIntegrity(v4::ModifiedImpact::None)),
            Metric::V4(v4::Metric::ModifiedVulnerableSystemAvailability(v4::ModifiedImpact::None)),
            Metric::V4(v4::Metric::ModifiedSubsequentSystemConfidentiality(v4::ModifiedImpact::None)),
            Metric::V4(v4::Metric::ModifiedSubsequentSystemIntegrity(v4::ModifiedSubsequentImpact::Safety)),
            Metric::V4(v4::Metric::ModifiedSubsequentSystemAvailability(v4::ModifiedSubsequentImpact::Safety)),
            Metric::V4(v4::Metric::Safety(v4::Safety::Negligible)),
            Metric::V4(v4::Metric::Automatable(v4::Automatable::Yes)),
            Metric::V4(v4::Metric::Recovery(v4::Recovery::Irrecoverable)),
            Metric::V4(v4::Metric::ValueDensity(v4::ValueDensity::Concentrated)),
            Metric::V4(v4::Metric::VulnerabilityResponseEffort(v4::VulnerabilityResponseEffort::High)),
            Metric::V4(v4::Metric::ProviderUrgency(v4::ProviderUrgency::Clear)),
          )
        ),
      );

      for (name, s, exp) in tests {
        let mut got: Vec<Metric> = Vec::new();
        for c in s.parse::<Vector>().unwrap() {
          got.push(c);
        }
        assert_eq!(got, exp, "{name}");
      }
    }

    #[test]
    fn test_base_score() {
      let tests = vec!((
        "v2", // name
        "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:H", // val
        Score(78), // exp score
      ), (
        "v3", // name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P/RL:U/RC:C/CR:L/IR:X/AR:M/MAV:N/MAC:H/MPR:X/MUI:X/MS:U/MC:L/MI:N/MA:H", // val
        Score(43), // exp score
      ), (
        "v4", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:H/SC:H/SI:L/SA:L/E:P/CR:X/IR:X/AR:X/MAV:N/MAC:X/MAT:N/MPR:H/MUI:X/MVC:N/MVI:N/MVA:N/MSC:L/MSI:X/MSA:X", // val
        Score(19), // exp score
      ));

      for (name, s, exp) in tests {
        let vec: Vector = s.parse().unwrap();
        assert_eq!(vec.base_score(), exp, "{name}");
      }
    }

    #[test]
    fn test_size() {
      assert_eq!(size_of::<Vector>(), size_of::<u64>());
    }
  }

  mod score {
    use {std::cmp::Ordering, super::super::Score};

    #[test]
    fn test_from_f32() {
      let tests = vec!(
        (12.3_f32, Score(123)),
        (5.23_f32, Score(52)),
      );

      for (val, exp) in tests {
        assert_eq!(Score::from(val), exp, "{val}");
      }
    }

    #[test]
    fn test_from_f64() {
      let tests = vec!(
        (12.3_f64, Score(123)),
        (5.23_f64, Score(52)),
      );

      for (val, exp) in tests {
        assert_eq!(Score::from(val), exp, "{val}");
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Score(93), "9.3"),
        (Score(52), "5.2"),
        (Score(63), "6.3"),
      );

      for (score, exp) in tests {
        assert_eq!(score.to_string(), exp, "{exp}");
      }
    }

    #[test]
    fn test_cmp() {
      let tests = vec!(
        (Score(10), Score(20), Ordering::Less),
        (Score(10), Score(10), Ordering::Equal),
        (Score(30), Score(20), Ordering::Greater),
      );

      for (a, b, exp) in tests {
        assert_eq!(a.cmp(&b), exp);
      }
    }

    #[test]
    fn test_lt() {
      let tests = vec!(
        (Score(10), Score(20), true),
        (Score(10), Score(10), false),
        (Score(30), Score(20), false),
      );

      for (a, b, exp) in tests {
        assert_eq!(a < b, exp);
      }
    }

    #[test]
    fn test_from_vector() {
      use super::super::Vector;

      let tests = vec!((
        "v2", // name
        "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M", // val
        Score(74), // exp score
      ), (
        "v3", // name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P/RL:U/RC:C/CR:L/IR:X/AR:M/MAV:N/MAC:H/MPR:X/MUI:X/MS:U/MC:L/MI:N/MA:H", // val
        Score(59), // exp score
      ), (
        "v4", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:H/SC:H/SI:L/SA:L/E:P/CR:X/IR:X/AR:X/MAV:N/MAC:X/MAT:N/MPR:H/MUI:X/MVC:N/MVI:N/MVA:N/MSC:L/MSI:X/MSA:X", // val
        Score(19), // exp score
      ));

      for (name, s, exp) in tests {
        let vec: Vector = s.parse().unwrap();
        assert_eq!(Score::from(vec), exp, "{name}");
      }
    }

  }

  mod severity {
    use super::super::{Err, Score, Severity};

    #[test]
    fn test_from_str_fail() {
      let tests = vec!(
        "asdf",
      );

      for t in tests {
        assert_eq!(t.parse::<Severity>(), Err(Err::UnknownSeverity), "{t}");
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        ("NONE", Severity::None),
        ("LOW", Severity::Low),
        ("MEDIUM", Severity::Medium),
        ("HIGH", Severity::High),
        ("CRITICAL", Severity::Critical),
      );

      for (s, exp) in tests {
        assert_eq!(s.parse::<Severity>().unwrap(), exp, "{s}");
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Severity::None, "NONE"),
        (Severity::Low, "LOW"),
        (Severity::Medium, "MEDIUM"),
        (Severity::High, "HIGH"),
        (Severity::Critical, "CRITICAL"),
      );

      for (s, exp) in tests {
        assert_eq!(s.to_string(), exp, "{s}");
      }
    }

    #[test]
    fn test_from_score() {
      let tests = vec!(
        (Score(0), Severity::None),
        (Score(1), Severity::Low),
        (Score(39), Severity::Low),
        (Score(40), Severity::Medium),
        (Score(69), Severity::Medium),
        (Score(70), Severity::High),
        (Score(89), Severity::High),
        (Score(90), Severity::Critical),
        (Score(100), Severity::Critical),
      );

      for (score, exp) in tests {
        assert_eq!(Severity::from(score), exp, "{score}");
      }
    }

    #[test]
    fn test_cmp() {
      use std::cmp::Ordering;

      let tests = vec!(
        (Severity::None, Severity::None, Ordering::Equal),
        (Severity::None, Severity::Low, Ordering::Less),
        (Severity::High, Severity::Medium, Ordering::Greater),
      );

      for (a, b, exp) in tests {
        assert_eq!(a.cmp(&b), exp, "{a},{b}");
      }
    }
  }
}
