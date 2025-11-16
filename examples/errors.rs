//! Show various errors.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example errors
//! ```

use polycvss::{Err, Severity, Version, v4};

fn main() {
  // Err::Len: String is too short to contain a CVSS vector string.
  assert_eq!("asdf".parse::<v4::Vector>(), Err(Err::Len));

  // Err::Prefix: String does not begin with a `CVSS:` prefix.
  assert_eq!("CVSS:foo/".parse::<v4::Vector>(), Err(Err::Prefix));

  // Err::DuplicateName: Vector string contains a duplicate metric name.
  assert_eq!("CVSS:4.0/AV:N/AV:N".parse::<v4::Vector>(), Err(Err::DuplicateName));

  // Err::UnknownName: Unknown metric name.
  assert_eq!("asdf".parse::<v4::Name>(), Err(Err::UnknownName));

  // Err::UnknownMetric: Vector string contains an unknown metric.
  assert_eq!("CVSS:4.0/AV:Z".parse::<v4::Vector>(), Err(Err::UnknownMetric));
  assert_eq!("CVSS:4.0/ZZ:Z".parse::<v4::Vector>(), Err(Err::UnknownMetric));

  // Err::MissingMandatoryMetric: Vector string is missing mandatory metrics.
  {
    let s = "CVSS:4.0/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";
    assert_eq!(s.parse::<v4::Vector>(), Err(Err::MissingMandatoryMetrics));
  }

  // Err::UnknownSeverity:  Unknown severity name.
  assert_eq!("asdf".parse::<Severity>(), Err(Err::UnknownSeverity));

  // Err::InvalidMacroVector: Invalid v4::MacroVector digit.
  assert_eq!(v4::MacroVector::try_from(123456), Err(Err::InvalidMacroVector));

  // Err::UnknownVersion: Unknown CVSS version.
  assert_eq!("asdf".parse::<Version>(), Err(Err::UnknownVersion));

  // Err::UnknownNomenclature: Unknown v4::Nomenclature.
  assert_eq!("asdf".parse::<v4::Nomenclature>(), Err(Err::UnknownNomenclature));
}
