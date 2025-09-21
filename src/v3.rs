//! [CVSS v3][doc] parser and score calculator.
//!
//! # Examples
//!
//! Parse [vector string][vector-string], then get a [`Metric`][] by [`Name`][]:
//!
//! ```
//! # use polycvss::{Err, v3::{AttackVector, Vector, Metric, Name}};
//! # fn main() -> Result<(), Err> {
//! // parse vector string
//! let v: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
//!
//! // get metric
//! let metric = v.get(Name::AttackVector);
//!
//! // check result
//! assert_eq!(metric, Metric::AttackVector(AttackVector::Network));
//! # Ok(())
//! # }
//! ```
//!
//! Parse [vector string][vector-string], then build a list of metric
//! [`Name`s][Name]:
//!
//! ```
//! # use polycvss::{Err, v3::{Name, Vector}};
//! # fn main() -> Result<(), Err> {
//! // parse vector string
//! let v: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
//!
//! // get metric names
//! let names: Vec<Name> = v.into_iter().map(Name::from).collect();
//!
//! // check result
//! assert_eq!(names, vec!(
//!   Name::AttackVector,
//!   Name::AttackComplexity,
//!   Name::PrivilegesRequired,
//!   Name::UserInteraction,
//!   Name::Scope,
//!   Name::Confidentiality,
//!   Name::Integrity,
//!   Name::Availability,
//! ));
//! # Ok(())
//! # }
//! ```
//!
//! Get score for [CVSS v3][doc] vector:
//!
//! ```
//! # use polycvss::{Err, Score, v3::Vector};
//! # fn main() -> Result<(), Err> {
//! // parse CVSS v3 vector string
//! let v: Vector = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H".parse()?;
//!
//! // get score
//! let score = Score::from(v);
//!
//! // check result
//! assert_eq!(score, Score::from(4.4));
//! # Ok(())
//! # }
//! ```
//!
//! [doc]: https://www.first.org/cvss/v3-1/specification-document
//!   "CVSS v3.1 Specification"
//! [vector-string]: https://www.first.org/cvss/v3-1/specification-document#Vector-String
//!   "CVSS v3.1 Specification, Section 6: Vector String"

#[cfg(feature="serde")]
use serde::{self,Deserialize,Serialize};
use super::{Err, Score, Version, encode::{EncodedVal, EncodedMetric}};

// TODO:
// - add name tests
// - more scores tests
// - update scores docs
// - consistent struct/impl ordering w v40.rs

/// Round value up to nearest 10th of a decimal.
///
/// Used for [CVSS v3][doc-v3] scoring.
///
/// The behavior of this function varies between CVSS v3.0 and CVSS v3.1.  See
/// [CVSS v3.1 Specification, Appendix A: Floating Point Rounding][doc].
///
/// # Example
///
/// ```
/// # use polycvss::{Version, v3::roundup};
/// # fn main() {
/// assert_eq!(roundup(4.000_002, Version::V30), 4.1);
/// assert_eq!(roundup(4.000_002, Version::V31), 4.0);
/// assert_eq!(roundup(4.02, Version::V31), 4.1);
/// assert_eq!(roundup(4.00, Version::V31), 4.0);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Appendix-A---Floating-Point-Rounding
///   "CVSS v3.1 Specification, Appendix A: Floating Point Rounding"
/// [doc-v3]: https://www.first.org/cvss/v3-1/specification-document
///   "CVSS v3.1 Specification"
pub fn roundup(val: f64, version: Version) -> f64 {
  match version {
    Version::V30 => (val * 10.0).ceil() / 10.0,
    Version::V31 => {
      let v: i32 = (val * 100_000.0).round() as i32;
      if v % 10_000 == 0 {
        (v as f64) / 100_000.0
      } else {
        (((v / 10_000) as f64) + 1.0) / 10.0
      }
    },
    _ => unreachable!(),
  }
}

/// [`Metric`][] group.
///
/// See [CVSS v3.1 Specification, Section 1.1: Metrics][doc].
///
/// # Example
///
/// Get metric group:
///
/// ```
/// # use polycvss::v3::{Group, Name};
/// # fn main() {
/// // get group
/// let group = Group::from(Name::AttackVector);
///
/// // check result
/// assert_eq!(group, Group::Base);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Metrics
///   "CVSS v3.1 Specification, Section 1.1: Metrics"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
pub enum Group {
  Base,
  Temporal,
  Environmental,
}

impl From<Name> for Group {
  fn from(name: Name) -> Group {
    match name {
      Name::AttackVector => Group::Base,
      Name::AttackComplexity => Group::Base,
      Name::PrivilegesRequired => Group::Base,
      Name::UserInteraction => Group::Base,
      Name::Scope => Group::Base,
      Name::Confidentiality => Group::Base,
      Name::Integrity => Group::Base,
      Name::Availability => Group::Base,
      Name::ExploitCodeMaturity => Group::Temporal,
      Name::RemediationLevel => Group::Temporal,
      Name::ReportConfidence => Group::Temporal,
      Name::ConfidentialityRequirement => Group::Environmental,
      Name::IntegrityRequirement => Group::Environmental,
      Name::AvailabilityRequirement => Group::Environmental,
      Name::ModifiedAttackVector => Group::Environmental,
      Name::ModifiedAttackComplexity => Group::Environmental,
      Name::ModifiedPrivilegesRequired => Group::Environmental,
      Name::ModifiedUserInteraction => Group::Environmental,
      Name::ModifiedScope => Group::Environmental,
      Name::ModifiedConfidentiality => Group::Environmental,
      Name::ModifiedIntegrity => Group::Environmental,
      Name::ModifiedAvailability => Group::Environmental,
    }
  }
}

impl std::fmt::Display for Group {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{self:?}")
  }
}

/// [`Metric`][] name.
///
/// # Examples
///
/// Get metric name:
///
/// ```
/// # use polycvss::v3::{AttackVector, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AttackVector(AttackVector::Local));
///
/// // check result
/// assert_eq!(name, Name::AttackVector);
/// # }
/// ```
///
/// Check if metric is mandatory:
///
/// ```
/// # use polycvss::v3::{AttackVector, Name};
/// # fn main() {
/// // check if metric is mandatory
/// assert_eq!(true, Name::AttackVector.is_mandatory());
/// # }
/// ```
#[derive(Clone,Copy,Debug,PartialEq)]
pub enum Name {
  /// Attack Vector (`AV`) metric name.  See [`Metric::AttackVector`][].
  AttackVector,

  /// Attack Complexity (`AC`) metric name.  See [`Metric::AttackComplexity`][].
  AttackComplexity,

  /// Privileges Required (`PR`) metric name.  See [`Metric::PrivilegesRequired`][].
  PrivilegesRequired,

  /// User Interaction (`UI`) metric name.  See [`Metric::UserInteraction`][].
  UserInteraction,

  /// Scope (`S`) metric name.  See [`Metric::Scope`][].
  Scope,

  /// Confidentiality (`C`) metric name.  See [`Metric::Confidentiality`][].
  Confidentiality,

  /// Integrity (`I`) metric name.  See [`Metric::Integrity`][].
  Integrity,

  /// Availability (`A`) metric name.  See [`Metric::Availability`][].
  Availability,

  /// Exploit Code Maturity (`E`) metric name.  See [`Metric::ExploitCodeMaturity`][].
  ExploitCodeMaturity,

  /// Remediation Level (`RL`) metric name.  See [`Metric::RemediationLevel`][].
  RemediationLevel,

  /// Report Confidence (`RC`) metric name.  See [`Metric::ReportConfidence`][].
  ReportConfidence,

  /// Confidentiality Requirement (`CR`) metric name.  See [`Metric::ConfidentialityRequirement`][].
  ConfidentialityRequirement,

  /// Integrity Requirement (`IR`) metric name.  See [`Metric::IntegrityRequirement`][].
  IntegrityRequirement,

  /// Availability Requirement (`AR`) metric name.  See [`Metric::AvailabilityRequirement`][].
  AvailabilityRequirement,

  /// Modified Attack Vector (`MAV`) metric name.  See [`Metric::ModifiedAttackVector`][].
  ModifiedAttackVector,

  /// Modified Attack Complexity (`MAC`) metric name.  See [`Metric::ModifiedAttackComplexity`][].
  ModifiedAttackComplexity,

  /// Modified Privileges Required (`MPR`) metric name.  See [`Metric::ModifiedPrivilegesRequired`][].
  ModifiedPrivilegesRequired,

  /// Modified User Interaction (`MUI`) metric name.  See [`Metric::ModifiedUserInteraction`][].
  ModifiedUserInteraction,

  /// Modified Scope (`MS`) metric name.  See [`Metric::ModifiedScope`][].
  ModifiedScope,

  /// Modified Confidentiality (`MC`) metric name.  See [`Metric::ModifiedConfidentiality`][].
  ModifiedConfidentiality,

  /// Modified Integrity (`MI`) metric name.  See [`Metric::ModifiedIntegrity`][].
  ModifiedIntegrity,

  /// Modified Availability (`MA`) metric name.  See [`Metric::ModifiedAvailability`][].
  ModifiedAvailability,
}

impl Name {
  /// Is this metric mandatory?
  ///
  /// # Example
  ///
  /// # use polycvss::v3::{AttackVector, Name};
  /// # fn main() {
  /// // check if metric is mandatory
  /// assert_eq!(true, Name::AttackVector.is_mandatory());
  /// # }
  pub fn is_mandatory(self) -> bool {
    Group::from(self) == Group::Base
  }
}

impl From<Metric> for Name {
  fn from(c: Metric) -> Name {
    match c {
      Metric::AttackVector(_) => Name::AttackVector,
      Metric::AttackComplexity(_) => Name::AttackComplexity,
      Metric::PrivilegesRequired(_) => Name::PrivilegesRequired,
      Metric::UserInteraction(_) => Name::UserInteraction,
      Metric::Scope(_) => Name::Scope,
      Metric::Confidentiality(_) => Name::Confidentiality,
      Metric::Integrity(_) => Name::Integrity,
      Metric::Availability(_) => Name::Availability,
      Metric::ExploitCodeMaturity(_) => Name::ExploitCodeMaturity,
      Metric::RemediationLevel(_) => Name::RemediationLevel,
      Metric::ReportConfidence(_) => Name::ReportConfidence,
      Metric::ConfidentialityRequirement(_) => Name::ConfidentialityRequirement,
      Metric::IntegrityRequirement(_) => Name::IntegrityRequirement,
      Metric::AvailabilityRequirement(_) => Name::AvailabilityRequirement,
      Metric::ModifiedAttackVector(_) => Name::ModifiedAttackVector,
      Metric::ModifiedAttackComplexity(_) => Name::ModifiedAttackComplexity,
      Metric::ModifiedPrivilegesRequired(_) => Name::ModifiedPrivilegesRequired,
      Metric::ModifiedUserInteraction(_) => Name::ModifiedUserInteraction,
      Metric::ModifiedScope(_) => Name::ModifiedScope,
      Metric::ModifiedConfidentiality(_) => Name::ModifiedConfidentiality,
      Metric::ModifiedIntegrity(_) => Name::ModifiedIntegrity,
      Metric::ModifiedAvailability(_) => Name::ModifiedAvailability,
    }
  }
}

impl std::str::FromStr for Name {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "AV" => Ok(Name::AttackVector),
      "AC" => Ok(Name::AttackComplexity),
      "PR" => Ok(Name::PrivilegesRequired),
      "UI" => Ok(Name::UserInteraction),
      "S" => Ok(Name::Scope),
      "C" => Ok(Name::Confidentiality),
      "I" => Ok(Name::Integrity),
      "A" => Ok(Name::Availability),
      "E" => Ok(Name::ExploitCodeMaturity),
      "RL" => Ok(Name::RemediationLevel),
      "RC" => Ok(Name::ReportConfidence),
      "CR" => Ok(Name::ConfidentialityRequirement),
      "IR" => Ok(Name::IntegrityRequirement),
      "AR" => Ok(Name::AvailabilityRequirement),
      "MAV" => Ok(Name::ModifiedAttackVector),
      "MAC" => Ok(Name::ModifiedAttackComplexity),
      "MPR" => Ok(Name::ModifiedPrivilegesRequired),
      "MUI" => Ok(Name::ModifiedUserInteraction),
      "MS" => Ok(Name::ModifiedScope),
      "MC" => Ok(Name::ModifiedConfidentiality),
      "MI" => Ok(Name::ModifiedIntegrity),
      "MA" => Ok(Name::ModifiedAvailability),
      _ => Err(Err::UnknownName),
    }
  }
}

impl std::fmt::Display for Name {
  // Format CVSS v3 metric name as a string.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{}", match self {
      Name::AttackVector => "AV",
      Name::AttackComplexity => "AC",
      Name::PrivilegesRequired => "PR",
      Name::UserInteraction => "UI",
      Name::Scope => "S",
      Name::Confidentiality => "C",
      Name::Integrity => "I",
      Name::Availability => "A",
      Name::ExploitCodeMaturity => "E",
      Name::RemediationLevel => "RL",
      Name::ReportConfidence => "RC",
      Name::ConfidentialityRequirement => "CR",
      Name::IntegrityRequirement => "IR",
      Name::AvailabilityRequirement => "AR",
      Name::ModifiedAttackVector => "MAV",
      Name::ModifiedAttackComplexity => "MAC",
      Name::ModifiedPrivilegesRequired => "MPR",
      Name::ModifiedUserInteraction => "MUI",
      Name::ModifiedScope => "MS",
      Name::ModifiedConfidentiality => "MC",
      Name::ModifiedIntegrity => "MI",
      Name::ModifiedAvailability => "MA",
    })
  }
}

/// [`Metric::AttackVector`][] (`AV`) values.
///
/// # Description
///
/// This metric reflects the context by which vulnerability exploitation
/// is possible. This metric value (and consequently the Base Score) will
/// be larger the more remote (logically, and physically) an attacker can
/// be in order to exploit the vulnerable component. The assumption is
/// that the number of potential attackers for a vulnerability that could
/// be exploited from across a network is larger than the number of
/// potential attackers that could exploit a vulnerability requiring
/// physical access to a device, and therefore warrants a greater Base
/// Score.
///
/// # Properties
///
/// - Metric Group: Base Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 2.1.1: Attack Vector (`AV`)][doc]
///
/// # Examples
///
/// Parse string as metric and check it:
///
/// ```
/// # use polycvss::{Err, v3::{AttackVector, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "AV:N".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::AttackVector(AttackVector::Network));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v3::{AttackVector, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::AttackVector(AttackVector::Adjacent).to_string();
///
/// // check result
/// assert_eq!(s, "AV:A");
/// # }
/// ```
///
/// Get metric name
///
/// ```
/// # use polycvss::v3::{AttackVector, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AttackVector(AttackVector::Local));
///
/// // check result
/// assert_eq!(name, Name::AttackVector);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Attack-Vector-AV
///   "CVSS v3.1 Specification, Section 2.1.1: Attack Vector (AV)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum AttackVector {
  /// Network (`N`)
  ///
  /// The vulnerable component is bound to the network stack and the set
  /// of possible attackers extends beyond the other options listed below,
  /// up to and including the entire Internet. Such a vulnerability is
  /// often termed “remotely exploitable” and can be thought of as an
  /// attack being exploitable at the protocol level one or more network
  /// hops away (e.g., across one or more routers). An example of a
  /// network attack is an attacker causing a denial of service (DoS) by
  /// sending a specially crafted TCP packet across a wide area network
  /// (e.g., CVE‑2004‑0230).
  Network,

  /// Adjacent (`A`)
  ///
  /// The vulnerable component is bound to the network stack, but the
  /// attack is limited at the protocol level to a logically adjacent
  /// topology. This can mean an attack must be launched from the same
  /// shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g.,
  /// local IP subnet) network, or from within a secure or otherwise
  /// limited administrative domain (e.g., MPLS, secure VPN to an
  /// administrative network zone). One example of an Adjacent attack
  /// would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to
  /// a denial of service on the local LAN segment (e.g., CVE‑2013‑6014).
  Adjacent,

  /// Local (`L`)
  ///
  /// The vulnerable component is not bound to the network stack and the
  /// attacker’s path is via read/write/execute capabilities. Either:
  ///
  /// - the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH); or
 /// - the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).
  Local,

  /// Physical (`P`)
  ///
  /// The attack requires the attacker to physically touch or manipulate
  /// the vulnerable component. Physical interaction may be brief (e.g.,
  /// evil maid attack1) or persistent. An example of such an attack is a
  /// cold boot attack in which an attacker gains access to disk
  /// encryption keys after physically accessing the target system. Other
  /// examples include peripheral attacks via FireWire/USB Direct Memory
  /// Access (DMA).
  Physical,
}

/// [`Metric::ModifiedAttackVector`][] (`MAV`) values.
///
/// # Description
///
/// Metric value which overrides the base [`Metric::AttackVector`][]
/// (`AV`) metric value.
///
/// # Properties
///
/// - Metric Group: Environmental Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedAttackVector {
  /// Not Defined (`X`)
  NotDefined,

  /// Network (`N`)
  ///
  /// See [AttackVector::Network][].
  Network,

  /// Adjacent (`A`)
  ///
  /// See [AttackVector::Adjacent][].
  Adjacent,

  /// Local (`L`)
  ///
  /// See [AttackVector::Local][].
  Local,

  /// Physical (`P`)
  ///
  /// See [AttackVector::Physical][].
  Physical,
}

/// [`Metric::AttackComplexity`][] (`AC`) values.
///
/// # Description
///
/// This metric describes the conditions beyond the attacker’s control
/// that must exist in order to exploit the vulnerability. As described
/// below, such conditions may require the collection of more information
/// about the target, or computational exceptions. Importantly, the
/// assessment of this metric excludes any requirements for user
/// interaction in order to exploit the vulnerability (such conditions are
/// captured in the User Interaction metric). If a specific configuration
/// is required for an attack to succeed, the Base metrics should be
/// scored assuming the vulnerable component is in that configuration. The
/// Base Score is greatest for the least complex attacks.
///
/// # Properties
///
/// - Metric Group: Base Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 2.1.2: Attack Complexity (`AC`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v3::{AttackComplexity, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "AC:L".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::AttackComplexity(AttackComplexity::Low));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v3::{AttackComplexity, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::AttackComplexity(AttackComplexity::High).to_string();
///
/// // check result
/// assert_eq!(s, "AC:H");
/// # }
/// ```
///
/// Get metric name
///
/// ```
/// # use polycvss::v3::{AttackComplexity, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AttackComplexity(AttackComplexity::High));
///
/// // check result
/// assert_eq!(name, Name::AttackComplexity);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Attack-Complexity-AC
///   "CVSS v3.1 Specification, Section 2.1.2: Attack Complexity (AC)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum AttackComplexity {
  /// Low (`L`)
  ///
  /// Specialized access conditions or extenuating circumstances do not
  /// exist. An attacker can expect repeatable success when attacking the
  /// vulnerable component.
  Low,

  /// High (`H`)
  ///
  /// A successful attack depends on conditions beyond the attacker's
  /// control. That is, a successful attack cannot be accomplished at
  /// will, but requires the attacker to invest in some measurable amount
  /// of effort in preparation or execution against the vulnerable
  /// component before a successful attack can be expected.2 For example,
  /// a successful attack may depend on an attacker overcoming any of the
  /// following conditions:
  ///
  /// - The attacker must gather knowledge about the environment in
  ///   which the vulnerable target/component exists. For example, a
  ///   requirement to collect details on target configuration settings,
  ///   sequence numbers, or shared secrets.
  /// - The attacker must prepare the target environment to improve
  ///   exploit reliability. For example, repeated exploitation to win a
  ///   race condition, or overcoming advanced exploit mitigation
  ///   techniques.
  /// - The attacker must inject themselves into the logical network
  ///   path between the target and the resource requested by the victim in
  ///   order to read and/or modify network communications (e.g., a man in
  ///   the middle attack).
  High,
}

/// [`Metric::ModifiedAttackComplexity`][] (`MAC`) values.
///
/// # Description
///
/// Metric value which overrides the base [`Metric::AttackComplexity`][]
/// (`AC`) metric value.
///
/// # Properties
///
/// - Metric Group: Environmental Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedAttackComplexity {
  /// Not Defined (`X`)
  NotDefined,

  /// Low (`L`)
  ///
  /// See [`AttackComplexity::Low`][].
  Low,

  /// High (`H`)
  ///
  /// See [`AttackComplexity::High`][].
  High,
}

/// [`Metric::PrivilegesRequired`][] (`PR`) values.
///
/// # Description
///
/// This metric describes the level of privileges an attacker must
/// possess before successfully exploiting the vulnerability. The Base
/// Score is greatest if no privileges are required.
///
/// # Properties
///
/// - Metric Group: Base Metrics
/// - Base Metric Set: Exploitability Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 2.1.3: Privileges Required (`PR`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v3::{PrivilegesRequired, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "PR:N".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::PrivilegesRequired(PrivilegesRequired::None));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v3::{PrivilegesRequired, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::PrivilegesRequired(PrivilegesRequired::Low).to_string();
///
/// // check result
/// assert_eq!(s, "PR:L");
/// # }
/// ```
///
/// Get metric name
///
/// ```
/// # use polycvss::v3::{PrivilegesRequired, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::PrivilegesRequired(PrivilegesRequired::High));
///
/// // check result
/// assert_eq!(name, Name::PrivilegesRequired);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Privileges-Required-PR
///   "CVSS v3.1 Specification, Section 2.1.3: Privileges Required (PR)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum PrivilegesRequired {
  /// None (`N`)
  ///
  /// The attacker is unauthenticated prior to attack, and therefore
  /// does not require any access to settings or files of the vulnerable
  /// system to carry out an attack.
  None,

  /// Low (`L`)
  ///
  /// The attacker requires privileges that provide basic capabilities
  /// that are typically limited to settings and resources owned by a
  /// single low-privileged user. Alternatively, an attacker with Low
  /// privileges has the ability to access only non-sensitive resources.
  Low,

  /// High (`H`)
  ///
  /// The attacker requires privileges that provide significant (e.g.,
  /// administrative) control over the vulnerable system allowing full
  /// access to the vulnerable system’s settings and files.
  High,
}

/// [`Metric::ModifiedPrivilegesRequired`][] (`MPR`) values.
///
/// # Description
///
/// Metric value which overrides the base [`Metric::PrivilegesRequired`][]
/// (`PR`) metric value.
///
/// # Properties
///
/// - Metric Group: Environmental Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedPrivilegesRequired {
  /// Not Defined (`X`)
  NotDefined,

  /// None (`N`)
  ///
  /// See [`PrivilegesRequired::None`][]
  None,

  /// Low (`L`)
  ///
  /// See [`PrivilegesRequired::Low`][]
  Low,

  /// High (`H`)
  ///
  /// See [`PrivilegesRequired::High`][]
  High,
}

/// [`Metric::UserInteraction`][] (`UI`) values.
///
/// # Description
///
/// This metric captures the requirement for a human user, other than
/// the attacker, to participate in the successful compromise of the
/// vulnerable component. This metric determines whether the vulnerability
/// can be exploited solely at the will of the attacker, or whether a
/// separate user (or user-initiated process) must participate in some
/// manner. The Base Score is greatest when no user interaction is
/// required.
///
/// # Properties
///
/// - Metric Group: Base Metrics
/// - Base Metric Set: Exploitability Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 2.1.4: User Interaction (`UI`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v3::{UserInteraction, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "UI:N".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::UserInteraction(UserInteraction::None));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v3::{UserInteraction, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::UserInteraction(UserInteraction::Required).to_string();
///
/// // check result
/// assert_eq!(s, "UI:R");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v3::{UserInteraction, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::UserInteraction(UserInteraction::None));
///
/// // check result
/// assert_eq!(name, Name::UserInteraction);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#User-Interaction-UI
///   "CVSS v3.1 Specification, Section 2.1.4: User Interaction (UI)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum UserInteraction {
  /// None (`N`)
  ///
  /// The vulnerable system can be exploited without interaction from any user.
  None,

  /// Required (`R`)
  ///
  /// Successful exploitation of this vulnerability requires a user to
  /// take some action before the vulnerability can be exploited. For
  /// example, a successful exploit may only be possible during the
  /// installation of an application by a system administrator.
  Required,
}

/// [`Metric::ModifiedUserInteraction`][] (`MUI`) values.
///
/// # Description
///
/// Metric value which overrides the base [`Metric::UserInteraction`][]
/// (`UI`) metric value.
///
/// # Properties
///
/// - Metric Group: Environmental Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedUserInteraction {
  /// Not Defined (`X`)
  NotDefined,

  /// None (`N`)
  ///
  /// See [`UserInteraction::None`][].
  None,

  /// Required (`R`)
  ///
  /// See [`UserInteraction::Required`][].
  Required,
}

/// [`Metric::Scope`][] (`S`) values.
///
/// # Description
///
/// The Scope metric captures whether a vulnerability in one vulnerable
/// component impacts resources in components beyond its security scope.
///
/// Formally, a security authority is a mechanism (e.g., an application,
/// an operating system, firmware, a sandbox environment) that defines and
/// enforces access control in terms of how certain subjects/actors (e.g.,
/// human users, processes) can access certain restricted
/// objects/resources (e.g., files, CPU, memory) in a controlled manner.
/// All the subjects and objects under the jurisdiction of a single
/// security authority are considered to be under one security scope. If a
/// vulnerability in a vulnerable component can affect a component which
/// is in a different security scope than the vulnerable component, a
/// Scope change occurs. Intuitively, whenever the impact of a
/// vulnerability breaches a security/trust boundary and impacts
/// components outside the security scope in which vulnerable component
/// resides, a Scope change occurs.
///
/// The security scope of a component encompasses other components that
/// provide functionality solely to that component, even if these other
/// components have their own security authority. For example, a database
/// used solely by one application is considered part of that
/// application’s security scope even if the database has its own security
/// authority, e.g., a mechanism controlling access to database records
/// based on database users and associated database privileges.
///
/// The Base Score is greatest when a scope change occurs.
///
/// # Properties
///
/// - Metric Group: Base Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 2.2: Scope (`S`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v3::{Scope, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "S:U".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::Scope(Scope::Unchanged));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v3::{Scope, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::Scope(Scope::Changed).to_string();
///
/// // check result
/// assert_eq!(s, "S:C");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v3::{Scope, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::Scope(Scope::Changed));
///
/// // check result
/// assert_eq!(name, Name::Scope);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Scope-S
///   "CVSS v3.1 Specification, Section 2.2: Scope (S)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum Scope {
  /// Unchanged (`U`)
  ///
  /// An exploited vulnerability can only affect resources managed by
  /// the same security authority. In this case, the vulnerable component
  /// and the impacted component are either the same, or both are managed
  /// by the same security authority.
  Unchanged,

  /// Changed (`C`)
  ///
  /// An exploited vulnerability can affect resources beyond the
  /// security scope managed by the security authority of the vulnerable
  /// component. In this case, the vulnerable component and the impacted
  /// component are different and managed by different security
  /// authorities.
  Changed,
}

/// [`Metric::ModifiedScope`][] (`MS`) values.
///
/// # Description
///
/// Metric value which overrides the base [`Metric::Scope`][]
/// (`S`) metric value.
///
/// # Properties
///
/// - Metric Group: Environmental Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedScope {
  /// Not Defined (`X`)
  NotDefined,

  /// Unchanged (`U`)
  ///
  /// An exploited vulnerability can only affect resources managed by
  /// the same security authority. In this case, the vulnerable component
  /// and the impacted component are either the same, or both are managed
  /// by the same security authority.
  Unchanged,

  /// Changed (`C`)
  ///
  /// An exploited vulnerability can affect resources beyond the
  /// security scope managed by the security authority of the vulnerable
  /// component. In this case, the vulnerable component and the impacted
  /// component are different and managed by different security
  /// authorities.
  Changed,
}

/// Impact metric (`C`, `I`, `A`) values.
///
/// # Description
///
/// Impact metrics:
///
/// - `C`: [`Metric::Confidentiality`][]
/// - `I`: [`Metric::Integrity`][]
/// - `A`: [`Metric::Availability`][]
///
/// # Properties
///
/// - Metric Group: Base Metrics
/// - Base Metric Set: Impact Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 2.3: Impact Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Impact-Metrics
///   "CVSS v3.1 Specification, Section 2.3: Impact Metrics"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum Impact {
  /// None (`N`)
  ///
  /// | Metric | Description |
  /// | ------ | ----------- |
  /// | `C` | There is no loss of confidentiality within the impacted component. |
  /// | `I` | There is no loss of integrity within the impacted component. |
  /// | `A` | There is no impact to availability within the impacted component. |
  None,

  /// Low (`L`)
  ///
  /// | Metric | Description |
  /// | ------ | ----------- |
  /// | `C` | There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component. |
  /// | `I` | Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component. |
  /// | `A` | Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component. |
  Low,

  /// High (`H`)
  ///
  /// | Metric | Description |
  /// | ------ | ----------- |
  /// | `C` | There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server. |
  /// | `I` | There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component. |
  /// | `A` | There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable). |
  High,
}

/// Modified impact metric (`MC`, `MI`, `MA`) values.
///
/// # Description
///
/// Modified impact metrics:
///
/// - `MC`: [`Metric::ModifiedConfidentiality`][]
/// - `MI`: [`Metric::ModifiedIntegrity`][]
/// - `MA`: [`Metric::ModifiedAvailability`][]
///
/// # Properties
///
/// - Metric Group: Environmental Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedImpact {
  /// Not Defined (`X`)
  NotDefined,

  /// None (`N`)
  ///
  /// | Metric | Description |
  /// | ------ | ----------- |
  /// | `C` | There is no loss of confidentiality within the impacted component. |
  /// | `I` | There is no loss of integrity within the impacted component. |
  /// | `A` | There is no impact to availability within the impacted component. |
  None,

  /// Low (`L`)
  ///
  /// | Metric | Description |
  /// | ------ | ----------- |
  /// | `C` | There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component. |
  /// | `I` | Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component. |
  /// | `A` | Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component. |
  Low,

  /// High (`H`)
  ///
  /// | Metric | Description |
  /// | ------ | ----------- |
  /// | `C` | There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server. |
  /// | `I` | There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component. |
  /// | `A` | There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable). |
  High,
}

/// [`Metric::ExploitCodeMaturity`][] (`E`) values.
///
/// # Description
///
/// This metric measures the likelihood of the vulnerability being
/// attacked, and is typically based on the current state of exploit
/// techniques, exploit code availability, or active, “in-the-wild”
/// exploitation. Public availability of easy-to-use exploit code
/// increases the number of potential attackers by including those who are
/// unskilled, thereby increasing the severity of the vulnerability.
/// Initially, real-world exploitation may only be theoretical.
/// Publication of proof-of-concept code, functional exploit code, or
/// sufficient technical details necessary to exploit the vulnerability
/// may follow. Furthermore, the exploit code available may progress from
/// a proof-of-concept demonstration to exploit code that is successful in
/// exploiting the vulnerability consistently. In severe cases, it may be
/// delivered as the payload of a network-based worm or virus or other
/// automated attack tools.
///
/// The more easily a vulnerability can be exploited, the higher the
/// vulnerability score.
///
/// # Properties
///
/// - Metric Group: Temporal Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 3.1: Exploit Code Maturity (`E`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v3::{ExploitCodeMaturity, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "E:F".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::ExploitCodeMaturity(ExploitCodeMaturity::Functional));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v3::{ExploitCodeMaturity, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::ExploitCodeMaturity(ExploitCodeMaturity::ProofOfConcept).to_string();
///
/// // check result
/// assert_eq!(s, "E:P");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v3::{ExploitCodeMaturity, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::ExploitCodeMaturity(ExploitCodeMaturity::High));
///
/// // check result
/// assert_eq!(name, Name::ExploitCodeMaturity);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Exploit-Code-Maturity-E
///   "CVSS v3.1 Specification, Section 3.1: Exploit Code Maturity (E)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ExploitCodeMaturity {
  /// Not Defined (`X`)
  ///
  /// Assigning this value indicates there is insufficient information
  /// to choose one of the other values, and has no impact on the overall
  /// Temporal Score, i.e., it has the same effect on scoring as assigning
  /// High.
  NotDefined,

  /// High (`H`)
  ///
  /// Functional autonomous code exists, or no exploit is required
  /// (manual trigger) and details are widely available. Exploit code
  /// works in every situation, or is actively being delivered via an
  /// autonomous agent (such as a worm or virus). Network-connected
  /// systems are likely to encounter scanning or exploitation attempts.
  /// Exploit development has reached the level of reliable, widely
  /// available, easy-to-use automated tools.
  High,

  /// Functional (`F`)
  ///
  /// Functional exploit code is available. The code works in most
  /// situations where the vulnerability exists.
  Functional,

  /// Proof-of-Concept (`P`)
  ///
  /// Proof-of-concept exploit code is available, or an attack
  /// demonstration is not practical for most systems. The code or
  /// technique is not functional in all situations and may require
  /// substantial modification by a skilled attacker.
  ProofOfConcept,

  /// Unproven (`U`)
  ///
  /// No exploit code is available, or an exploit is theoretical.
  Unproven,
}

/// [`Metric::RemediationLevel`][] (`RL`) values.
///
/// # Description
///
/// The Remediation Level of a vulnerability is an important factor for
/// prioritization. The typical vulnerability is unpatched when initially
/// published. Workarounds or hotfixes may offer interim remediation until
/// an official patch or upgrade is issued. Each of these respective
/// stages adjusts the Temporal Score downwards, reflecting the decreasing
/// urgency as remediation becomes final. The list of possible values is
/// presented in Table 10. The less official and permanent a fix, the
/// higher the vulnerability score.
///
/// # Properties
///
/// - Metric Group: Temporal Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 3.2: Remediation Level (`RL`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v3::{RemediationLevel, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "RL:U".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::RemediationLevel(RemediationLevel::Unavailable));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v3::{RemediationLevel, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::RemediationLevel(RemediationLevel::Workaround).to_string();
///
/// // check result
/// assert_eq!(s, "RL:W");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v3::{RemediationLevel, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::RemediationLevel(RemediationLevel::TemporaryFix));
///
/// // check result
/// assert_eq!(name, Name::RemediationLevel);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Remediation-Level-RL
///   "CVSS v3.1 Specification, Section 3.2: Remediation Level (RL)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum RemediationLevel {
  /// Not Defined (`X`)
  ///
  /// Assigning this value indicates there is insufficient information
  /// to choose one of the other values, and has no impact on the overall
  /// Temporal Score, i.e., it has the same effect on scoring as assigning
  /// Unavailable.
  NotDefined,

  /// Unavailable (`U`)
  ///
  /// There is either no solution available or it is impossible to apply.
  Unavailable,

  /// Workaround (`W`)
  ///
  /// There is an unofficial, non-vendor solution available. In some
  /// cases, users of the affected technology will create a patch of their
  /// own or provide steps to work around or otherwise mitigate the
  /// vulnerability.
  Workaround,

  /// Temporary Fix (`T`)
  ///
  /// There is an official but temporary fix available. This includes
  /// instances where the vendor issues a temporary hotfix, tool, or
  /// workaround.
  TemporaryFix,

  /// Official Fix (`O`)
  ///
  /// A complete vendor solution is available. Either the vendor has
  /// issued an official patch, or an upgrade is available.
  OfficialFix,
}

/// [`Metric::ReportConfidence`][] (`RC`) values.
///
/// # Description
///
/// This metric measures the degree of confidence in the existence of
/// the vulnerability and the credibility of the known technical details.
/// Sometimes only the existence of vulnerabilities is publicized, but
/// without specific details. For example, an impact may be recognized as
/// undesirable, but the root cause may not be known. The vulnerability
/// may later be corroborated by research which suggests where the
/// vulnerability may lie, though the research may not be certain.
/// Finally, a vulnerability may be confirmed through acknowledgment by
/// the author or vendor of the affected technology. The urgency of a
/// vulnerability is higher when a vulnerability is known to exist with
/// certainty. This metric also suggests the level of technical knowledge
/// available to would-be attackers. The more a vulnerability is
/// validated by the vendor or other reputable sources, the higher the
/// score.
///
/// # Properties
///
/// - Metric Group: Temporal Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 3.3: Report Confidence (`RC`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v3::{ReportConfidence, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "RC:C".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::ReportConfidence(ReportConfidence::Confirmed));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v3::{ReportConfidence, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::ReportConfidence(ReportConfidence::Reasonable).to_string();
///
/// // check result
/// assert_eq!(s, "RC:R");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v3::{ReportConfidence, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::ReportConfidence(ReportConfidence::Unknown));
///
/// // check result
/// assert_eq!(name, Name::ReportConfidence);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Report-Confidence-RC
///   "CVSS v3.1 Specification, Section 3.3: Report Confidence (RC)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ReportConfidence {
  /// Not Defined (`X`)
  ///
  /// Assigning this value indicates there is insufficient information
  /// to choose one of the other values, and has no impact on the overall
  /// Temporal Score, i.e., it has the same effect on scoring as assigning
  /// Confirmed.
  NotDefined,

  /// Confirmed (`C`)
  ///
  /// Detailed reports exist, or functional reproduction is possible
  /// (functional exploits may provide this). Source code is available to
  /// independently verify the assertions of the research, or the author
  /// or vendor of the affected code has confirmed the presence of the
  /// vulnerability.
  Confirmed,

  /// Reasonable (`R`)
  ///
  /// Significant details are published, but researchers either do not
  /// have full confidence in the root cause, or do not have access to
  /// source code to fully confirm all of the interactions that may lead
  /// to the result. Reasonable confidence exists, however, that the bug
  /// is reproducible and at least one impact is able to be verified
  /// (proof-of-concept exploits may provide this). An example is a
  /// detailed write-up of research into a vulnerability with an
  /// explanation (possibly obfuscated or “left as an exercise to the
  /// reader”) that gives assurances on how to reproduce the results.
  Reasonable,

  /// Unknown (`U`)
  ///
  /// There are reports of impacts that indicate a vulnerability is
  /// present. The reports indicate that the cause of the vulnerability is
  /// unknown, or reports may differ on the cause or impacts of the
  /// vulnerability. Reporters are uncertain of the true nature of the
  /// vulnerability, and there is little confidence in the validity of the
  /// reports or whether a static Base Score can be applied given the
  /// differences described. An example is a bug report which notes that
  /// an intermittent but non-reproducible crash occurs, with evidence of
  /// memory corruption suggesting that denial of service, or possible
  /// more serious impacts, may result.
  Unknown,
}

/// Requirement metric (`CR`, `IR`, `AR`) values.
///
/// # Description
///
/// These metrics enable the analyst to customize the CVSS score
/// depending on the importance of the affected IT asset to a user’s
/// organization, measured in terms of Confidentiality, Integrity, and
/// Availability. That is, if an IT asset supports a business function for
/// which Availability is most important, the analyst can assign a greater
/// value to Availability relative to Confidentiality and Integrity. Each
/// Security Requirement has three possible values: Low, Medium, or High.
///
/// The full effect on the environmental score is determined by the
/// corresponding Modified Base Impact metrics. That is, these metrics
/// modify the environmental score by reweighting the Modified
/// Confidentiality, Integrity, and Availability impact metrics. For
/// example, the Modified Confidentiality impact (MC) metric has increased
/// weight if the Confidentiality Requirement (CR) is High. Likewise, the
/// Modified Confidentiality impact metric has decreased weight if the
/// Confidentiality Requirement is Low. The Modified Confidentiality
/// impact metric weighting is neutral if the Confidentiality Requirement
/// is Medium. This same process is applied to the Integrity and
/// Availability requirements.
///
/// Note that the Confidentiality Requirement will not affect the
/// Environmental score if the (Modified Base) confidentiality impact is
/// set to None. Also, increasing the Confidentiality Requirement from
/// Medium to High will not change the Environmental score when the
/// (Modified Base) impact metrics are set to High. This is because the
/// Modified Impact Sub-Score (part of the Modified Base Score that
/// calculates impact) is already at a maximum value of 10.
///
/// # Metrics
///
/// - `CR`: [`Metric::ConfidentialityRequirement`][]
/// - `IR`: [`Metric::IntegrityRequirement`][]
/// - `AR`: [`Metric::AvailabilityRequirement`][]
///
/// # Properties
///
/// - Metric Group: Environmental Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 4.1: Security Requirements][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Security-Requirements
///   "CVSS v3.1 Specification, Section 4.1: Security Requirements"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum Requirement {
  /// Not Defined (`X`)
  ///
  /// Assigning this value indicates there is insufficient information
  /// to choose one of the other values, and has no impact on the overall
  /// Environmental Score, i.e., it has the same effect on scoring as
  /// assigning Medium.
  NotDefined,

  /// Low (`L`)
  ///
  /// Loss of [Confidentiality | Integrity | Availability] is likely to
  /// have a catastrophic adverse effect on the organization or
  /// individuals associated with the organization (e.g., employees,
  /// customers).
  Low,

  /// Medium (`M`)
  ///
  /// Loss of [Confidentiality | Integrity | Availability] is likely to
  /// have a serious adverse effect on the organization or individuals
  /// associated with the organization (e.g., employees, customers).
  Medium,

  /// High (`H`)
  ///
  /// Loss of [Confidentiality | Integrity | Availability] is likely to
  /// have a catastrophic adverse effect on the organization or
  /// individuals associated with the organization (e.g., employees,
  /// customers).
  High,
}

/// [`Metric`][] component.
///
/// # Examples
///
/// Parse string as metric and check it:
///
/// ```
/// # use polycvss::{Err, v3::{AttackVector, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "AV:N".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::AttackVector(AttackVector::Network));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v3::{AttackVector, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::AttackVector(AttackVector::Adjacent).to_string();
///
/// // check result
/// assert_eq!(s, "AV:A");
/// # }
/// ```
///
/// Get metric name
///
/// ```
/// # use polycvss::v3::{AttackVector, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AttackVector(AttackVector::Local));
///
/// // check result
/// assert_eq!(name, Name::AttackVector);
/// # }
/// ```
#[derive(Clone,Copy,Debug,PartialEq)]
pub enum Metric {
  /// [`Metric::AttackVector`][] (`AV`) metric.
  ///
  /// # Description
  ///
  /// This metric reflects the context by which vulnerability exploitation
  /// is possible. This metric value (and consequently the Base Score) will
  /// be larger the more remote (logically, and physically) an attacker can
  /// be in order to exploit the vulnerable component. The assumption is
  /// that the number of potential attackers for a vulnerability that could
  /// be exploited from across a network is larger than the number of
  /// potential attackers that could exploit a vulnerability requiring
  /// physical access to a device, and therefore warrants a greater Base
  /// Score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 2.1.1: Attack Vector (`AV`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric and check it:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{AttackVector, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "AV:N".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::AttackVector(AttackVector::Network));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v3::{AttackVector, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::AttackVector(AttackVector::Adjacent).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "AV:A");
  /// # }
  /// ```
  ///
  /// Get metric name
  ///
  /// ```
  /// # use polycvss::v3::{AttackVector, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::AttackVector(AttackVector::Local));
  ///
  /// // check result
  /// assert_eq!(name, Name::AttackVector);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Attack-Vector-AV
  ///   "CVSS v3.1 Specification, Section 2.1.1: Attack Vector (AV)"
  AttackVector(AttackVector),

  /// [`Metric::ModifiedAttackVector`][] (`MAV`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::AttackVector`][]
  /// (`AV`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  AttackComplexity(AttackComplexity),

  /// [`Metric::PrivilegesRequired`][] (`PR`) metric.
  ///
  /// # Description
  ///
  /// This metric describes the level of privileges an attacker must
  /// possess before successfully exploiting the vulnerability. The Base
  /// Score is greatest if no privileges are required.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base Metrics
  /// - Base Metric Set: Exploitability Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 2.1.3: Privileges Required (`PR`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{PrivilegesRequired, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "PR:N".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::PrivilegesRequired(PrivilegesRequired::None));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v3::{PrivilegesRequired, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::PrivilegesRequired(PrivilegesRequired::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "PR:L");
  /// # }
  /// ```
  ///
  /// Get metric name
  ///
  /// ```
  /// # use polycvss::v3::{PrivilegesRequired, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::PrivilegesRequired(PrivilegesRequired::High));
  ///
  /// // check result
  /// assert_eq!(name, Name::PrivilegesRequired);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Privileges-Required-PR
  ///   "CVSS v3.1 Specification, Section 2.1.3: Privileges Required (PR)"
  PrivilegesRequired(PrivilegesRequired),

  /// [`Metric::UserInteraction`][] (`UI`) metric.
  ///
  /// # Description
  ///
  /// This metric captures the requirement for a human user, other than
  /// the attacker, to participate in the successful compromise of the
  /// vulnerable component. This metric determines whether the vulnerability
  /// can be exploited solely at the will of the attacker, or whether a
  /// separate user (or user-initiated process) must participate in some
  /// manner. The Base Score is greatest when no user interaction is
  /// required.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base Metrics
  /// - Base Metric Set: Exploitability Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 2.1.4: User Interaction (`UI`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{UserInteraction, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "UI:N".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::UserInteraction(UserInteraction::None));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v3::{UserInteraction, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::UserInteraction(UserInteraction::Required).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "UI:R");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v3::{UserInteraction, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::UserInteraction(UserInteraction::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::UserInteraction);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#User-Interaction-UI
  ///   "CVSS v3.1 Specification, Section 2.1.4: User Interaction (UI)"
  UserInteraction(UserInteraction),

  /// [`Metric::Scope`][] (`S`) metric.
  ///
  /// # Description
  ///
  /// The Scope metric captures whether a vulnerability in one vulnerable
  /// component impacts resources in components beyond its security scope.
  ///
  /// Formally, a security authority is a mechanism (e.g., an application,
  /// an operating system, firmware, a sandbox environment) that defines and
  /// enforces access control in terms of how certain subjects/actors (e.g.,
  /// human users, processes) can access certain restricted
  /// objects/resources (e.g., files, CPU, memory) in a controlled manner.
  /// All the subjects and objects under the jurisdiction of a single
  /// security authority are considered to be under one security scope. If a
  /// vulnerability in a vulnerable component can affect a component which
  /// is in a different security scope than the vulnerable component, a
  /// Scope change occurs. Intuitively, whenever the impact of a
  /// vulnerability breaches a security/trust boundary and impacts
  /// components outside the security scope in which vulnerable component
  /// resides, a Scope change occurs.
  ///
  /// The security scope of a component encompasses other components that
  /// provide functionality solely to that component, even if these other
  /// components have their own security authority. For example, a database
  /// used solely by one application is considered part of that
  /// application’s security scope even if the database has its own security
  /// authority, e.g., a mechanism controlling access to database records
  /// based on database users and associated database privileges.
  ///
  /// The Base Score is greatest when a scope change occurs.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 2.2: Scope (`S`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{Scope, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "S:U".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Scope(Scope::Unchanged));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v3::{Scope, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Scope(Scope::Changed).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "S:C");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v3::{Scope, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Scope(Scope::Changed));
  ///
  /// // check result
  /// assert_eq!(name, Name::Scope);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Scope-S
  ///   "CVSS v3.1 Specification, Section 2.2: Scope (S)"
  Scope(Scope),

  /// Confidencialy (`C`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the impact to the confidentiality of the
  /// information resources managed by a software component due to a
  /// successfully exploited vulnerability. Confidentiality refers to
  /// limiting information access and disclosure to only authorized users,
  /// as well as preventing access by, or disclosure to, unauthorized
  /// ones. The Base Score is greatest when the loss to the impacted
  /// component is highest.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base Metrics
  /// - Base Metric Set: Impact Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 2.3.1: Confidentiality (`C`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "C:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Confidentiality(Impact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v3::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Confidentiality(Impact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "C:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v3::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Confidentiality(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::Confidentiality);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#2-3-1-Confidentiality-C
  ///   "CVSS v3.1 Specification, Section 2.3.1: Confidentiality (C)"
  Confidentiality(Impact),

  /// Integrity (`I`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the impact to integrity of a successfully
  /// exploited vulnerability. Integrity refers to the trustworthiness and
  /// veracity of information. The Base Score is greatest when the
  /// consequence to the impacted component is highest.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base Metrics
  /// - Base Metric Set: Impact Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 2.3.2: Integrity (`I`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "I:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Integrity(Impact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v3::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Integrity(Impact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "I:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v3::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Integrity(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::Integrity);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#2-3-2-Integrity-I
  ///   "CVSS v3.1 Specification, Section 2.3.2: Integrity (I)"
  Integrity(Impact),

  /// Availability (`A`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the impact to the availability of the
  /// impacted component resulting from a successfully exploited
  /// vulnerability. While the Confidentiality and Integrity impact
  /// metrics apply to the loss of confidentiality or integrity of data
  /// (e.g., information, files) used by the impacted component, this
  /// metric refers to the loss of availability of the impacted component
  /// itself, such as a networked service (e.g., web, database, email).
  /// Since availability refers to the accessibility of information
  /// resources, attacks that consume network bandwidth, processor cycles,
  /// or disk space all impact the availability of an impacted component.
  /// The Base Score is greatest when the consequence to the impacted
  /// component is highest.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base Metrics
  /// - Base Metric Set: Impact Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 2.3.3: Availability (`A`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "A:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Availability(Impact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v3::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Availability(Impact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "A:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v3::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Availability(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::Availability);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#2-3-3-Availability-A
  ///   "CVSS v3.1 Specification, Section 2.3.3: Availability (A)"
  Availability(Impact),

  /// Exploit Code Maturity (`E`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the likelihood of the vulnerability being
  /// attacked, and is typically based on the current state of exploit
  /// techniques, exploit code availability, or active, “in-the-wild”
  /// exploitation. Public availability of easy-to-use exploit code
  /// increases the number of potential attackers by including those who are
  /// unskilled, thereby increasing the severity of the vulnerability.
  /// Initially, real-world exploitation may only be theoretical.
  /// Publication of proof-of-concept code, functional exploit code, or
  /// sufficient technical details necessary to exploit the vulnerability
  /// may follow. Furthermore, the exploit code available may progress from
  /// a proof-of-concept demonstration to exploit code that is successful in
  /// exploiting the vulnerability consistently. In severe cases, it may be
  /// delivered as the payload of a network-based worm or virus or other
  /// automated attack tools.
  ///
  /// The more easily a vulnerability can be exploited, the higher the
  /// vulnerability score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Temporal Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 3.1: Exploit Code Maturity (`E`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{ExploitCodeMaturity, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "E:F".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ExploitCodeMaturity(ExploitCodeMaturity::Functional));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v3::{ExploitCodeMaturity, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ExploitCodeMaturity(ExploitCodeMaturity::ProofOfConcept).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "E:P");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v3::{ExploitCodeMaturity, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ExploitCodeMaturity(ExploitCodeMaturity::High));
  ///
  /// // check result
  /// assert_eq!(name, Name::ExploitCodeMaturity);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#3-1-Exploit-Code-Maturity-E
  ///   "CVSS v3.1 Specification, Section 3.1: Exploit Code Maturity (E)"
  ExploitCodeMaturity(ExploitCodeMaturity),

  /// Remediation Level (`RL`) metric.
  ///
  /// # Description
  ///
  /// The Remediation Level of a vulnerability is an important factor for
  /// prioritization. The typical vulnerability is unpatched when initially
  /// published. Workarounds or hotfixes may offer interim remediation until
  /// an official patch or upgrade is issued. Each of these respective
  /// stages adjusts the Temporal Score downwards, reflecting the decreasing
  /// urgency as remediation becomes final. The list of possible values is
  /// presented in Table 10. The less official and permanent a fix, the
  /// higher the vulnerability score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Temporal Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 3.2: Remediation Level (`RL`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{RemediationLevel, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "RL:U".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::RemediationLevel(RemediationLevel::Unavailable));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v3::{RemediationLevel, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::RemediationLevel(RemediationLevel::Workaround).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "RL:W");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v3::{RemediationLevel, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::RemediationLevel(RemediationLevel::TemporaryFix));
  ///
  /// // check result
  /// assert_eq!(name, Name::RemediationLevel);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Remediation-Level-RL
  ///   "CVSS v3.1 Specification, Section 3.2: Remediation Level (RL)"
  RemediationLevel(RemediationLevel),

  /// Report Confidence (`RC`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the degree of confidence in the existence of
  /// the vulnerability and the credibility of the known technical details.
  /// Sometimes only the existence of vulnerabilities is publicized, but
  /// without specific details. For example, an impact may be recognized as
  /// undesirable, but the root cause may not be known. The vulnerability
  /// may later be corroborated by research which suggests where the
  /// vulnerability may lie, though the research may not be certain.
  /// Finally, a vulnerability may be confirmed through acknowledgment by
  /// the author or vendor of the affected technology. The urgency of a
  /// vulnerability is higher when a vulnerability is known to exist with
  /// certainty. This metric also suggests the level of technical knowledge
  /// available to would-be attackers. The more a vulnerability is
  /// validated by the vendor or other reputable sources, the higher the
  /// score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Temporal Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 3.3: Report Confidence (`RC`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{ReportConfidence, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "RC:C".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ReportConfidence(ReportConfidence::Confirmed));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v3::{ReportConfidence, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ReportConfidence(ReportConfidence::Reasonable).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "RC:R");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v3::{ReportConfidence, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ReportConfidence(ReportConfidence::Unknown));
  ///
  /// // check result
  /// assert_eq!(name, Name::ReportConfidence);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Report-Confidence-RC
  ///   "CVSS v3.1 Specification, Section 3.3: Report Confidence (RC)"
  ReportConfidence(ReportConfidence),

  /// Confidentiality Requirement (`CR`) metric.
  ///
  /// # Description
  ///
  /// These metrics enable the analyst to customize the CVSS score
  /// depending on the importance of the affected IT asset to a user’s
  /// organization, measured in terms of Confidentiality, Integrity, and
  /// Availability. That is, if an IT asset supports a business function for
  /// which Availability is most important, the analyst can assign a greater
  /// value to Availability relative to Confidentiality and Integrity. Each
  /// Security Requirement has three possible values: Low, Medium, or High.
  ///
  /// The full effect on the environmental score is determined by the
  /// corresponding Modified Base Impact metrics. That is, these metrics
  /// modify the environmental score by reweighting the Modified
  /// Confidentiality, Integrity, and Availability impact metrics. For
  /// example, the Modified Confidentiality impact (MC) metric has increased
  /// weight if the Confidentiality Requirement (CR) is High. Likewise, the
  /// Modified Confidentiality impact metric has decreased weight if the
  /// Confidentiality Requirement is Low. The Modified Confidentiality
  /// impact metric weighting is neutral if the Confidentiality Requirement
  /// is Medium. This same process is applied to the Integrity and
  /// Availability requirements.
  ///
  /// Note that the Confidentiality Requirement will not affect the
  /// Environmental score if the (Modified Base) confidentiality impact is
  /// set to None. Also, increasing the Confidentiality Requirement from
  /// Medium to High will not change the Environmental score when the
  /// (Modified Base) impact metrics are set to High. This is because the
  /// Modified Impact Sub-Score (part of the Modified Base Score that
  /// calculates impact) is already at a maximum value of 10.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.1: Security Requirements][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#4-1-Security-Requirements
  ///   "CVSS v3.1 Specification, Section 4.1: Security Requirements"
  ConfidentialityRequirement(Requirement),

  /// Integrity Requirement (`IR`) metric.
  ///
  /// # Description
  ///
  /// These metrics enable the analyst to customize the CVSS score
  /// depending on the importance of the affected IT asset to a user’s
  /// organization, measured in terms of Confidentiality, Integrity, and
  /// Availability. That is, if an IT asset supports a business function for
  /// which Availability is most important, the analyst can assign a greater
  /// value to Availability relative to Confidentiality and Integrity. Each
  /// Security Requirement has three possible values: Low, Medium, or High.
  ///
  /// The full effect on the environmental score is determined by the
  /// corresponding Modified Base Impact metrics. That is, these metrics
  /// modify the environmental score by reweighting the Modified
  /// Confidentiality, Integrity, and Availability impact metrics. For
  /// example, the Modified Confidentiality impact (MC) metric has increased
  /// weight if the Confidentiality Requirement (CR) is High. Likewise, the
  /// Modified Confidentiality impact metric has decreased weight if the
  /// Confidentiality Requirement is Low. The Modified Confidentiality
  /// impact metric weighting is neutral if the Confidentiality Requirement
  /// is Medium. This same process is applied to the Integrity and
  /// Availability requirements.
  ///
  /// Note that the Confidentiality Requirement will not affect the
  /// Environmental score if the (Modified Base) confidentiality impact is
  /// set to None. Also, increasing the Confidentiality Requirement from
  /// Medium to High will not change the Environmental score when the
  /// (Modified Base) impact metrics are set to High. This is because the
  /// Modified Impact Sub-Score (part of the Modified Base Score that
  /// calculates impact) is already at a maximum value of 10.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.1: Security Requirements][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#4-1-Security-Requirements
  ///   "CVSS v3.1 Specification, Section 4.1: Security Requirements"
  IntegrityRequirement(Requirement),

  /// Availability Requirement (`AR`) metric.
  ///
  /// # Description
  ///
  /// These metrics enable the analyst to customize the CVSS score
  /// depending on the importance of the affected IT asset to a user’s
  /// organization, measured in terms of Confidentiality, Integrity, and
  /// Availability. That is, if an IT asset supports a business function for
  /// which Availability is most important, the analyst can assign a greater
  /// value to Availability relative to Confidentiality and Integrity. Each
  /// Security Requirement has three possible values: Low, Medium, or High.
  ///
  /// The full effect on the environmental score is determined by the
  /// corresponding Modified Base Impact metrics. That is, these metrics
  /// modify the environmental score by reweighting the Modified
  /// Confidentiality, Integrity, and Availability impact metrics. For
  /// example, the Modified Confidentiality impact (MC) metric has increased
  /// weight if the Confidentiality Requirement (CR) is High. Likewise, the
  /// Modified Confidentiality impact metric has decreased weight if the
  /// Confidentiality Requirement is Low. The Modified Confidentiality
  /// impact metric weighting is neutral if the Confidentiality Requirement
  /// is Medium. This same process is applied to the Integrity and
  /// Availability requirements.
  ///
  /// Note that the Confidentiality Requirement will not affect the
  /// Environmental score if the (Modified Base) confidentiality impact is
  /// set to None. Also, increasing the Confidentiality Requirement from
  /// Medium to High will not change the Environmental score when the
  /// (Modified Base) impact metrics are set to High. This is because the
  /// Modified Impact Sub-Score (part of the Modified Base Score that
  /// calculates impact) is already at a maximum value of 10.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.1: Security Requirements][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#4-1-Security-Requirements
  ///   "CVSS v3.1 Specification, Section 4.1: Security Requirements"
  AvailabilityRequirement(Requirement),

  /// Modified Attack Vector (`MAV`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::AttackVector`][]
  /// (`AV`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedAttackVector(ModifiedAttackVector),

  /// Modified Attack Complexity (`MAC`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::AttackComplexity`][]
  /// (`AC`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedAttackComplexity(ModifiedAttackComplexity),

  /// Modified Privileges Required (`MPR`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::PrivilegesRequired`][]
  /// (`PR`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedPrivilegesRequired(ModifiedPrivilegesRequired),

  /// Modified User Interaction (`MUI`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::UserInteraction`][]
  /// (`UI`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedUserInteraction(ModifiedUserInteraction),

  /// Modified Scope (`MS`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::Scope`][]
  /// (`S`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedScope(ModifiedScope),

  /// Modified Confidentiality (`MC`) metric.
  ///
  /// # Description
  ///
  /// Overrides the base [`Metric::Confidentiality`][] (`C`) metric.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedConfidentiality(ModifiedImpact),

  /// Modified Integrity (`MI`) metric.
  ///
  /// # Description
  ///
  /// Overrides the base [`Metric::Integrity`][] (`I`) metric.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedIntegrity(ModifiedImpact),

  /// Modified Availability (`MA`) metric.
  ///
  /// # Description
  ///
  /// Overrides the base [`Metric::Availability`][] (`A`) metric.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental Metrics
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedAvailability(ModifiedImpact),
}

impl std::str::FromStr for Metric {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "AV:N" => Ok(Metric::AttackVector(AttackVector::Network)),
      "AV:A" => Ok(Metric::AttackVector(AttackVector::Adjacent)),
      "AV:L" => Ok(Metric::AttackVector(AttackVector::Local)),
      "AV:P" => Ok(Metric::AttackVector(AttackVector::Physical)),

      "AC:L" => Ok(Metric::AttackComplexity(AttackComplexity::Low)),
      "AC:H" => Ok(Metric::AttackComplexity(AttackComplexity::High)),

      "PR:N" => Ok(Metric::PrivilegesRequired(PrivilegesRequired::None)),
      "PR:L" => Ok(Metric::PrivilegesRequired(PrivilegesRequired::Low)),
      "PR:H" => Ok(Metric::PrivilegesRequired(PrivilegesRequired::High)),

      "UI:N" => Ok(Metric::UserInteraction(UserInteraction::None)),
      "UI:R" => Ok(Metric::UserInteraction(UserInteraction::Required)),

      "S:U" => Ok(Metric::Scope(Scope::Unchanged)),
      "S:C" => Ok(Metric::Scope(Scope::Changed)),

      "C:H" => Ok(Metric::Confidentiality(Impact::High)),
      "C:L" => Ok(Metric::Confidentiality(Impact::Low)),
      "C:N" => Ok(Metric::Confidentiality(Impact::None)),

      "I:H" => Ok(Metric::Integrity(Impact::High)),
      "I:L" => Ok(Metric::Integrity(Impact::Low)),
      "I:N" => Ok(Metric::Integrity(Impact::None)),

      "A:H" => Ok(Metric::Availability(Impact::High)),
      "A:L" => Ok(Metric::Availability(Impact::Low)),
      "A:N" => Ok(Metric::Availability(Impact::None)),

      "E:X" => Ok(Metric::ExploitCodeMaturity(ExploitCodeMaturity::NotDefined)),
      "E:H" => Ok(Metric::ExploitCodeMaturity(ExploitCodeMaturity::High)),
      "E:F" => Ok(Metric::ExploitCodeMaturity(ExploitCodeMaturity::Functional)),
      "E:P" => Ok(Metric::ExploitCodeMaturity(ExploitCodeMaturity::ProofOfConcept)),
      "E:U" => Ok(Metric::ExploitCodeMaturity(ExploitCodeMaturity::Unproven)),

      "RL:X" => Ok(Metric::RemediationLevel(RemediationLevel::NotDefined)),
      "RL:U" => Ok(Metric::RemediationLevel(RemediationLevel::Unavailable)),
      "RL:W" => Ok(Metric::RemediationLevel(RemediationLevel::Workaround)),
      "RL:T" => Ok(Metric::RemediationLevel(RemediationLevel::TemporaryFix)),
      "RL:O" => Ok(Metric::RemediationLevel(RemediationLevel::OfficialFix)),

      "RC:X" => Ok(Metric::ReportConfidence(ReportConfidence::NotDefined)),
      "RC:C" => Ok(Metric::ReportConfidence(ReportConfidence::Confirmed)),
      "RC:R" => Ok(Metric::ReportConfidence(ReportConfidence::Reasonable)),
      "RC:U" => Ok(Metric::ReportConfidence(ReportConfidence::Unknown)),

      "CR:X" => Ok(Metric::ConfidentialityRequirement(Requirement::NotDefined)),
      "CR:H" => Ok(Metric::ConfidentialityRequirement(Requirement::High)),
      "CR:M" => Ok(Metric::ConfidentialityRequirement(Requirement::Medium)),
      "CR:L" => Ok(Metric::ConfidentialityRequirement(Requirement::Low)),

      "IR:X" => Ok(Metric::IntegrityRequirement(Requirement::NotDefined)),
      "IR:H" => Ok(Metric::IntegrityRequirement(Requirement::High)),
      "IR:M" => Ok(Metric::IntegrityRequirement(Requirement::Medium)),
      "IR:L" => Ok(Metric::IntegrityRequirement(Requirement::Low)),

      "AR:X" => Ok(Metric::AvailabilityRequirement(Requirement::NotDefined)),
      "AR:H" => Ok(Metric::AvailabilityRequirement(Requirement::High)),
      "AR:M" => Ok(Metric::AvailabilityRequirement(Requirement::Medium)),
      "AR:L" => Ok(Metric::AvailabilityRequirement(Requirement::Low)),

      "MAV:X" => Ok(Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined)),
      "MAV:N" => Ok(Metric::ModifiedAttackVector(ModifiedAttackVector::Network)),
      "MAV:A" => Ok(Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent)),
      "MAV:L" => Ok(Metric::ModifiedAttackVector(ModifiedAttackVector::Local)),
      "MAV:P" => Ok(Metric::ModifiedAttackVector(ModifiedAttackVector::Physical)),

      "MAC:X" => Ok(Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined)),
      "MAC:L" => Ok(Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low)),
      "MAC:H" => Ok(Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High)),

      "MPR:X" => Ok(Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined)),
      "MPR:N" => Ok(Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None)),
      "MPR:L" => Ok(Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low)),
      "MPR:H" => Ok(Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High)),

      "MUI:X" => Ok(Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined)),
      "MUI:N" => Ok(Metric::ModifiedUserInteraction(ModifiedUserInteraction::None)),
      "MUI:R" => Ok(Metric::ModifiedUserInteraction(ModifiedUserInteraction::Required)),

      "MS:X" => Ok(Metric::ModifiedScope(ModifiedScope::NotDefined)),
      "MS:U" => Ok(Metric::ModifiedScope(ModifiedScope::Unchanged)),
      "MS:C" => Ok(Metric::ModifiedScope(ModifiedScope::Changed)),

      "MC:X" => Ok(Metric::ModifiedConfidentiality(ModifiedImpact::NotDefined)),
      "MC:N" => Ok(Metric::ModifiedConfidentiality(ModifiedImpact::None)),
      "MC:L" => Ok(Metric::ModifiedConfidentiality(ModifiedImpact::Low)),
      "MC:H" => Ok(Metric::ModifiedConfidentiality(ModifiedImpact::High)),

      "MI:X" => Ok(Metric::ModifiedIntegrity(ModifiedImpact::NotDefined)),
      "MI:N" => Ok(Metric::ModifiedIntegrity(ModifiedImpact::None)),
      "MI:L" => Ok(Metric::ModifiedIntegrity(ModifiedImpact::Low)),
      "MI:H" => Ok(Metric::ModifiedIntegrity(ModifiedImpact::High)),

      "MA:X" => Ok(Metric::ModifiedAvailability(ModifiedImpact::NotDefined)),
      "MA:N" => Ok(Metric::ModifiedAvailability(ModifiedImpact::None)),
      "MA:L" => Ok(Metric::ModifiedAvailability(ModifiedImpact::Low)),
      "MA:H" => Ok(Metric::ModifiedAvailability(ModifiedImpact::High)),

      _ => Err(Err::UnknownMetric),
    }
  }
}

impl TryFrom<String> for Metric {
  type Error = Err;

  fn try_from(s: String) -> Result<Self, Self::Error> {
    s.parse::<Metric>()
  }
}

impl std::fmt::Display for Metric {
  // Format CVSS v3 metric as a string.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{}", match self {
      Metric::AttackVector(AttackVector::Network) => "AV:N",
      Metric::AttackVector(AttackVector::Adjacent) => "AV:A",
      Metric::AttackVector(AttackVector::Local) => "AV:L",
      Metric::AttackVector(AttackVector::Physical) => "AV:P",

      Metric::AttackComplexity(AttackComplexity::Low) => "AC:L",
      Metric::AttackComplexity(AttackComplexity::High) => "AC:H",

      Metric::PrivilegesRequired(PrivilegesRequired::None) => "PR:N",
      Metric::PrivilegesRequired(PrivilegesRequired::Low) => "PR:L",
      Metric::PrivilegesRequired(PrivilegesRequired::High) => "PR:H",

      Metric::UserInteraction(UserInteraction::None) => "UI:N",
      Metric::UserInteraction(UserInteraction::Required) => "UI:R",

      Metric::Scope(Scope::Unchanged) => "S:U",
      Metric::Scope(Scope::Changed) => "S:C",

      Metric::Confidentiality(Impact::High) => "C:H",
      Metric::Confidentiality(Impact::Low) => "C:L",
      Metric::Confidentiality(Impact::None) => "C:N",

      Metric::Integrity(Impact::High) => "I:H",
      Metric::Integrity(Impact::Low) => "I:L",
      Metric::Integrity(Impact::None) => "I:N",

      Metric::Availability(Impact::High) => "A:H",
      Metric::Availability(Impact::Low) => "A:L",
      Metric::Availability(Impact::None) => "A:N",

      Metric::ExploitCodeMaturity(ExploitCodeMaturity::NotDefined) => "E:X",
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::High) => "E:H",
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::Functional) => "E:F",
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::ProofOfConcept) => "E:P",
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::Unproven) => "E:U",

      Metric::RemediationLevel(RemediationLevel::NotDefined) => "RL:X",
      Metric::RemediationLevel(RemediationLevel::Unavailable) => "RL:U",
      Metric::RemediationLevel(RemediationLevel::Workaround) => "RL:W",
      Metric::RemediationLevel(RemediationLevel::TemporaryFix) => "RL:T",
      Metric::RemediationLevel(RemediationLevel::OfficialFix) => "RL:O",

      Metric::ReportConfidence(ReportConfidence::NotDefined) => "RC:X",
      Metric::ReportConfidence(ReportConfidence::Confirmed) => "RC:C",
      Metric::ReportConfidence(ReportConfidence::Reasonable) => "RC:R",
      Metric::ReportConfidence(ReportConfidence::Unknown) => "RC:U",

      Metric::ConfidentialityRequirement(Requirement::NotDefined) => "CR:X",
      Metric::ConfidentialityRequirement(Requirement::High) => "CR:H",
      Metric::ConfidentialityRequirement(Requirement::Medium) => "CR:M",
      Metric::ConfidentialityRequirement(Requirement::Low) => "CR:L",

      Metric::IntegrityRequirement(Requirement::NotDefined) => "IR:X",
      Metric::IntegrityRequirement(Requirement::High) => "IR:H",
      Metric::IntegrityRequirement(Requirement::Medium) => "IR:M",
      Metric::IntegrityRequirement(Requirement::Low) => "IR:L",

      Metric::AvailabilityRequirement(Requirement::NotDefined) => "AR:X",
      Metric::AvailabilityRequirement(Requirement::High) => "AR:H",
      Metric::AvailabilityRequirement(Requirement::Medium) => "AR:M",
      Metric::AvailabilityRequirement(Requirement::Low) => "AR:L",

      Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined) => "MAV:X",
      Metric::ModifiedAttackVector(ModifiedAttackVector::Network) => "MAV:N",
      Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent) => "MAV:A",
      Metric::ModifiedAttackVector(ModifiedAttackVector::Local) => "MAV:L",
      Metric::ModifiedAttackVector(ModifiedAttackVector::Physical) => "MAV:P",

      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined) => "MAC:X",
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low) => "MAC:L",
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High) => "MAC:H",

      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined) => "MPR:X",
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None) => "MPR:N",
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low) => "MPR:L",
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High) => "MPR:H",

      Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined) => "MUI:X",
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::None) => "MUI:N",
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::Required) => "MUI:R",

      Metric::ModifiedScope(ModifiedScope::NotDefined) => "MS:X",
      Metric::ModifiedScope(ModifiedScope::Unchanged) => "MS:U",
      Metric::ModifiedScope(ModifiedScope::Changed) => "MS:C",

      Metric::ModifiedConfidentiality(ModifiedImpact::NotDefined) => "MC:X",
      Metric::ModifiedConfidentiality(ModifiedImpact::None) => "MC:N",
      Metric::ModifiedConfidentiality(ModifiedImpact::Low) => "MC:L",
      Metric::ModifiedConfidentiality(ModifiedImpact::High) => "MC:H",

      Metric::ModifiedIntegrity(ModifiedImpact::NotDefined) => "MI:X",
      Metric::ModifiedIntegrity(ModifiedImpact::None) => "MI:N",
      Metric::ModifiedIntegrity(ModifiedImpact::Low) => "MI:L",
      Metric::ModifiedIntegrity(ModifiedImpact::High) => "MI:H",

      Metric::ModifiedAvailability(ModifiedImpact::NotDefined) => "MA:X",
      Metric::ModifiedAvailability(ModifiedImpact::None) => "MA:N",
      Metric::ModifiedAvailability(ModifiedImpact::Low) => "MA:L",
      Metric::ModifiedAvailability(ModifiedImpact::High) => "MA:H",
    })
  }
}

impl From<Metric> for EncodedMetric {
  fn from(metric: Metric) -> EncodedMetric {
    let (bit, shift, val) = match metric {
      Metric::AttackVector(AttackVector::Network) => (0, 0, 0),
      Metric::AttackVector(AttackVector::Adjacent) => (0, 0, 1),
      Metric::AttackVector(AttackVector::Local) => (0, 0, 2),
      Metric::AttackVector(AttackVector::Physical) => (0, 0, 3),

      Metric::AttackComplexity(AttackComplexity::Low) => (1, 2, 0),
      Metric::AttackComplexity(AttackComplexity::High) => (1, 2, 1),

      Metric::PrivilegesRequired(PrivilegesRequired::None) => (2, 3, 0),
      Metric::PrivilegesRequired(PrivilegesRequired::Low) => (2, 3, 1),
      Metric::PrivilegesRequired(PrivilegesRequired::High) => (2, 3, 2),

      Metric::UserInteraction(UserInteraction::None) => (3, 5, 0),
      Metric::UserInteraction(UserInteraction::Required) => (3, 5, 1),

      Metric::Scope(Scope::Unchanged) => (4, 6, 0),
      Metric::Scope(Scope::Changed) => (4, 6, 1),

      Metric::Confidentiality(Impact::High) => (5, 7, 0),
      Metric::Confidentiality(Impact::Low) => (5, 7, 1),
      Metric::Confidentiality(Impact::None) => (5, 7, 2),

      Metric::Integrity(Impact::High) => (6, 9, 0),
      Metric::Integrity(Impact::Low) => (6, 9, 1),
      Metric::Integrity(Impact::None) => (6, 9, 2),

      Metric::Availability(Impact::High) => (7, 11, 0),
      Metric::Availability(Impact::Low) => (7, 11, 1),
      Metric::Availability(Impact::None) => (7, 11, 2),

      Metric::ExploitCodeMaturity(ExploitCodeMaturity::NotDefined) => (8, 13, 0),
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::High) => (8, 13, 1),
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::Functional) => (8, 13, 2),
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::ProofOfConcept) => (8, 13, 3),
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::Unproven) => (8, 13, 4),

      Metric::RemediationLevel(RemediationLevel::NotDefined) => (10, 16, 0),
      Metric::RemediationLevel(RemediationLevel::Unavailable) => (10, 16, 1),
      Metric::RemediationLevel(RemediationLevel::Workaround) => (10, 16, 2),
      Metric::RemediationLevel(RemediationLevel::TemporaryFix) => (10, 16, 3),
      Metric::RemediationLevel(RemediationLevel::OfficialFix) => (10, 16, 4),

      Metric::ReportConfidence(ReportConfidence::NotDefined) => (11, 19, 0),
      Metric::ReportConfidence(ReportConfidence::Confirmed) => (11, 19, 1),
      Metric::ReportConfidence(ReportConfidence::Reasonable) => (11, 19, 2),
      Metric::ReportConfidence(ReportConfidence::Unknown) => (11, 19, 3),

      Metric::ConfidentialityRequirement(Requirement::NotDefined) => (12, 21, 0),
      Metric::ConfidentialityRequirement(Requirement::High) => (12, 21, 1),
      Metric::ConfidentialityRequirement(Requirement::Medium) => (12, 21, 2),
      Metric::ConfidentialityRequirement(Requirement::Low) => (12, 21, 3),

      Metric::IntegrityRequirement(Requirement::NotDefined) => (13, 23, 0),
      Metric::IntegrityRequirement(Requirement::High) => (13, 23, 1),
      Metric::IntegrityRequirement(Requirement::Medium) => (13, 23, 2),
      Metric::IntegrityRequirement(Requirement::Low) => (13, 23, 3),

      Metric::AvailabilityRequirement(Requirement::NotDefined) => (14, 25, 0),
      Metric::AvailabilityRequirement(Requirement::High) => (14, 25, 1),
      Metric::AvailabilityRequirement(Requirement::Medium) => (14, 25, 2),
      Metric::AvailabilityRequirement(Requirement::Low) => (14, 25, 3),

      Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined) => (15, 27, 0),
      Metric::ModifiedAttackVector(ModifiedAttackVector::Network) => (15, 27, 1),
      Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent) => (15, 27, 2),
      Metric::ModifiedAttackVector(ModifiedAttackVector::Local) => (15, 27, 3),
      Metric::ModifiedAttackVector(ModifiedAttackVector::Physical) => (15, 27, 4),

      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined) => (16, 30, 0),
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low) => (16, 30, 1),
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High) => (16, 30, 2),

      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined) => (17, 32, 0),
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None) => (17, 32, 1),
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low) => (17, 32, 2),
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High) => (17, 32, 3),

      Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined) => (18, 34, 0),
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::None) => (18, 34, 1),
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::Required) => (18, 34, 2),

      Metric::ModifiedScope(ModifiedScope::NotDefined) => (19, 36, 0),
      Metric::ModifiedScope(ModifiedScope::Unchanged) => (19, 36, 1),
      Metric::ModifiedScope(ModifiedScope::Changed) => (19, 36, 2),

      Metric::ModifiedConfidentiality(ModifiedImpact::NotDefined) => (20, 38, 0),
      Metric::ModifiedConfidentiality(ModifiedImpact::None) => (20, 38, 1),
      Metric::ModifiedConfidentiality(ModifiedImpact::Low) => (20, 38, 2),
      Metric::ModifiedConfidentiality(ModifiedImpact::High) => (20, 38, 3),

      Metric::ModifiedIntegrity(ModifiedImpact::NotDefined) => (21, 40, 0),
      Metric::ModifiedIntegrity(ModifiedImpact::None) => (21, 40, 1),
      Metric::ModifiedIntegrity(ModifiedImpact::Low) => (21, 40, 2),
      Metric::ModifiedIntegrity(ModifiedImpact::High) => (21, 40, 3),

      Metric::ModifiedAvailability(ModifiedImpact::NotDefined) => (22, 42, 0),
      Metric::ModifiedAvailability(ModifiedImpact::None) => (22, 42, 1),
      Metric::ModifiedAvailability(ModifiedImpact::Low) => (22, 42, 2),
      Metric::ModifiedAvailability(ModifiedImpact::High) => (22, 42, 3),
    };

    EncodedMetric { bit: 1 << bit, val: EncodedVal::Shift(val << shift) }
  }
}

// Internal array of metrics.
//
// Used by the following methods to decode metric values from a
// `u64`: `Vector::get()`, `Vector::fmt()`, and
// `VectorIterator::next()`.
const METRICS: [Metric; 78] = [
  Metric::AttackVector(AttackVector::Network),
  Metric::AttackVector(AttackVector::Adjacent),
  Metric::AttackVector(AttackVector::Local),
  Metric::AttackVector(AttackVector::Physical),

  Metric::AttackComplexity(AttackComplexity::Low),
  Metric::AttackComplexity(AttackComplexity::High),

  Metric::PrivilegesRequired(PrivilegesRequired::None),
  Metric::PrivilegesRequired(PrivilegesRequired::Low),
  Metric::PrivilegesRequired(PrivilegesRequired::High),

  Metric::UserInteraction(UserInteraction::None),
  Metric::UserInteraction(UserInteraction::Required),

  Metric::Scope(Scope::Unchanged),
  Metric::Scope(Scope::Changed),

  Metric::Confidentiality(Impact::High),
  Metric::Confidentiality(Impact::Low),
  Metric::Confidentiality(Impact::None),

  Metric::Integrity(Impact::High),
  Metric::Integrity(Impact::Low),
  Metric::Integrity(Impact::None),

  Metric::Availability(Impact::High),
  Metric::Availability(Impact::Low),
  Metric::Availability(Impact::None),

  Metric::ExploitCodeMaturity(ExploitCodeMaturity::NotDefined),
  Metric::ExploitCodeMaturity(ExploitCodeMaturity::High),
  Metric::ExploitCodeMaturity(ExploitCodeMaturity::Functional),
  Metric::ExploitCodeMaturity(ExploitCodeMaturity::ProofOfConcept),
  Metric::ExploitCodeMaturity(ExploitCodeMaturity::Unproven),

  Metric::RemediationLevel(RemediationLevel::NotDefined),
  Metric::RemediationLevel(RemediationLevel::Unavailable),
  Metric::RemediationLevel(RemediationLevel::Workaround),
  Metric::RemediationLevel(RemediationLevel::TemporaryFix),
  Metric::RemediationLevel(RemediationLevel::OfficialFix),

  Metric::ReportConfidence(ReportConfidence::NotDefined),
  Metric::ReportConfidence(ReportConfidence::Confirmed),
  Metric::ReportConfidence(ReportConfidence::Reasonable),
  Metric::ReportConfidence(ReportConfidence::Unknown),

  Metric::ConfidentialityRequirement(Requirement::NotDefined),
  Metric::ConfidentialityRequirement(Requirement::High),
  Metric::ConfidentialityRequirement(Requirement::Medium),
  Metric::ConfidentialityRequirement(Requirement::Low),

  Metric::IntegrityRequirement(Requirement::NotDefined),
  Metric::IntegrityRequirement(Requirement::High),
  Metric::IntegrityRequirement(Requirement::Medium),
  Metric::IntegrityRequirement(Requirement::Low),

  Metric::AvailabilityRequirement(Requirement::NotDefined),
  Metric::AvailabilityRequirement(Requirement::High),
  Metric::AvailabilityRequirement(Requirement::Medium),
  Metric::AvailabilityRequirement(Requirement::Low),

  Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined),
  Metric::ModifiedAttackVector(ModifiedAttackVector::Network),
  Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent),
  Metric::ModifiedAttackVector(ModifiedAttackVector::Local),
  Metric::ModifiedAttackVector(ModifiedAttackVector::Physical),

  Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined),
  Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low),
  Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High),

  Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined),
  Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None),
  Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low),
  Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High),

  Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined),
  Metric::ModifiedUserInteraction(ModifiedUserInteraction::None),
  Metric::ModifiedUserInteraction(ModifiedUserInteraction::Required),

  Metric::ModifiedScope(ModifiedScope::NotDefined),
  Metric::ModifiedScope(ModifiedScope::Unchanged),
  Metric::ModifiedScope(ModifiedScope::Changed),

  Metric::ModifiedConfidentiality(ModifiedImpact::NotDefined),
  Metric::ModifiedConfidentiality(ModifiedImpact::None),
  Metric::ModifiedConfidentiality(ModifiedImpact::Low),
  Metric::ModifiedConfidentiality(ModifiedImpact::High),

  Metric::ModifiedIntegrity(ModifiedImpact::NotDefined),
  Metric::ModifiedIntegrity(ModifiedImpact::None),
  Metric::ModifiedIntegrity(ModifiedImpact::Low),
  Metric::ModifiedIntegrity(ModifiedImpact::High),

  Metric::ModifiedAvailability(ModifiedImpact::NotDefined),
  Metric::ModifiedAvailability(ModifiedImpact::None),
  Metric::ModifiedAvailability(ModifiedImpact::Low),
  Metric::ModifiedAvailability(ModifiedImpact::High),
];

// Data used to decode a metric from a u64-encoded vector.
struct Decode(Name, usize, (usize, usize)); // key, shift, values

impl From<Name> for Decode {
  fn from(name: Name) -> Decode {
    // note: copied from `DECODES` above
    match name {
      Name::AttackVector => Decode(Name::AttackVector, 0, (0, 4)),
      Name::AttackComplexity => Decode(Name::AttackComplexity, 2, (4, 6)),
      Name::PrivilegesRequired => Decode(Name::PrivilegesRequired, 3, (6, 9)),
      Name::UserInteraction => Decode(Name::UserInteraction, 5, (9, 11)),
      Name::Scope => Decode(Name::Scope, 6, (11, 13)),
      Name::Confidentiality => Decode(Name::Confidentiality, 7, (13, 16)),
      Name::Integrity => Decode(Name::Integrity, 9, (16, 19)),
      Name::Availability => Decode(Name::Availability, 11, (19, 22)),
      Name::ExploitCodeMaturity => Decode(Name::ExploitCodeMaturity, 13, (22, 27)),
      Name::RemediationLevel => Decode(Name::RemediationLevel, 16, (27, 32)),
      Name::ReportConfidence => Decode(Name::ReportConfidence, 19, (32, 36)),
      Name::ConfidentialityRequirement => Decode(Name::ConfidentialityRequirement, 21, (36, 40)),
      Name::IntegrityRequirement => Decode(Name::IntegrityRequirement, 23, (40, 44)),
      Name::AvailabilityRequirement => Decode(Name::AvailabilityRequirement, 25, (44, 48)),
      Name::ModifiedAttackVector => Decode(Name::ModifiedAttackVector, 27, (48, 53)),
      Name::ModifiedAttackComplexity => Decode(Name::ModifiedAttackComplexity, 30, (53, 56)),
      Name::ModifiedPrivilegesRequired => Decode(Name::ModifiedPrivilegesRequired, 32, (56, 60)),
      Name::ModifiedUserInteraction => Decode(Name::ModifiedUserInteraction, 34, (60, 63)),
      Name::ModifiedScope => Decode(Name::ModifiedScope, 36, (63, 66)),
      Name::ModifiedConfidentiality => Decode(Name::ModifiedConfidentiality, 38, (66, 70)),
      Name::ModifiedIntegrity => Decode(Name::ModifiedIntegrity, 40, (70, 74)),
      Name::ModifiedAvailability => Decode(Name::ModifiedAvailability, 42, (74, 78)),
    }
  }
}

// Metric decodes.
//
// Used by `Vector::fmt()` and `VectorIterator::next()` to decode a
// u64-encoded vector into individual metrics in canonical order.
//
// Sorted in order specified in Table 15 in [Section 6 of the CVSS v4.0
// specification][vector-string].
//
// [vector-string]: https://www.first.org/cvss/v3-1/specification-document#Vector-String
//   "CVSS v3.1 Specification, Section 6: Vector String"
const DECODES: [Decode; 22] = [
  Decode(Name::AttackVector, 0, (0, 4)),
  Decode(Name::AttackComplexity, 2, (4, 6)),
  Decode(Name::PrivilegesRequired, 3, (6, 9)),
  Decode(Name::UserInteraction, 5, (9, 11)),
  Decode(Name::Scope, 6, (11, 13)),
  Decode(Name::Confidentiality, 7, (13, 16)),
  Decode(Name::Integrity, 9, (16, 19)),
  Decode(Name::Availability, 11, (19, 22)),
  Decode(Name::ExploitCodeMaturity, 13, (22, 27)),
  Decode(Name::RemediationLevel, 16, (27, 32)),
  Decode(Name::ReportConfidence, 19, (32, 36)),
  Decode(Name::ConfidentialityRequirement, 21, (36, 40)),
  Decode(Name::IntegrityRequirement, 23, (40, 44)),
  Decode(Name::AvailabilityRequirement, 25, (44, 48)),
  Decode(Name::ModifiedAttackVector, 27, (48, 53)),
  Decode(Name::ModifiedAttackComplexity, 30, (53, 56)),
  Decode(Name::ModifiedPrivilegesRequired, 32, (56, 60)),
  Decode(Name::ModifiedUserInteraction, 34, (60, 63)),
  Decode(Name::ModifiedScope, 36, (63, 66)),
  Decode(Name::ModifiedConfidentiality, 38, (66, 70)),
  Decode(Name::ModifiedIntegrity, 40, (70, 74)),
  Decode(Name::ModifiedAvailability, 42, (74, 78)),
];

/// [`Vector`][] iterator.
///
/// # Description
///
/// Used to iterate over the defined [`Metric`s][Metric] of a
/// [`Vector`][] in the order specified in Table 15 in [Section 6 of
/// the CVSS v3.1 specification][vector-string].
///
/// Created by [`Vector::into_iter()`][].
///
/// # Examples
///
/// Iterate over [`Vector`][] and appending each [`Metric`][]
/// to a [`std::vec::Vec`][]:
///
/// ```
/// # use polycvss::{Err, v3::{AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, Impact, Metric, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse string as vector
/// let v: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
///
/// // build ordered list (std::vec::Vec) of defined metrics in a vector
/// let mut metrics = Vec::new();
/// for metric in v {
///   metrics.push(metric);
/// }
///
/// // check result
/// assert_eq!(metrics, vec!(
///   Metric::AttackVector(AttackVector::Network),
///   Metric::AttackComplexity(AttackComplexity::Low),
///   Metric::PrivilegesRequired(PrivilegesRequired::None),
///   Metric::UserInteraction(UserInteraction::None),
///   Metric::Scope(Scope::Unchanged),
///   Metric::Confidentiality(Impact::High),
///   Metric::Integrity(Impact::High),
///   Metric::Availability(Impact::High),
/// ));
/// # Ok(())
/// # }
/// ```
///
/// Create a explicit iterator over [`Vector`][] and get the first
/// [`Metric`][]:
///
/// ```
/// # use polycvss::{Err, v3::{AttackVector, Metric, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse string as vector
/// let v: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
///
/// // create iterator
/// let mut iter = v.into_iter();
///
/// // get first metric
/// let metric = iter.next();
///
/// // check result
/// assert_eq!(metric, Some(Metric::AttackVector(AttackVector::Network)));
/// # Ok(())
/// # }
/// ```
///
/// [vector-string]: https://www.first.org/cvss/v3-1/specification-document#Vector-String
///   "CVSS v3.1 Specification, Section 6: Vector String"
pub struct VectorIterator {
  pos: usize, // position in vector
  val: u64, // encoded vector value
}

impl Iterator for VectorIterator {
  type Item = Metric;

  fn next(&mut self) -> Option<Metric> {
    self.pos += 1; // step

    loop {
      if self.pos > DECODES.len() {
        return None // stop
      }

      let (found, val) = {
        let decode = &DECODES[self.pos - 1];
        let (key, shift, range) = (decode.0, decode.1, decode.2);
        let vals = &METRICS[range.0..range.1];
        let mask = match vals.len() {
          2 => 1,
          3 | 4 => 0b11,
          5 => 0b111,
          _ => unreachable!(),
        };
        let ofs = ((self.val >> shift) as usize) & mask;
        (key.is_mandatory() || ofs > 0, vals[ofs])
      };

      if found {
        return Some(val) // found defined metric, return it
      }

      self.pos += 1; // step
    }
  }
}

/// [CVSS v3.1][cvss31] vector.
///
/// Notes:
///
/// - Represented internally as a `u64`.  See "Internal Representation" below.
/// - When iterating the metrics in a [`Vector`][] or converting a
///   [`Vector`][] to a string, the metrics are sorted in the order
///   specified in Table 23 of [Section 7 of the CVSS v4.0
///   specification][vector-string]; the sort order of metrics within
///   the source vector string is **not** preserved. See "Examples" below.
/// - Optional metrics with a value of `Not Defined (X)` are skipped
///   when iterating the metrics in a [`Vector`][] and when converting a
///   [`Vector`][] to a string. See "Examples" below.
///
/// # Examples
///
/// Parse a [`&str`][] into a [`Vector`][]:
///
/// ```
/// # use polycvss::{Err, v3::{Vector}};
/// # fn main() -> Result<(), Err> {
/// // CVSS v3.1 vector string
/// let s = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
///
/// // parse string as Vector
/// let v: Vector = s.parse()?;
/// # Ok(())
/// # }
/// ```
///
/// Get base score:
///
/// ```
/// # use polycvss::{Err, v3::{Scores, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string
/// let v: Vector = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H".parse()?;
///
/// // get scores
/// let scores = Scores::from(v);
///
/// // check result
/// assert_eq!(scores.base.to_string(), "4.4");
/// # Ok(())
/// # }
/// ```
///
/// Iterate over [`Metric`s][Metric] in a [`Vector`][]:
///
/// ```
/// # use polycvss::{Err, v3::Vector};
/// # fn main() -> Result<(), Err> {
/// // parse vector string
/// let v: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
///
/// // iterate over and print each metric
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
/// # use polycvss::{Err, v3::{AttackVector, Vector, Metric, Name}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string
/// let v: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
///
/// // get metric
/// let metric = v.get(Name::AttackVector);
///
/// // check result
/// assert_eq!(metric, Metric::AttackVector(AttackVector::Network));
/// # Ok(())
/// # }
/// ```
///
/// Show that the order of metrics within a vector string is **not**
/// preserved when parsing a vector string and then converting the
/// [`Vector`][] back to a string:
///
/// ```
/// # use polycvss::{Err, v3::Vector};
/// # fn main() -> Result<(), Err> {
/// // vector string with first two metrics (AV and AC) swapped
/// let s = "CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H";
///
/// // expected result after parsing vector string above and converting
/// // the parsed vector back to a vector string
/// let exp = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
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
/// [`Vector`][] back to a string:
///
/// ```
/// # use polycvss::{Err, v3::Vector};
/// # fn main() -> Result<(), Err> {
/// // vector string which contains an optional metric (MAV) with a
/// // value of `Not Defined (X)`
/// let s = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:X";
///
/// // expected result after parsing vector string above and converting
/// // the parsed vector back to a vector string
/// let exp = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
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
/// Verify that a vector is the same size as a `u64`:
///
/// ```
/// # use polycvss::v3::Vector;
/// # fn main() {
/// assert_eq!(size_of::<Vector>(), size_of::<u64>());
/// # }
/// ```
///
/// # Internal Representation
///
/// A CVSS v3 [`Vector`][] is represented internally as a [bit
/// field][bit-field] within a `u64`.  Metric values are stored in the
/// lower 44 bits (bits `0..44`) and the CVSS version is stored in the
/// upper 4 bits (bits `60..64`):
///
/// | Bit Range | Description                |
/// | --------- | -------------------------- |
/// | `0..44`   | Metric values.             |
/// | `44..60`  | Unused bits.               |
/// | `60..64`  | CVSS version (3.0 or 3.1). |
///
/// The number of bits used by a packed metric value is calculated as
/// `num_bits = ceil(log2(num_vals))`), where `num_vals` is the number
/// of possible values for that metric:
///
/// | # of Values | # of Bits |
/// | ----------- | --------- |
/// | 2 values    | 1 bit     |
/// | 3 values    | 2 bits    |
/// | 4 values    | 2 bits    |
/// | 5 values    | 3 bits    |
///
/// [cvss31]: https://www.first.org/cvss/v3-1/specification-document
///   "CVSS v3.1 Specification"
/// [bit-field]: https://en.wikipedia.org/wiki/Bit_field
///   "Bit field (Wikipedia)"
/// [vector-string]: https://www.first.org/cvss/v3-1/specification-document#Vector-String
///   "CVSS v3.1 Specification, Section 6: Vector String"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(try_from="String"))]
pub struct Vector(u64);

impl Vector {
  /// Get [`Metric`][] from [`Vector`][] by [`Name`][].
  ///
  /// # Examples
  ///
  /// Get metric from vector:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{AttackVector, Vector, Metric, Name}};
  /// # fn main() -> Result<(), Err> {
  /// // parse vector string
  /// let v: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
  ///
  /// // get metric
  /// let metric = v.get(Name::AttackVector);
  ///
  /// // check result
  /// assert_eq!(metric, Metric::AttackVector(AttackVector::Network));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Get optional metric from vector:
  ///
  /// ```
  /// # use polycvss::{Err, v3::{ModifiedAttackVector, Vector, Metric, Name}};
  /// # fn main() -> Result<(), Err> {
  /// // parse vector string
  /// let v: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".parse()?;
  ///
  /// // get metric
  /// let metric = v.get(Name::ModifiedAttackVector);
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined));
  /// # Ok(())
  /// # }
  /// ```
  pub fn get(self, name: Name) -> Metric {
    let decode = Decode::from(name);
    let (shift, range) = (decode.1, decode.2);
    let vals = &METRICS[range.0..range.1];
    let ofs = ((self.0 >> shift) as usize) & (vals.len() - 1);
    vals[ofs]
  }
}

impl IntoIterator for Vector {
  type Item = Metric;
  type IntoIter = VectorIterator;

  // Required method
  fn into_iter(self) -> Self::IntoIter {
    VectorIterator { pos: 0, val: self.0 }
  }
}

impl From<Vector> for Version {
  fn from(vec: Vector) -> Version {
    Version::from(super::Vector::from(vec))
  }
}

impl From<Vector> for u64 {
  fn from(vec: Vector) -> u64 {
    vec.0
  }
}

impl From<super::Vector> for Vector {
  fn from(vec: super::Vector) -> Self {
    Vector(vec.0)
  }
}

impl From<Vector> for super::Vector {
  fn from(vec: Vector) -> super::Vector {
    super::Vector(vec.0)
  }
}

impl From<Vector> for Score {
  fn from(vec: Vector) -> Score {
    let scores = Scores::from(vec);

    if let Some(score) = scores.environmental {
      score
    } else if let Some(score) = scores.temporal {
      score
    } else {
      scores.base
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

    // check string prefix, get version
    let version = u64::from(match &s[0..9]  {
      "CVSS:3.0/" => Version::V30,
      "CVSS:3.1/" => Version::V31,
      _ => return Err(Err::Prefix),
    });

    // split into metrics, then encode as u64
    let mut val = 0; // encoded Pot metrics
    let mut _acc = 0; // encoded non-PoT metrics (unused for cvss v3)
    let mut seen: u32 = 0; // seen keys
    for s in s[9..].split('/') {
      let c = EncodedMetric::from(s.parse::<Metric>()?); // encode

      // check for duplicate name
      if seen & c.bit != 0 {
        return Err(Err::DuplicateName);
      }

      seen |= c.bit; // mark name as seen
      match c.val {
        EncodedVal::Shift(v) => val |= v, // encode PoT value
        EncodedVal::Arith(v) => _acc += v, // encode non-PoT value
      }
    }

    // check for missing mandatory metrics
    if seen & 0xff != 0xff {
      return Err(Err::MissingMandatoryMetrics);
    }

    // return encoded vector
    Ok(Vector(version | val))
  }
}

impl TryFrom<String> for Vector {
  type Error = Err;

  fn try_from(s: String) -> Result<Self, Self::Error> {
    s.parse::<Vector>()
  }
}

impl std::fmt::Display for Vector {
  // Format CVSS v3 vector as a string.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    // write prefix
    write!(f, "CVSS:3.{}", match Version::from(*self) {
      Version::V30 => 0,
      Version::V31 => 1,
      _ => unreachable!(),
    })?;

    // write metrics
    for decode in DECODES {
      let (found, val) = {
        let (key, shift, range) = (decode.0, decode.1, decode.2);
        let vals = &METRICS[range.0..range.1];
        let mask = match vals.len() {
          2 => 1,
          3 | 4 => 0b11,
          5 => 0b111,
          _ => unreachable!(),
        };
        let ofs = ((self.0 >> shift) as usize) & mask;
        (key.is_mandatory() || ofs > 0, vals[ofs])
      };

      if found {
        write!(f, "/{val}")?;
      }
    }

    Ok(())
  }
}

/// [CVSS v3][doc] base, temporal, and environmental scores.
///
/// See [CVSS v3.1 Specification, Section 7: CVSS v3.1 Equations][eqs].
///
/// # Example
///
/// Get base score for [CVSS v3][doc] vector:
///
/// ```
/// # use polycvss::{Err, v3::{Scores, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v3 vector string
/// let v: Vector = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H".parse()?;
///
/// // get scores
/// let scores = Scores::from(v);
///
/// // check result
/// assert_eq!(scores.base.to_string(), "4.4");
/// # Ok(())
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document
///   "CVSS v3.1 Specification"
/// [eqs]: https://www.first.org/cvss/v3-1/specification-document#CVSS-v3-1-Equations
///   "CVSS v3.1 Specification, Section 7: CVSS v3.1 Equations"
#[derive(Clone,Copy,Debug,PartialEq)]
pub struct Scores {
  /// Base Score.
  pub base: Score,

  /// Temporal Score. Will have a value of `None` if no Temporal
  /// metrics are defined.
  pub temporal: Option<Score>,

  /// Environmental Score.  Will have a value of `None` if no
  /// environmental metrics are defined.
  pub environmental: Option<Score>,
}

impl From<Vector> for Scores {
  fn from(vec: Vector) -> Scores {
    let version = Version::from(vec);

    // cache scope changed
    let scope_changed = match vec.get(Name::Scope) {
      Metric::Scope(Scope::Changed) => true,
      Metric::Scope(Scope::Unchanged) => false,
      _ => unreachable!(),
    };

    // cache modified scope changed
    let modified_scope_changed = match vec.get(Name::ModifiedScope) {
      Metric::ModifiedScope(ModifiedScope::NotDefined) => scope_changed,
      Metric::ModifiedScope(ModifiedScope::Changed) => true,
      Metric::ModifiedScope(ModifiedScope::Unchanged) => false,
      _ => unreachable!(),
    };

    // Attack Vector
    //   Network  0.85
    //   Adjacent  0.62
    //   Local  0.55
    //   Physical  0.2
    let av = match vec.get(Name::AttackVector) {
      Metric::AttackVector(AttackVector::Network) => 0.85,
      Metric::AttackVector(AttackVector::Adjacent) => 0.62,
      Metric::AttackVector(AttackVector::Local) => 0.55,
      Metric::AttackVector(AttackVector::Physical) => 0.2,
      _ => unreachable!(),
    };

    // Attack Complexity
    //   Low  0.77
    //   High  0.44
    let ac = match vec.get(Name::AttackComplexity) {
      Metric::AttackComplexity(AttackComplexity::Low) => 0.77,
      Metric::AttackComplexity(AttackComplexity::High) => 0.44,
      _ => unreachable!(),
    };

    // Privileges Required
    //   None  0.85
    //   Low  0.62 (or 0.68 if Scope / Modified Scope is Changed)
    //   High  0.27 (or 0.5 if Scope / Modified Scope is Changed)
    let pr = match (vec.get(Name::PrivilegesRequired), scope_changed) {
      (Metric::PrivilegesRequired(PrivilegesRequired::None), _) => 0.85,
      (Metric::PrivilegesRequired(PrivilegesRequired::Low), true) => 0.68,
      (Metric::PrivilegesRequired(PrivilegesRequired::Low), false) => 0.62,
      (Metric::PrivilegesRequired(PrivilegesRequired::High), true) => 0.5,
      (Metric::PrivilegesRequired(PrivilegesRequired::High), false) => 0.27,
      _ => unreachable!(),
    };

    // User Interaction
    //   None  0.85
    //   Required  0.62
    let ui = match vec.get(Name::UserInteraction) {
      Metric::UserInteraction(UserInteraction::None) => 0.85,
      Metric::UserInteraction(UserInteraction::Required) => 0.62,
      _ => unreachable!(),
    };

    // Confidentiality
    // High 0.56
    // Low  0.22
    // None  0
    let c = match vec.get(Name::Confidentiality) {
      Metric::Confidentiality(Impact::High) => 0.56,
      Metric::Confidentiality(Impact::Low) => 0.22,
      Metric::Confidentiality(Impact::None) => 0.0,
      _ => unreachable!(),
    };

    // Integrity
    // High 0.56
    // Low  0.22
    // None  0
    let i = match vec.get(Name::Integrity) {
      Metric::Integrity(Impact::High) => 0.56,
      Metric::Integrity(Impact::Low) => 0.22,
      Metric::Integrity(Impact::None) => 0.0,
      _ => unreachable!(),
    };

    // Availability,
    // High 0.56
    // Low  0.22
    // None  0
    let a = match vec.get(Name::Availability) {
      Metric::Availability(Impact::High) => 0.56,
      Metric::Availability(Impact::Low) => 0.22,
      Metric::Availability(Impact::None) => 0.0,
      _ => unreachable!(),
    };

    // impact sub score
    // 1 - [ (1 - Confidentiality) × (1 - Integrity) × (1 - Availability) ]
    let iss: f64 = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));

    // get impact
    //
    // Impact =
    // If Scope is Unchanged   6.42 × ISS
    // If Scope is Changed   7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15
    let impact = match vec.get(Name::Scope) {
      Metric::Scope(Scope::Unchanged) => 6.42 * iss,
      Metric::Scope(Scope::Changed) => 7.52*(iss-0.029) - 3.25*(iss-0.02).powi(15),
      _ => unreachable!(),
    };

    // Exploitability = 8.22 × AttackVector × AttackComplexity ×
    //   PrivilegesRequired × UserInteraction
    let exploitability = 8.22 * av * ac * pr * ui;

    // BaseScore =
    //   If Impact \<= 0  0, else
    //   If Scope is Unchanged  Roundup (Minimum [(Impact + Exploitability), 10])
    //   If Scope is Changed  Roundup (Minimum [1.08 × (Impact + Exploitability), 10])
    let base_score = if impact > 0.0 {
      if scope_changed {
        roundup((1.08 * (impact + exploitability)).min(10.0), version)
      } else {
        roundup((impact + exploitability).min(10.0), version)
      }
    } else {
      0.0
    };

    // Exploit Code Maturity
    //   Not Defined  1
    //   High  1
    //   Functional  0.97
    //   Proof of Concept  0.94
    //   Unproven  0.91
    let ecm = match vec.get(Name::ExploitCodeMaturity) {
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::NotDefined) => 1.0,
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::High) => 1.0,
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::Functional) => 0.97,
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::ProofOfConcept) => 0.94,
      Metric::ExploitCodeMaturity(ExploitCodeMaturity::Unproven) => 0.91,
      _ => unreachable!(),
    };

    // Remediation Level
    //   Not Defined  1
    //   Unavailable  1
    //   Workaround  0.97
    //   Temporary Fix  0.96
    //   Official Fix  0.95
    let rl = match vec.get(Name::RemediationLevel) {
      Metric::RemediationLevel(RemediationLevel::NotDefined) => 1.0,
      Metric::RemediationLevel(RemediationLevel::Unavailable) => 1.0,
      Metric::RemediationLevel(RemediationLevel::Workaround) => 0.97,
      Metric::RemediationLevel(RemediationLevel::TemporaryFix) => 0.96,
      Metric::RemediationLevel(RemediationLevel::OfficialFix) => 0.95,
      _ => unreachable!(),
    };

    // Report Confidence
    //   Not Defined  1
    //   Confirmed  1
    //   Reasonable  0.96
    //   Unknown  0.92
    let rc = match vec.get(Name::ReportConfidence) {
      Metric::ReportConfidence(ReportConfidence::NotDefined) => 1.0,
      Metric::ReportConfidence(ReportConfidence::Confirmed) => 1.0,
      Metric::ReportConfidence(ReportConfidence::Reasonable) => 0.96,
      Metric::ReportConfidence(ReportConfidence::Unknown) => 0.92,
      _ => unreachable!(),
    };

    // is at least one temporal metric defined?
    let has_temporal_metrics = {
      // cache "Not Defined" values for temporal metrics
      let m_ecm_nd = Metric::ExploitCodeMaturity(ExploitCodeMaturity::NotDefined);
      let m_rl_nd = Metric::RemediationLevel(RemediationLevel::NotDefined);
      let m_rc_nd = Metric::ReportConfidence(ReportConfidence::NotDefined);

      vec.get(Name::ExploitCodeMaturity) != m_ecm_nd ||
      vec.get(Name::RemediationLevel) != m_rl_nd ||
      vec.get(Name::ReportConfidence) != m_rc_nd
    };

    // TemporalScore =
    //   Roundup (BaseScore × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
    let temporal_score = if has_temporal_metrics {
      Some(roundup(base_score * ecm * rl * rc, version))
    } else {
      None // no temporal metrics defined
    };

    // Modified Attack Vector
    //   Not Defined  base av
    //   Network  0.85
    //   Adjacent  0.62
    //   Local  0.55
    //   Physical  0.2
    let mav = match vec.get(Name::ModifiedAttackVector) {
      Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined) => av,
      Metric::ModifiedAttackVector(ModifiedAttackVector::Network) => 0.85,
      Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent) => 0.62,
      Metric::ModifiedAttackVector(ModifiedAttackVector::Local) => 0.55,
      Metric::ModifiedAttackVector(ModifiedAttackVector::Physical) => 0.2,
      _ => unreachable!(),
    };

    // Modified Attack Complexity
    //   Not Defined  base ac
    //   Low  0.77
    //   High  0.44
    let mac = match vec.get(Name::ModifiedAttackComplexity) {
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined) => ac,
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low) => 0.77,
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High) => 0.44,
      _ => unreachable!(),
    };

    // Modified Privileges Required
    //   Not Defined  base pr
    //   None  0.85
    //   Low  0.62 (or 0.68 if Scope / Modified Scope is Changed)
    //   High  0.27 (or 0.5 if Scope / Modified Scope is Changed)
    let mpr = match (vec.get(Name::ModifiedPrivilegesRequired), modified_scope_changed) {
      (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined), _) => pr,
      (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None), _) => 0.85,
      (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low), true) => 0.68,
      (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low), false) => 0.62,
      (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High), true) => 0.5,
      (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High), false) => 0.27,
      _ => unreachable!(),
    };

    // Modified User Interaction
    //   Not Defined  base ui
    //   None  0.85
    //   Required  0.62
    let mui = match vec.get(Name::ModifiedUserInteraction) {
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined) => ui,
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::None) => 0.85,
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::Required) => 0.62,
      _ => unreachable!(),
    };

    // Confidentiality Requirement
    //   Not Defined  1
    //   High  1.5
    //   Medium  1
    //   Low  0.5
    let cr = match vec.get(Name::ConfidentialityRequirement) {
      Metric::ConfidentialityRequirement(Requirement::NotDefined) => 1.0,
      Metric::ConfidentialityRequirement(Requirement::High) => 1.5,
      Metric::ConfidentialityRequirement(Requirement::Medium) => 1.0,
      Metric::ConfidentialityRequirement(Requirement::Low) => 0.5,
      _ => unreachable!(),
    };

    // Integrity Requirement
    //   Not Defined  1
    //   High  1.5
    //   Medium  1
    //   Low  0.5
    let ir = match vec.get(Name::IntegrityRequirement) {
      Metric::IntegrityRequirement(Requirement::NotDefined) => 1.0,
      Metric::IntegrityRequirement(Requirement::High) => 1.5,
      Metric::IntegrityRequirement(Requirement::Medium) => 1.0,
      Metric::IntegrityRequirement(Requirement::Low) => 0.5,
      _ => unreachable!(),
    };

    // Availability Requirement
    //   Not Defined  1
    //   High  1.5
    //   Medium  1
    //   Low  0.5
    let ar = match vec.get(Name::AvailabilityRequirement) {
      Metric::AvailabilityRequirement(Requirement::NotDefined) => 1.0,
      Metric::AvailabilityRequirement(Requirement::High) => 1.5,
      Metric::AvailabilityRequirement(Requirement::Medium) => 1.0,
      Metric::AvailabilityRequirement(Requirement::Low) => 0.5,
      _ => unreachable!(),
    };

    // Modified Confidentiality
    //   Not Defined base confidentiality
    //   High 0.56
    //   Low  0.22
    //   None  0
    let mc = match vec.get(Name::ModifiedConfidentiality) {
      Metric::ModifiedConfidentiality(ModifiedImpact::NotDefined) => c,
      Metric::ModifiedConfidentiality(ModifiedImpact::High) => 0.56,
      Metric::ModifiedConfidentiality(ModifiedImpact::Low) => 0.22,
      Metric::ModifiedConfidentiality(ModifiedImpact::None) => 0.0,
      _ => unreachable!(),
    };

    // Modified Integrity
    //   Not Defined base integrity
    //   High 0.56
    //   Low  0.22
    //   None  0
    let mi = match vec.get(Name::ModifiedIntegrity) {
      Metric::ModifiedIntegrity(ModifiedImpact::NotDefined) => i,
      Metric::ModifiedIntegrity(ModifiedImpact::High) => 0.56,
      Metric::ModifiedIntegrity(ModifiedImpact::Low) => 0.22,
      Metric::ModifiedIntegrity(ModifiedImpact::None) => 0.0,
      _ => unreachable!(),
    };

    // Modified Availability
    //   Not Defined base availability
    //   High 0.56
    //   Low  0.22
    //   None  0
    let ma = match vec.get(Name::ModifiedAvailability) {
      Metric::ModifiedAvailability(ModifiedImpact::NotDefined) => a,
      Metric::ModifiedAvailability(ModifiedImpact::High) => 0.56,
      Metric::ModifiedAvailability(ModifiedImpact::Low) => 0.22,
      Metric::ModifiedAvailability(ModifiedImpact::None) => 0.0,
      _ => unreachable!(),
    };

    // MISS = Minimum(
    //   1 - [ (1 - ConfidentialityRequirement × ModifiedConfidentiality) × (1 - IntegrityRequirement × ModifiedIntegrity) × (1 - AvailabilityRequirement × ModifiedAvailability) ],
    //   0.915
    // )
    let miss = (1.0 - ((1.0 - cr * mc) * (1.0 - ir * mi) * (1.0 - ar * ma))).min(0.915);

    // ModifiedImpact =
    // If ModifiedScope is Unchanged   6.42 × MISS
    // If ModifiedScope is Changed
    // - CVSS v3.0:
    //     7.52 × (MISS - 0.029) - 3.25 × (MISS - 0.02)^15
    //     https://www.first.org/cvss/v3-0/specification-document#8-3-Environmental
    // - CVSS v3.1:
    //     7.52 × (MISS - 0.029) - 3.25 × (MISS × 0.9731 - 0.02)^13
    //     https://www.first.org/cvss/v3-1/specification-document#7-3-Environmental-Metrics-Equations
    //
    // differences between v3.0 and v3.1:
    // - v3.1: MISS dampening factor in final term
    // - v3.1: lower exponent on final term (13 instead of 15)
    let modified_impact = if modified_scope_changed {
      let (factor, exp) = match version {
        Version::V30 => (1.0, 15),
        Version::V31 => (0.9731, 13),
        _ => unreachable!(),
      };

      7.52 * (miss - 0.029) - 3.25 * (miss * factor - 0.02).powi(exp)
    } else {
      6.42 * miss
    };

    // ModifiedExploitability =
    //   8.22 × ModifiedAttackVector × ModifiedAttackComplexity × ModifiedPrivilegesRequired × ModifiedUserInteraction
    let modified_exploitability = 8.22 * mav * mac * mpr * mui;

    // EnvironmentalScore =
    // If ModifiedImpact \<= 0  0, else
    //   If ModifiedScope is Unchanged: Roundup ( Roundup [Minimum ([ModifiedImpact + ModifiedExploitability], 10) ] × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
    // Unchanged
    //   If ModifiedScope is Changed: Roundup ( Roundup [Minimum (1.08 × [ModifiedImpact + ModifiedExploitability], 10) ] × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
    let env_score = if modified_impact > 0.0 {
      let factor = if modified_scope_changed { 1.08 } else { 1.0 };
      Some(roundup(roundup((factor * (modified_impact + modified_exploitability)).min(10.0), version) * ecm * rl * rc, version))
    } else {
      None
    };

    Scores {
      base: Score::from(base_score),
      temporal: temporal_score.map(Score::from),
      environmental: env_score.map(Score::from),
    }
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn test_roundup() {
    use super::{super::Version, roundup};
    let tests = vec!(
      (4.000_002, Version::V30, 4.1),
      (4.000_002, Version::V31, 4.0),
      (4.02, Version::V31, 4.1),
      (4.00, Version::V31, 4.0),
    );

    for (val, version, exp) in tests {
      assert_eq!(roundup(val, version), exp, "{val}, {version}");
    }
  }

  mod group {
    use super::super::{Name, Group};

    #[test]
    fn test_from_name() {
      let tests = vec!(
        (Name::AttackVector, Group::Base),
        (Name::ExploitCodeMaturity, Group::Temporal),
        (Name::ConfidentialityRequirement, Group::Environmental),
      );

      for (name, group) in tests {
        assert_eq!(Group::from(name), group, "{group}");
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Group::Base, "Base"),
        (Group::Temporal, "Temporal"),
        (Group::Environmental, "Environmental"),
      );

      for (group, exp) in tests {
        assert_eq!(group.to_string(), exp, "{exp}");
      }
    }
  }

  mod name {
    use super::super::{Err, Name};

    #[test]
    fn test_from_str_fail() {
      let tests = vec!(
        ("empty", "", Err::UnknownName),
        ("asdf", "asdf", Err::UnknownName),
      );

      for (test_name, s, exp) in tests {
        assert_eq!(s.parse::<Name>(), Err(exp), "{test_name}");
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        ("AV", Name::AttackVector),
        ("AC", Name::AttackComplexity),
        ("PR", Name::PrivilegesRequired),
        ("UI", Name::UserInteraction),
        ("S", Name::Scope),
        ("C", Name::Confidentiality),
        ("I", Name::Integrity),
        ("A", Name::Availability),
        ("E", Name::ExploitCodeMaturity),
        ("RL", Name::RemediationLevel),
        ("RC", Name::ReportConfidence),
        ("CR", Name::ConfidentialityRequirement),
        ("IR", Name::IntegrityRequirement),
        ("AR", Name::AvailabilityRequirement),
        ("MAV", Name::ModifiedAttackVector),
        ("MAC", Name::ModifiedAttackComplexity),
        ("MPR", Name::ModifiedPrivilegesRequired),
        ("MUI", Name::ModifiedUserInteraction),
        ("MS", Name::ModifiedScope),
        ("MC", Name::ModifiedConfidentiality),
        ("MI", Name::ModifiedIntegrity),
        ("MA", Name::ModifiedAvailability),
      );

      for (s, exp) in tests {
        assert_eq!(s.parse::<Name>(), Ok(exp), "{s}");
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Name::AttackVector, "AV"),
        (Name::AttackComplexity, "AC"),
        (Name::PrivilegesRequired, "PR"),
        (Name::UserInteraction, "UI"),
        (Name::Scope, "S"),
        (Name::Confidentiality, "C"),
        (Name::Integrity, "I"),
        (Name::Availability, "A"),
        (Name::ExploitCodeMaturity, "E"),
        (Name::RemediationLevel, "RL"),
        (Name::ReportConfidence, "RC"),
        (Name::ConfidentialityRequirement, "CR"),
        (Name::IntegrityRequirement, "IR"),
        (Name::AvailabilityRequirement, "AR"),
        (Name::ModifiedAttackVector, "MAV"),
        (Name::ModifiedAttackComplexity, "MAC"),
        (Name::ModifiedPrivilegesRequired, "MPR"),
        (Name::ModifiedUserInteraction, "MUI"),
        (Name::ModifiedScope, "MS"),
        (Name::ModifiedConfidentiality, "MC"),
        (Name::ModifiedIntegrity, "MI"),
        (Name::ModifiedAvailability, "MA"),
      );

      for (name, exp) in tests {
        assert_eq!(name.to_string(), exp, "{exp}");
      }
    }
  }

  mod metric {
    use super::super::{
      Err,
      Metric,
      AttackVector,
      AttackComplexity,
      PrivilegesRequired,
      UserInteraction,
      Scope,
      Impact,
      ExploitCodeMaturity,
      RemediationLevel,
      ReportConfidence,
      Requirement,
      ModifiedAttackVector,
      ModifiedAttackComplexity,
      ModifiedPrivilegesRequired,
      ModifiedUserInteraction,
      ModifiedScope,
      ModifiedImpact,
    };

    #[test]
    fn test_from_str_fail() {
      let tests = vec!("foo", "bar", "baz");
      for t in tests {
        assert_eq!(t.parse::<Metric>(), Err(Err::UnknownMetric), "{t}");
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        ("AV:N", Metric::AttackVector(AttackVector::Network)),
        ("AV:A", Metric::AttackVector(AttackVector::Adjacent)),
        ("AV:L", Metric::AttackVector(AttackVector::Local)),
        ("AV:P", Metric::AttackVector(AttackVector::Physical)),

        ("AC:H", Metric::AttackComplexity(AttackComplexity::High)),
        ("AC:L", Metric::AttackComplexity(AttackComplexity::Low)),

        ("PR:H", Metric::PrivilegesRequired(PrivilegesRequired::High)),
        ("PR:L", Metric::PrivilegesRequired(PrivilegesRequired::Low)),
        ("PR:N", Metric::PrivilegesRequired(PrivilegesRequired::None)),

        ("UI:N", Metric::UserInteraction(UserInteraction::None)),
        ("UI:R", Metric::UserInteraction(UserInteraction::Required)),

        ("S:U", Metric::Scope(Scope::Unchanged)),
        ("S:C", Metric::Scope(Scope::Changed)),

        ("C:N", Metric::Confidentiality(Impact::None)),
        ("C:L", Metric::Confidentiality(Impact::Low)),
        ("C:H", Metric::Confidentiality(Impact::High)),

        ("I:N", Metric::Integrity(Impact::None)),
        ("I:L", Metric::Integrity(Impact::Low)),
        ("I:H", Metric::Integrity(Impact::High)),

        ("A:N", Metric::Availability(Impact::None)),
        ("A:L", Metric::Availability(Impact::Low)),
        ("A:H", Metric::Availability(Impact::High)),

        ("E:U", Metric::ExploitCodeMaturity(ExploitCodeMaturity::Unproven)),
        ("E:P", Metric::ExploitCodeMaturity(ExploitCodeMaturity::ProofOfConcept)),
        ("E:F", Metric::ExploitCodeMaturity(ExploitCodeMaturity::Functional)),
        ("E:H", Metric::ExploitCodeMaturity(ExploitCodeMaturity::High)),
        ("E:X", Metric::ExploitCodeMaturity(ExploitCodeMaturity::NotDefined)),

        ("RL:O", Metric::RemediationLevel(RemediationLevel::OfficialFix)),
        ("RL:T", Metric::RemediationLevel(RemediationLevel::TemporaryFix)),
        ("RL:W", Metric::RemediationLevel(RemediationLevel::Workaround)),
        ("RL:U", Metric::RemediationLevel(RemediationLevel::Unavailable)),
        ("RL:X", Metric::RemediationLevel(RemediationLevel::NotDefined)),

        ("RC:U", Metric::ReportConfidence(ReportConfidence::Unknown)),
        ("RC:R", Metric::ReportConfidence(ReportConfidence::Reasonable)),
        ("RC:C", Metric::ReportConfidence(ReportConfidence::Confirmed)),
        ("RC:X", Metric::ReportConfidence(ReportConfidence::NotDefined)),

        ("CR:L", Metric::ConfidentialityRequirement(Requirement::Low)),
        ("CR:M", Metric::ConfidentialityRequirement(Requirement::Medium)),
        ("CR:H", Metric::ConfidentialityRequirement(Requirement::High)),
        ("CR:X", Metric::ConfidentialityRequirement(Requirement::NotDefined)),

        ("IR:L", Metric::IntegrityRequirement(Requirement::Low)),
        ("IR:M", Metric::IntegrityRequirement(Requirement::Medium)),
        ("IR:H", Metric::IntegrityRequirement(Requirement::High)),
        ("IR:X", Metric::IntegrityRequirement(Requirement::NotDefined)),

        ("AR:L", Metric::AvailabilityRequirement(Requirement::Low)),
        ("AR:M", Metric::AvailabilityRequirement(Requirement::Medium)),
        ("AR:H", Metric::AvailabilityRequirement(Requirement::High)),
        ("AR:X", Metric::AvailabilityRequirement(Requirement::NotDefined)),

        ("MAV:N", Metric::ModifiedAttackVector(ModifiedAttackVector::Network)),
        ("MAV:A", Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent)),
        ("MAV:L", Metric::ModifiedAttackVector(ModifiedAttackVector::Local)),
        ("MAV:P", Metric::ModifiedAttackVector(ModifiedAttackVector::Physical)),
        ("MAV:X", Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined)),

        ("MAC:H", Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High)),
        ("MAC:L", Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low)),
        ("MAC:X", Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined)),

        ("MPR:H", Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High)),
        ("MPR:L", Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low)),
        ("MPR:N", Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None)),
        ("MPR:X", Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined)),

        ("MUI:N", Metric::ModifiedUserInteraction(ModifiedUserInteraction::None)),
        ("MUI:R", Metric::ModifiedUserInteraction(ModifiedUserInteraction::Required)),
        ("MUI:X", Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined)),

        ("MS:U", Metric::ModifiedScope(ModifiedScope::Unchanged)),
        ("MS:C", Metric::ModifiedScope(ModifiedScope::Changed)),
        ("MS:X", Metric::ModifiedScope(ModifiedScope::NotDefined)),

        ("MC:N", Metric::ModifiedConfidentiality(ModifiedImpact::None)),
        ("MC:L", Metric::ModifiedConfidentiality(ModifiedImpact::Low)),
        ("MC:H", Metric::ModifiedConfidentiality(ModifiedImpact::High)),
        ("MC:X", Metric::ModifiedConfidentiality(ModifiedImpact::NotDefined)),

        ("MI:N", Metric::ModifiedIntegrity(ModifiedImpact::None)),
        ("MI:L", Metric::ModifiedIntegrity(ModifiedImpact::Low)),
        ("MI:H", Metric::ModifiedIntegrity(ModifiedImpact::High)),
        ("MI:X", Metric::ModifiedIntegrity(ModifiedImpact::NotDefined)),

        ("MA:N", Metric::ModifiedAvailability(ModifiedImpact::None)),
        ("MA:L", Metric::ModifiedAvailability(ModifiedImpact::Low)),
        ("MA:H", Metric::ModifiedAvailability(ModifiedImpact::High)),
        ("MA:X", Metric::ModifiedAvailability(ModifiedImpact::NotDefined)),
      );

      for (s, exp) in tests {
        assert_eq!(s.parse::<Metric>(), Ok(exp), "{s}");
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Metric::AttackVector(AttackVector::Network), "AV:N"),
        (Metric::AttackVector(AttackVector::Adjacent), "AV:A"),
        (Metric::AttackVector(AttackVector::Local), "AV:L"),
        (Metric::AttackVector(AttackVector::Physical), "AV:P"),

        (Metric::AttackComplexity(AttackComplexity::High), "AC:H"),
        (Metric::AttackComplexity(AttackComplexity::Low), "AC:L"),

        (Metric::PrivilegesRequired(PrivilegesRequired::High), "PR:H"),
        (Metric::PrivilegesRequired(PrivilegesRequired::Low), "PR:L"),
        (Metric::PrivilegesRequired(PrivilegesRequired::None), "PR:N"),

        (Metric::UserInteraction(UserInteraction::None), "UI:N"),
        (Metric::UserInteraction(UserInteraction::Required), "UI:R"),

        (Metric::Scope(Scope::Unchanged), "S:U"),
        (Metric::Scope(Scope::Changed), "S:C"),

        (Metric::Confidentiality(Impact::None), "C:N"),
        (Metric::Confidentiality(Impact::Low), "C:L"),
        (Metric::Confidentiality(Impact::High), "C:H"),

        (Metric::Integrity(Impact::None), "I:N"),
        (Metric::Integrity(Impact::Low), "I:L"),
        (Metric::Integrity(Impact::High), "I:H"),

        (Metric::Availability(Impact::None), "A:N"),
        (Metric::Availability(Impact::Low), "A:L"),
        (Metric::Availability(Impact::High), "A:H"),

        (Metric::ExploitCodeMaturity(ExploitCodeMaturity::Unproven), "E:U"),
        (Metric::ExploitCodeMaturity(ExploitCodeMaturity::ProofOfConcept), "E:P"),
        (Metric::ExploitCodeMaturity(ExploitCodeMaturity::Functional), "E:F"),
        (Metric::ExploitCodeMaturity(ExploitCodeMaturity::High), "E:H"),
        (Metric::ExploitCodeMaturity(ExploitCodeMaturity::NotDefined), "E:X"),

        (Metric::RemediationLevel(RemediationLevel::OfficialFix), "RL:O"),
        (Metric::RemediationLevel(RemediationLevel::TemporaryFix), "RL:T"),
        (Metric::RemediationLevel(RemediationLevel::Workaround), "RL:W"),
        (Metric::RemediationLevel(RemediationLevel::Unavailable), "RL:U"),
        (Metric::RemediationLevel(RemediationLevel::NotDefined), "RL:X"),

        (Metric::ReportConfidence(ReportConfidence::Unknown), "RC:U"),
        (Metric::ReportConfidence(ReportConfidence::Reasonable), "RC:R"),
        (Metric::ReportConfidence(ReportConfidence::Confirmed), "RC:C"),
        (Metric::ReportConfidence(ReportConfidence::NotDefined), "RC:X"),

        (Metric::ConfidentialityRequirement(Requirement::Low), "CR:L"),
        (Metric::ConfidentialityRequirement(Requirement::Medium), "CR:M"),
        (Metric::ConfidentialityRequirement(Requirement::High), "CR:H"),
        (Metric::ConfidentialityRequirement(Requirement::NotDefined), "CR:X"),

        (Metric::IntegrityRequirement(Requirement::Low), "IR:L"),
        (Metric::IntegrityRequirement(Requirement::Medium), "IR:M"),
        (Metric::IntegrityRequirement(Requirement::High), "IR:H"),
        (Metric::IntegrityRequirement(Requirement::NotDefined), "IR:X"),

        (Metric::AvailabilityRequirement(Requirement::Low), "AR:L"),
        (Metric::AvailabilityRequirement(Requirement::Medium), "AR:M"),
        (Metric::AvailabilityRequirement(Requirement::High), "AR:H"),
        (Metric::AvailabilityRequirement(Requirement::NotDefined), "AR:X"),

        (Metric::ModifiedAttackVector(ModifiedAttackVector::Network), "MAV:N"),
        (Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent), "MAV:A"),
        (Metric::ModifiedAttackVector(ModifiedAttackVector::Local), "MAV:L"),
        (Metric::ModifiedAttackVector(ModifiedAttackVector::Physical), "MAV:P"),
        (Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined), "MAV:X"),

        (Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High), "MAC:H"),
        (Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low), "MAC:L"),
        (Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined), "MAC:X"),

        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High), "MPR:H"),
        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low), "MPR:L"),
        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None), "MPR:N"),
        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined), "MPR:X"),

        (Metric::ModifiedUserInteraction(ModifiedUserInteraction::None), "MUI:N"),
        (Metric::ModifiedUserInteraction(ModifiedUserInteraction::Required), "MUI:R"),
        (Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined), "MUI:X"),

        (Metric::ModifiedScope(ModifiedScope::Unchanged), "MS:U"),
        (Metric::ModifiedScope(ModifiedScope::Changed), "MS:C"),
        (Metric::ModifiedScope(ModifiedScope::NotDefined), "MS:X"),

        (Metric::ModifiedConfidentiality(ModifiedImpact::None), "MC:N"),
        (Metric::ModifiedConfidentiality(ModifiedImpact::Low), "MC:L"),
        (Metric::ModifiedConfidentiality(ModifiedImpact::High), "MC:H"),
        (Metric::ModifiedConfidentiality(ModifiedImpact::NotDefined), "MC:X"),

        (Metric::ModifiedIntegrity(ModifiedImpact::None), "MI:N"),
        (Metric::ModifiedIntegrity(ModifiedImpact::Low), "MI:L"),
        (Metric::ModifiedIntegrity(ModifiedImpact::High), "MI:H"),
        (Metric::ModifiedIntegrity(ModifiedImpact::NotDefined), "MI:X"),

        (Metric::ModifiedAvailability(ModifiedImpact::None), "MA:N"),
        (Metric::ModifiedAvailability(ModifiedImpact::Low), "MA:L"),
        (Metric::ModifiedAvailability(ModifiedImpact::High), "MA:H"),
        (Metric::ModifiedAvailability(ModifiedImpact::NotDefined), "MA:X"),
      );

      for (m, exp) in tests {
        assert_eq!(m.to_string(), exp, "{exp}");
      }
    }

    #[test]
    fn test_size() {
      assert_eq!(size_of::<Metric>(), size_of::<u16>());
    }
  }

  mod vector {
    use super::super::{
        super::{Score, Version},
        Err,
        Metric,
        Vector,
        Name,
        AttackVector,
        AttackComplexity,
        PrivilegesRequired,
        UserInteraction,
        Scope,
        Impact,
        ExploitCodeMaturity,
        RemediationLevel,
        ReportConfidence,
        Requirement,
        ModifiedAttackVector,
        ModifiedAttackComplexity,
        ModifiedPrivilegesRequired,
        ModifiedUserInteraction,
        ModifiedScope,
        ModifiedImpact,
      };

    #[test]
    fn test_from_str_fail() {
      let tests = vec!(
        ("", Err::Len),
        ("CVSS:3.2/", Err::Prefix),
        ("CVSS:3.1/AV:N/AV:N", Err::DuplicateName),
        ("CVSS:3.1/AV:N/AV:A", Err::DuplicateName),
        ("CVSS:3.1/AV:Z", Err::UnknownMetric),
        ("CVSS:3.1/ZZ:Z", Err::UnknownMetric),
        ("CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Err::MissingMandatoryMetrics),
        ("CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H", Err::MissingMandatoryMetrics),
        ("CVSS:3.1/AV:N/AC:L/UI:N/S:U/C:H/I:H/A:H", Err::MissingMandatoryMetrics),
        ("CVSS:3.1/AV:N/AC:L/PR:N/S:U/C:H/I:H/A:H", Err::MissingMandatoryMetrics),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H", Err::MissingMandatoryMetrics),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/I:H/A:H", Err::MissingMandatoryMetrics),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/A:H", Err::MissingMandatoryMetrics),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", Err::MissingMandatoryMetrics),
      );

      for (s, exp) in tests {
        assert_eq!(s.parse::<Vector>(), Err(exp), "{s}");
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        // AV
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // AV:N
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // AV:A
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // AV:L
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // AV:P

        // AC
        "CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N", // AC:L
        "CVSS:3.1/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N", // AC:H

        // PR
        "CVSS:3.1/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N/AC:H", // PR:N
        "CVSS:3.1/PR:L/UI:N/S:U/C:H/I:H/A:H/AV:N/AC:H", // PR:L
        "CVSS:3.1/PR:H/UI:N/S:U/C:H/I:H/A:H/AV:N/AC:H", // PR:H

        // UI
        "CVSS:3.1/UI:N/S:U/C:H/I:H/A:H/AV:N/AC:H/PR:N", // UI:N
        "CVSS:3.1/UI:R/S:U/C:H/I:H/A:H/AV:N/AC:H/PR:N", // UI:R

        // S
        "CVSS:3.1/S:U/C:H/I:H/A:H/AV:N/AC:H/PR:N/UI:N", // S:U
        "CVSS:3.1/S:C/C:H/I:H/A:H/AV:N/AC:H/PR:N/UI:N", // S:C

        // C
        "CVSS:3.1/C:H/I:H/A:H/AV:N/AC:H/PR:N/UI:N/S:U", // C:H
        "CVSS:3.1/C:L/I:H/A:H/AV:N/AC:H/PR:N/UI:N/S:U", // C:L
        "CVSS:3.1/C:N/I:H/A:H/AV:N/AC:H/PR:N/UI:N/S:U", // C:N

        // I
        "CVSS:3.1/I:H/A:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H", // I:H
        "CVSS:3.1/I:L/A:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H", // I:L
        "CVSS:3.1/I:N/A:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H", // I:N

        // A
        "CVSS:3.1/A:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H", // A:H
        "CVSS:3.1/A:L/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H", // A:L
        "CVSS:3.1/A:N/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H", // A:N

        // E
        "CVSS:3.1/E:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // E:X
        "CVSS:3.1/E:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // E:H
        "CVSS:3.1/E:F/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // E:F
        "CVSS:3.1/E:P/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // E:P
        "CVSS:3.1/E:U/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // E:U

        // RL
        "CVSS:3.1/RL:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // RL:X
        "CVSS:3.1/RL:U/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // RL:U
        "CVSS:3.1/RL:W/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // RL:W
        "CVSS:3.1/RL:T/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // RL:T
        "CVSS:3.1/RL:O/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // RL:O

        // RC
        "CVSS:3.1/RC:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // RC:X
        "CVSS:3.1/RC:C/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // RC:C
        "CVSS:3.1/RC:R/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // RC:R
        "CVSS:3.1/RC:U/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // RC:U

        // CR
        "CVSS:3.1/CR:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // CR:X
        "CVSS:3.1/CR:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // CR:H
        "CVSS:3.1/CR:M/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // CR:M
        "CVSS:3.1/CR:L/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // CR:L

        // IR
        "CVSS:3.1/IR:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // IR:X
        "CVSS:3.1/IR:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // IR:H
        "CVSS:3.1/IR:M/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // IR:M
        "CVSS:3.1/IR:L/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // IR:L

        // AR
        "CVSS:3.1/AR:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // AR:X
        "CVSS:3.1/AR:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // AR:H
        "CVSS:3.1/AR:M/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // AR:M
        "CVSS:3.1/AR:L/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // AR:L

        // MAV
        "CVSS:3.1/MAV:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MAV:X
        "CVSS:3.1/MAV:N/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MAV:N
        "CVSS:3.1/MAV:A/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MAV:A
        "CVSS:3.1/MAV:L/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MAV:L
        "CVSS:3.1/MAV:P/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MAV:P

        // MAC
        "CVSS:3.1/MAC:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MAC:X
        "CVSS:3.1/MAC:L/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MAC:L
        "CVSS:3.1/MAC:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MAC:H

        // MPR
        "CVSS:3.1/MPR:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MPR:X
        "CVSS:3.1/MPR:N/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MPR:N
        "CVSS:3.1/MPR:L/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MPR:L
        "CVSS:3.1/MPR:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MPR:H

        // MUI
        "CVSS:3.1/MUI:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MUI:X
        "CVSS:3.1/MUI:N/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MUI:N
        "CVSS:3.1/MUI:R/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MUI:R

        // MS
        "CVSS:3.1/MS:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MS:X
        "CVSS:3.1/MS:U/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MS:U
        "CVSS:3.1/MS:C/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MS:C

        // MC
        "CVSS:3.1/MC:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MC:X
        "CVSS:3.1/MC:N/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MC:N
        "CVSS:3.1/MC:L/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MC:L
        "CVSS:3.1/MC:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MC:H

        // MI
        "CVSS:3.1/MI:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MI:X
        "CVSS:3.1/MI:N/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MI:N
        "CVSS:3.1/MI:L/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MI:L
        "CVSS:3.1/MI:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MI:H

        // MA
        "CVSS:3.1/MA:X/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MA:X
        "CVSS:3.1/MA:N/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MA:N
        "CVSS:3.1/MA:L/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MA:L
        "CVSS:3.1/MA:H/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // MA:H
      );

      for t in tests {
        t.parse::<Vector>().expect(t);
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (
          "default", // name
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "everything", // name
          "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H", // val
          "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H", // exp
        ),

        (
          "everything jumbled", // name
          "CVSS:3.1/MC:H/MAC:H/MAV:P/CR:L/RL:O/C:N/PR:H/AV:P/AC:H/UI:R/S:C/I:N/A:N/E:U/RC:U/IR:L/AR:L/MPR:H/MUI:R/MS:C/MI:H/MA:H", // val
          "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H", // exp
        ),

        (
          "reordered", // name
          "CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "AV:N", // name
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "AV:A", // name
          "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "AV:L", // name
          "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "AV:P", // name
          "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "AC:L", // name
          "CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "AC:H", // name
          "CVSS:3.1/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N", // val
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "PR:N", // name
          "CVSS:3.1/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N/AC:L", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "PR:L", // name
          "CVSS:3.1/PR:L/UI:N/S:U/C:H/I:H/A:H/AV:N/AC:L", // val
          "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "PR:H", // name
          "CVSS:3.1/PR:H/UI:N/S:U/C:H/I:H/A:H/AV:N/AC:L", // val
          "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "UI:N", // name
          "CVSS:3.1/UI:N/S:U/C:H/I:H/A:H/AV:N/AC:L/PR:N", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "UI:R", // name
          "CVSS:3.1/UI:R/S:U/C:H/I:H/A:H/AV:N/AC:L/PR:N", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "S:U", // name
          "CVSS:3.1/S:U/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "S:C", // name
          "CVSS:3.1/S:C/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", // exp
        ),

        (
          "C:H", // name
          "CVSS:3.1/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "C:L", // name
          "CVSS:3.1/C:L/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H", // exp
        ),

        (
          "C:N", // name
          "CVSS:3.1/C:N/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", // exp
        ),

        (
          "I:H", // name
          "CVSS:3.1/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U/C:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "I:L", // name
          "CVSS:3.1/I:L/A:H/AV:N/AC:L/PR:N/UI:N/S:U/C:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H", // exp
        ),

        (
          "I:N", // name
          "CVSS:3.1/I:N/A:H/AV:N/AC:L/PR:N/UI:N/S:U/C:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", // exp
        ),

        (
          "A:H", // name
          "CVSS:3.1/A:H/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "A:L", // name
          "CVSS:3.1/A:L/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // exp
        ),

        (
          "A:N", // name
          "CVSS:3.1/A:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", // exp
        ),

        (
          "E:X", // name
          "CVSS:3.1/E:X/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "E:H", // name
          "CVSS:3.1/E:H/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H", // exp
        ),

        (
          "E:F", // name
          "CVSS:3.1/E:F/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F", // exp
        ),

        (
          "E:P", // name
          "CVSS:3.1/E:P/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P", // exp
        ),

        (
          "E:U", // name
          "CVSS:3.1/E:U/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U", // exp
        ),

        (
          "RL:X", // name
          "CVSS:3.1/RL:X/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // exp
        ),

        (
          "RL:U", // name
          "CVSS:3.1/RL:U/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/RL:U", // exp
        ),
        (
          "RL:W", // name
          "CVSS:3.1/RL:W/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/RL:W", // exp
        ),

        (
          "RL:T", // name
          "CVSS:3.1/RL:T/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/RL:T", // exp
        ),

        (
          "RL:O", // name
          "CVSS:3.1/RL:O/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/RL:O", // exp
        ),

        (
          "84832a7a", // name
          "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:H/E:H/RL:X/RC:C/CR:M/IR:X/AR:M/MAV:P/MAC:X/MPR:L/MUI:R/MS:U/MC:H/MI:L/MA:X", // val
          "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:H/E:H/RC:C/CR:M/AR:M/MAV:P/MPR:L/MUI:R/MS:U/MC:H/MI:L", // exp
        ),
      );

      for (name, val, exp) in tests {
        assert_eq!(val.parse::<Vector>().expect(name).to_string(), exp, "{name}");
      }
    }

    #[test]
    fn test_get() {
      let tests = vec!((
        "base metric", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // val
        Name::AttackVector, // metric name
        Metric::AttackVector(AttackVector::Network), // exp
      ), (
        "optional metric", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H", // val
        Name::ModifiedAttackVector, // metric name
        Metric::ModifiedAttackVector(ModifiedAttackVector::Physical), // exp
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
          "basic",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          vec!(
            Metric::AttackVector(AttackVector::Network),
            Metric::AttackComplexity(AttackComplexity::Low),
            Metric::PrivilegesRequired(PrivilegesRequired::None),
            Metric::UserInteraction(UserInteraction::None),
            Metric::Scope(Scope::Unchanged),
            Metric::Confidentiality(Impact::High),
            Metric::Integrity(Impact::High),
            Metric::Availability(Impact::High),
          )
        ),

        (
          "everything",
          "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
          vec!(
            Metric::AttackVector(AttackVector::Physical),
            Metric::AttackComplexity(AttackComplexity::High),
            Metric::PrivilegesRequired(PrivilegesRequired::High),
            Metric::UserInteraction(UserInteraction::Required),
            Metric::Scope(Scope::Changed),
            Metric::Confidentiality(Impact::None),
            Metric::Integrity(Impact::None),
            Metric::Availability(Impact::None),
            Metric::ExploitCodeMaturity(ExploitCodeMaturity::Unproven),
            Metric::RemediationLevel(RemediationLevel::OfficialFix),
            Metric::ReportConfidence(ReportConfidence::Unknown),
            Metric::ConfidentialityRequirement(Requirement::Low),
            Metric::IntegrityRequirement(Requirement::Low),
            Metric::AvailabilityRequirement(Requirement::Low),
            Metric::ModifiedAttackVector(ModifiedAttackVector::Physical),
            Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High),
            Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High),
            Metric::ModifiedUserInteraction(ModifiedUserInteraction::Required),
            Metric::ModifiedScope(ModifiedScope::Changed),
            Metric::ModifiedConfidentiality(ModifiedImpact::High),
            Metric::ModifiedIntegrity(ModifiedImpact::High),
            Metric::ModifiedAvailability(ModifiedImpact::High),
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
          "basic",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          vec!(
            Metric::AttackVector(AttackVector::Network),
            Metric::AttackComplexity(AttackComplexity::Low),
            Metric::PrivilegesRequired(PrivilegesRequired::None),
            Metric::UserInteraction(UserInteraction::None),
            Metric::Scope(Scope::Unchanged),
            Metric::Confidentiality(Impact::High),
            Metric::Integrity(Impact::High),
            Metric::Availability(Impact::High),
          )
        ),

        (
          "everything",
          "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
          vec!(
            Metric::AttackVector(AttackVector::Physical),
            Metric::AttackComplexity(AttackComplexity::High),
            Metric::PrivilegesRequired(PrivilegesRequired::High),
            Metric::UserInteraction(UserInteraction::Required),
            Metric::Scope(Scope::Changed),
            Metric::Confidentiality(Impact::None),
            Metric::Integrity(Impact::None),
            Metric::Availability(Impact::None),
            Metric::ExploitCodeMaturity(ExploitCodeMaturity::Unproven),
            Metric::RemediationLevel(RemediationLevel::OfficialFix),
            Metric::ReportConfidence(ReportConfidence::Unknown),
            Metric::ConfidentialityRequirement(Requirement::Low),
            Metric::IntegrityRequirement(Requirement::Low),
            Metric::AvailabilityRequirement(Requirement::Low),
            Metric::ModifiedAttackVector(ModifiedAttackVector::Physical),
            Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High),
            Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High),
            Metric::ModifiedUserInteraction(ModifiedUserInteraction::Required),
            Metric::ModifiedScope(ModifiedScope::Changed),
            Metric::ModifiedConfidentiality(ModifiedImpact::High),
            Metric::ModifiedIntegrity(ModifiedImpact::High),
            Metric::ModifiedAvailability(ModifiedImpact::High),
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
    fn test_into_version() {
      let tests = vec!(
        ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", Version::V30),
        ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", Version::V31),
      );

      for (s, exp) in tests {
        let got = Version::from(s.parse::<Vector>().unwrap());
        assert_eq!(got, exp, "{s}");
      }
    }

    #[test]
    fn test_into_score() {
      // actual CVEs from tests/data
      let tests = vec!(
        (
          "CVE-2024-12345", // name
          "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", // val
          Score(44), // exp
        ),

        (
          "CVE-2025-33053", // name
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", // val
          Score(88), // exp
        ),
      );

      for (name, s, exp) in tests {
        let got = Score::from(s.parse::<Vector>().unwrap());
        assert_eq!(got, exp, "{name}");
      }
    }

    #[test]
    fn test_size() {
      assert_eq!(size_of::<Vector>(), size_of::<u64>());
    }
  }

  mod scores {
    use super::super::{super::Score, Vector, Scores};

    #[test]
    fn test_examples() {
      // actual CVEs from tests/data
      let tests = vec!(
        (
          "CVE-2024-12345", // name
          "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", // val
          Scores {
            base: Score::from(4.4),
            temporal: None,
            environmental: Some(Score::from(4.4)),
          }, // exp
        ),

        (
          "CVE-2025-33053", // name
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", // val
          Scores {
            base: Score::from(8.8),
            temporal: None,
            environmental: Some(Score::from(8.8)),
          }, // exp
        ),
      );

      for (name, vs, exp) in tests {
        let vec: Vector = vs.parse().unwrap(); // parse vector
        let got = Scores::from(vec); // get scores
        assert_eq!(got, exp, "{name}, {vec}"); // check result
      }
    }

    #[test]
    fn test_from_vector() {
      // TODO: get more (and test temporal and env vectors)
      let tests = vec!((
        "84832a7a 5.8", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:H/E:H/RL:X/RC:C/CR:M/IR:X/AR:M/MAV:P/MAC:X/MPR:L/MUI:R/MS:U/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "9ec42ef5 0.0", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:L/I:N/A:L/E:H/RL:X/RC:C/CR:L/IR:H/AR:H/MAV:L/MAC:H/MPR:L/MUI:N/MS:U/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "2ed05e63 5.7", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:H/E:P/RL:U/RC:R/CR:L/IR:M/AR:H/MAV:A/MAC:X/MPR:H/MUI:R/MS:U/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "0dfd6747 2.7", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L/E:P/RL:U/RC:X/CR:H/IR:L/AR:L/MAV:L/MAC:H/MPR:N/MUI:N/MS:X/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "4b1718b2 3.4", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:N/E:F/RL:W/RC:X/CR:X/IR:L/AR:X/MAV:X/MAC:L/MPR:N/MUI:N/MS:U/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "8b71ca76 7.1", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:N/E:H/RL:W/RC:U/CR:H/IR:X/AR:X/MAV:A/MAC:L/MPR:H/MUI:R/MS:C/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "a36f0ec0 4.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H/E:H/RL:O/RC:R/CR:X/IR:L/AR:X/MAV:A/MAC:L/MPR:H/MUI:X/MS:X/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(8.4), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "955341f3 9.1", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:L/E:H/RL:U/RC:X/CR:X/IR:H/AR:L/MAV:N/MAC:X/MPR:L/MUI:R/MS:C/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(9.1)), // exp environmental score
        }, // exp
      ), (
        "766e53f3 5.0", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/E:P/RL:T/RC:U/CR:X/IR:L/AR:M/MAV:P/MAC:H/MPR:N/MUI:N/MS:C/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(9.6), // exp base score
          temporal: Some(Score::from(8.0)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "38d5b8c2 3.7", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L/E:P/RL:U/RC:R/CR:H/IR:L/AR:H/MAV:L/MAC:L/MPR:L/MUI:R/MS:X/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "73a8f346 4.4", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N/E:U/RL:O/RC:X/CR:X/IR:M/AR:H/MAV:N/MAC:X/MPR:L/MUI:N/MS:C/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "8ddda776 5.6", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L/E:U/RL:W/RC:R/CR:H/IR:M/AR:H/MAV:X/MAC:L/MPR:H/MUI:R/MS:X/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "41e88a1a 5.5", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H/E:X/RL:X/RC:C/CR:H/IR:H/AR:M/MAV:N/MAC:X/MPR:H/MUI:R/MS:U/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "9c2894af 3.3", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H/E:P/RL:T/RC:X/CR:M/IR:L/AR:M/MAV:N/MAC:H/MPR:L/MUI:X/MS:U/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "b8c2ad87 5.7", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L/E:X/RL:X/RC:X/CR:X/IR:L/AR:H/MAV:L/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "02a15af8 5.0", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N/E:X/RL:X/RC:C/CR:H/IR:L/AR:M/MAV:A/MAC:L/MPR:H/MUI:N/MS:U/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "df9671d0 7.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N/E:P/RL:T/RC:C/CR:X/IR:L/AR:M/MAV:A/MAC:X/MPR:X/MUI:X/MS:C/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "34092dd1 5.1", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N/E:X/RL:X/RC:R/CR:M/IR:X/AR:X/MAV:N/MAC:H/MPR:N/MUI:R/MS:X/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "dce0eded 4.2", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H/E:U/RL:U/RC:C/CR:M/IR:X/AR:M/MAV:P/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(8.8), // exp base score
          temporal: Some(Score::from(8.1)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "e0036c06 3.6", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:H/E:U/RL:O/RC:U/CR:L/IR:H/AR:M/MAV:A/MAC:H/MPR:H/MUI:X/MS:U/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "90eadbc6 0.0", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H/E:F/RL:T/RC:X/CR:M/IR:X/AR:M/MAV:N/MAC:L/MPR:N/MUI:X/MS:C/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "f3ea8026 5.0", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:N/E:U/RL:U/RC:U/CR:M/IR:L/AR:M/MAV:P/MAC:L/MPR:N/MUI:R/MS:U/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "5aaa6071 6.9", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:L/E:P/RL:O/RC:R/CR:H/IR:M/AR:M/MAV:X/MAC:X/MPR:H/MUI:N/MS:C/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "5b4ec6c3 4.8", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N/E:F/RL:W/RC:R/CR:L/IR:X/AR:X/MAV:A/MAC:H/MPR:N/MUI:N/MS:X/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "83dd9689 3.9", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:H/E:P/RL:T/RC:R/CR:H/IR:H/AR:X/MAV:L/MAC:H/MPR:X/MUI:R/MS:C/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "b5000bec 4.3", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:L/E:P/RL:O/RC:X/CR:L/IR:M/AR:M/MAV:P/MAC:X/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "1fe8ad28 4.0", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:L/E:H/RL:W/RC:U/CR:X/IR:L/AR:X/MAV:A/MAC:X/MPR:L/MUI:X/MS:X/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "ac47240d 7.1", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N/E:X/RL:O/RC:C/CR:M/IR:X/AR:L/MAV:N/MAC:L/MPR:N/MUI:X/MS:C/MC:X/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "3c87b6f8 4.1", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:L/E:F/RL:U/RC:R/CR:L/IR:X/AR:M/MAV:A/MAC:X/MPR:X/MUI:R/MS:X/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "504526e2 5.6", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:N/A:L/E:F/RL:U/RC:U/CR:L/IR:X/AR:X/MAV:P/MAC:H/MPR:L/MUI:X/MS:C/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "5c4d5a75 2.0", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:L/E:X/RL:T/RC:R/CR:L/IR:M/AR:X/MAV:A/MAC:L/MPR:H/MUI:R/MS:X/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "415dfc97 7.3", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N/E:H/RL:U/RC:R/CR:H/IR:M/AR:M/MAV:A/MAC:H/MPR:H/MUI:N/MS:C/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(3.1), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "f8106ad0 6.5", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:N/E:F/RL:T/RC:X/CR:X/IR:M/AR:M/MAV:X/MAC:L/MPR:H/MUI:R/MS:C/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.6)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "ba2d4a55 2.7", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:H/E:U/RL:W/RC:R/CR:M/IR:X/AR:L/MAV:P/MAC:H/MPR:L/MUI:R/MS:X/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "483e1150 7.2", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H/E:H/RL:O/RC:R/CR:X/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:R/MS:U/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.6)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "fa363685 3.6", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:H/E:P/RL:W/RC:R/CR:X/IR:M/AR:M/MAV:A/MAC:H/MPR:X/MUI:X/MS:C/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "b27f693a 6.9", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N/E:X/RL:T/RC:C/CR:H/IR:X/AR:M/MAV:X/MAC:H/MPR:L/MUI:N/MS:C/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(9.3), // exp base score
          temporal: Some(Score::from(9.0)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "41a0334d 5.7", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L/E:X/RL:W/RC:R/CR:M/IR:H/AR:M/MAV:L/MAC:L/MPR:N/MUI:R/MS:U/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "8c0b30d1 7.0", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L/E:H/RL:U/RC:R/CR:L/IR:H/AR:L/MAV:L/MAC:L/MPR:N/MUI:N/MS:X/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "3bd0f982 6.3", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H/E:P/RL:U/RC:X/CR:X/IR:H/AR:X/MAV:P/MAC:L/MPR:X/MUI:N/MS:X/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "fb5dc513 0.0", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L/E:P/RL:X/RC:X/CR:H/IR:L/AR:L/MAV:P/MAC:H/MPR:L/MUI:N/MS:C/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "3d0eacab 2.1", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H/E:U/RL:X/RC:R/CR:L/IR:H/AR:L/MAV:A/MAC:L/MPR:X/MUI:R/MS:U/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "1f843903 2.1", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N/E:X/RL:X/RC:U/CR:X/IR:L/AR:M/MAV:P/MAC:X/MPR:H/MUI:N/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(1.6), // exp base score
          temporal: Some(Score::from(1.5)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "81d92bc2 7.2", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H/E:H/RL:X/RC:X/CR:L/IR:M/AR:H/MAV:A/MAC:X/MPR:H/MUI:R/MS:X/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "df7a8e6e 6.1", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N/E:H/RL:U/RC:X/CR:H/IR:X/AR:H/MAV:P/MAC:L/MPR:H/MUI:R/MS:U/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "55fe8500 3.2", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H/E:U/RL:T/RC:C/CR:L/IR:M/AR:M/MAV:L/MAC:H/MPR:X/MUI:X/MS:X/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "7c358778 0.0", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H/E:H/RL:W/RC:U/CR:M/IR:H/AR:H/MAV:A/MAC:L/MPR:N/MUI:N/MS:X/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "dc24e4b4 5.5", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:H/E:U/RL:W/RC:R/CR:L/IR:H/AR:M/MAV:L/MAC:X/MPR:N/MUI:N/MS:X/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "03fc916e 4.1", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H/E:U/RL:W/RC:U/CR:H/IR:M/AR:H/MAV:N/MAC:L/MPR:N/MUI:R/MS:U/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "c7132036 5.0", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:L/E:U/RL:O/RC:C/CR:L/IR:X/AR:M/MAV:A/MAC:L/MPR:L/MUI:N/MS:U/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "dffae123 6.5", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N/E:F/RL:X/RC:C/CR:X/IR:X/AR:X/MAV:X/MAC:L/MPR:X/MUI:R/MS:C/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "d6ec8d1d 5.5", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H/E:H/RL:O/RC:U/CR:H/IR:L/AR:L/MAV:L/MAC:X/MPR:H/MUI:R/MS:X/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "cecc85a8 4.5", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:L/E:F/RL:O/RC:C/CR:X/IR:H/AR:L/MAV:P/MAC:L/MPR:H/MUI:X/MS:C/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.6)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "f4322bd8 0.0", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:H/E:H/RL:T/RC:U/CR:L/IR:L/AR:M/MAV:L/MAC:L/MPR:H/MUI:N/MS:X/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "b231ab69 1.8", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N/E:H/RL:W/RC:R/CR:X/IR:H/AR:M/MAV:P/MAC:X/MPR:L/MUI:R/MS:U/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "8a4ac8dc 3.7", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L/E:P/RL:X/RC:U/CR:X/IR:M/AR:X/MAV:N/MAC:H/MPR:L/MUI:N/MS:U/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "9e1f38ca 2.6", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:N/E:U/RL:U/RC:C/CR:L/IR:M/AR:H/MAV:P/MAC:L/MPR:N/MUI:R/MS:X/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "533abf98 5.3", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L/E:F/RL:X/RC:R/CR:H/IR:X/AR:L/MAV:N/MAC:X/MPR:H/MUI:N/MS:C/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "63c095f6 5.8", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N/E:P/RL:W/RC:C/CR:X/IR:X/AR:M/MAV:X/MAC:H/MPR:X/MUI:X/MS:C/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "b4cf5ec0 0.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:C/C:L/I:N/A:L/E:F/RL:O/RC:U/CR:H/IR:M/AR:X/MAV:X/MAC:X/MPR:L/MUI:R/MS:C/MC:N/MI:X/MA:N", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "cfb542a4 5.8", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:L/I:H/A:L/E:U/RL:T/RC:R/CR:X/IR:M/AR:L/MAV:P/MAC:L/MPR:X/MUI:R/MS:X/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "be4fbc16 5.1", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N/E:F/RL:T/RC:U/CR:H/IR:H/AR:X/MAV:N/MAC:H/MPR:X/MUI:N/MS:U/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "66874de8 6.9", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L/E:X/RL:T/RC:X/CR:L/IR:M/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "d4e5c158 3.4", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H/E:F/RL:X/RC:C/CR:M/IR:M/AR:L/MAV:A/MAC:L/MPR:N/MUI:R/MS:U/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "466d8be3 5.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:H/E:U/RL:O/RC:X/CR:M/IR:X/AR:L/MAV:X/MAC:L/MPR:H/MUI:R/MS:C/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "57bb314c 2.9", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N/E:F/RL:U/RC:R/CR:M/IR:M/AR:L/MAV:L/MAC:X/MPR:H/MUI:R/MS:X/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "93c90b66 7.9", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H/E:P/RL:W/RC:C/CR:H/IR:X/AR:H/MAV:X/MAC:X/MPR:N/MUI:X/MS:C/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "22689650 8.3", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:H/I:N/A:H/E:H/RL:O/RC:C/CR:H/IR:M/AR:H/MAV:A/MAC:L/MPR:N/MUI:R/MS:X/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(8.3)), // exp environmental score
        }, // exp
      ), (
        "f104979a 5.8", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N/E:H/RL:X/RC:X/CR:L/IR:H/AR:X/MAV:A/MAC:H/MPR:X/MUI:X/MS:C/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "7b6be059 4.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:N/I:H/A:H/E:H/RL:W/RC:X/CR:L/IR:M/AR:L/MAV:A/MAC:L/MPR:X/MUI:N/MS:X/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "ec43f143 4.4", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:L/E:P/RL:X/RC:R/CR:L/IR:X/AR:M/MAV:A/MAC:X/MPR:N/MUI:R/MS:X/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "d8d619b4 3.3", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:H/E:F/RL:T/RC:R/CR:M/IR:H/AR:M/MAV:P/MAC:X/MPR:N/MUI:N/MS:U/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "69ebf13a 5.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H/E:H/RL:T/RC:U/CR:L/IR:H/AR:H/MAV:X/MAC:H/MPR:X/MUI:X/MS:X/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "1e7489c0 5.5", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H/E:P/RL:O/RC:R/CR:X/IR:M/AR:H/MAV:A/MAC:H/MPR:H/MUI:N/MS:X/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "d11d2dce 4.6", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:L/A:H/E:P/RL:X/RC:C/CR:M/IR:M/AR:M/MAV:A/MAC:L/MPR:X/MUI:X/MS:U/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "3ac948ea 7.7", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:H/E:H/RL:X/RC:C/CR:X/IR:L/AR:X/MAV:L/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "c7bd5cd2 5.5", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H/E:X/RL:W/RC:R/CR:X/IR:X/AR:X/MAV:L/MAC:L/MPR:X/MUI:X/MS:U/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "38983c3e 6.2", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:L/E:U/RL:X/RC:U/CR:M/IR:X/AR:H/MAV:P/MAC:L/MPR:N/MUI:R/MS:C/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "2f3d5cfc 4.4", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H/E:P/RL:T/RC:X/CR:M/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:N/MS:X/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "4a0d18ad 0.7", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H/E:U/RL:T/RC:R/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:X/MUI:N/MS:X/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(4.2), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(0.7)), // exp environmental score
        }, // exp
      ), (
        "35f1e8cb 5.2", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N/E:X/RL:T/RC:X/CR:M/IR:M/AR:L/MAV:L/MAC:X/MPR:H/MUI:R/MS:X/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "9d2acc3c 1.5", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:L/E:P/RL:U/RC:U/CR:L/IR:M/AR:M/MAV:P/MAC:H/MPR:L/MUI:X/MS:U/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "4127c57c 5.1", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N/E:F/RL:W/RC:R/CR:L/IR:H/AR:X/MAV:N/MAC:H/MPR:H/MUI:N/MS:C/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "555b5289 6.6", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L/E:X/RL:O/RC:U/CR:M/IR:H/AR:M/MAV:X/MAC:X/MPR:N/MUI:R/MS:X/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(4.2), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "328a50e2 5.7", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N/E:P/RL:U/RC:R/CR:X/IR:M/AR:L/MAV:N/MAC:X/MPR:N/MUI:N/MS:C/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "50bb1f75 3.8", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N/E:X/RL:X/RC:U/CR:L/IR:X/AR:L/MAV:X/MAC:H/MPR:X/MUI:R/MS:C/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "310de1ae 6.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L/E:X/RL:T/RC:C/CR:H/IR:L/AR:L/MAV:N/MAC:X/MPR:N/MUI:N/MS:X/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "e55d50b6 6.9", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:H/E:X/RL:U/RC:R/CR:M/IR:H/AR:L/MAV:X/MAC:L/MPR:H/MUI:R/MS:C/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "59698b87 5.4", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:H/RL:T/RC:X/CR:M/IR:X/AR:M/MAV:P/MAC:H/MPR:X/MUI:N/MS:X/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "339af9b1 7.1", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H/E:H/RL:T/RC:C/CR:H/IR:M/AR:H/MAV:N/MAC:X/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "764420da 3.4", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N/E:H/RL:W/RC:C/CR:H/IR:H/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "9627e8c8 5.2", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L/E:U/RL:O/RC:C/CR:X/IR:X/AR:H/MAV:P/MAC:H/MPR:L/MUI:R/MS:C/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(2.2), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "bd806ced 2.2", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:F/RL:W/RC:U/CR:H/IR:L/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:C/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "29ac3cb2 4.9", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L/E:U/RL:X/RC:U/CR:M/IR:X/AR:M/MAV:L/MAC:L/MPR:H/MUI:R/MS:U/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "ee9d3755 5.8", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L/E:U/RL:W/RC:C/CR:H/IR:M/AR:X/MAV:P/MAC:L/MPR:N/MUI:X/MS:C/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "f4401a7e 5.9", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H/E:H/RL:W/RC:C/CR:L/IR:L/AR:X/MAV:A/MAC:X/MPR:L/MUI:X/MS:U/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "77f90a55 6.3", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H/E:U/RL:X/RC:R/CR:L/IR:M/AR:X/MAV:N/MAC:H/MPR:L/MUI:N/MS:C/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "cc917469 6.6", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H/E:F/RL:W/RC:X/CR:L/IR:X/AR:X/MAV:A/MAC:X/MPR:N/MUI:R/MS:X/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "a2555da1 6.1", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L/E:X/RL:U/RC:U/CR:L/IR:H/AR:H/MAV:P/MAC:L/MPR:L/MUI:N/MS:X/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "37d0680a 8.6", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L/E:H/RL:X/RC:R/CR:H/IR:H/AR:M/MAV:A/MAC:L/MPR:N/MUI:X/MS:C/MC:X/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(8.6)), // exp environmental score
        }, // exp
      ));

      for (name, s, exp) in tests {
        let vec: Vector = s.parse().unwrap(); // parse vector
        let got = Scores::from(vec); // get scores
        assert_eq!(got, exp, "{name}, {vec}"); // check result
      }
    }
  }
}
