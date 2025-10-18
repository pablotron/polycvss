//! [CVSS v3][doc] parsing and scoring.
//!
//! # Examples
//!
//! Parse [CVSS v3][doc] [vector string][vector-string], then get a
//! [`Metric`] by [`Name`]:
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
//! Build [`Vec`] of metric names:
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

/// [`Metric`] group.
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
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
pub enum Group {
  /// Base metrics.
  ///
  /// The Base metric group represents the intrinsic characteristics of
  /// a vulnerability that are constant over time and across user
  /// environments. It is composed of two sets of metrics: the
  /// Exploitability metrics and the Impact metrics.
  ///
  /// The Exploitability metrics reflect the ease and technical means by
  /// which the vulnerability can be exploited. That is, they represent
  /// characteristics of the thing that is vulnerable, which we refer to
  /// formally as the vulnerable component. The Impact metrics reflect the
  /// direct consequence of a successful exploit, and represent the
  /// consequence to the thing that suffers the impact, which we refer to
  /// formally as the impacted component.
  ///
  /// While the vulnerable component is typically a software
  /// application, module, driver, etc. (or possibly a hardware device),
  /// the impacted component could be a software application, a hardware
  /// device or a network resource. This potential for measuring the
  /// impact of a vulnerability other than the vulnerable component, was a
  /// key feature introduced with CVSS v3.0. This property is captured by
  /// the Scope metric, discussed later.
  ///
  /// See [CVSS v3.1 Specification, Section 2: Base Metrics][doc].
  ///
  /// # Metrics
  ///
  /// - [`Metric::AttackVector`]
  /// - [`Metric::AttackComplexity`]
  /// - [`Metric::PrivilegesRequired`]
  /// - [`Metric::UserInteraction`]
  /// - [`Metric::Scope`]
  /// - [`Metric::Confidentiality`]
  /// - [`Metric::Integrity`]
  /// - [`Metric::Availability`]
  ///
  /// # Example
  ///
  /// Get metric group:
  ///
  /// ```
  /// # use polycvss::v3::{Group, Name};
  /// # fn main() {
  /// assert_eq!(Group::from(Name::AttackVector), Group::Base);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Base-Metrics
  ///   "CVSS v3.1 Specification, Section 2: Base Metrics"
  Base,

  /// Temporal metrics.
  ///
  /// The Temporal metric group reflects the characteristics of a
  /// vulnerability that may change over time but not across user
  /// environments. For example, the presence of a simple-to-use exploit
  /// kit would increase the CVSS score, while the creation of an official
  /// patch would decrease it.
  ///
  /// See [CVSS v3.1 Specification, Section 3: Temporal Metrics][doc].
  ///
  /// # Metrics
  ///
  /// - [`Metric::ExploitCodeMaturity`]
  /// - [`Metric::RemediationLevel`]
  /// - [`Metric::ReportConfidence`]
  ///
  /// # Example
  ///
  /// Get metric group:
  ///
  /// ```
  /// # use polycvss::v3::{Group, Name};
  /// # fn main() {
  /// assert_eq!(Group::from(Name::ExploitCodeMaturity), Group::Temporal);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Temporal-Metrics
  ///   "CVSS v3.1 Specification, Section 3: Temporal Metrics"
  Temporal,

  /// Environmental metrics.
  ///
  /// The Environmental metric group represents the characteristics of a
  /// vulnerability that are relevant and unique to a particular user’s
  /// environment. Considerations include the presence of security
  /// controls which may mitigate some or all consequences of a successful
  /// attack, and the relative importance of a vulnerable system within a
  /// technology infrastructure.
  ///
  /// See [CVSS v3.1 Specification, Section 4: Environmental Metrics][doc].
  ///
  /// # Metrics
  ///
  /// - [`Metric::ConfidentialityRequirement`]
  /// - [`Metric::IntegrityRequirement`]
  /// - [`Metric::AvailabilityRequirement`]
  /// - [`Metric::ModifiedAttackVector`]
  /// - [`Metric::ModifiedAttackComplexity`]
  /// - [`Metric::ModifiedPrivilegesRequired`]
  /// - [`Metric::ModifiedUserInteraction`]
  /// - [`Metric::ModifiedScope`]
  /// - [`Metric::ModifiedConfidentiality`]
  /// - [`Metric::ModifiedIntegrity`]
  /// - [`Metric::ModifiedAvailability`]
  ///
  /// # Example
  ///
  /// Get metric group:
  ///
  /// ```
  /// # use polycvss::v3::{Group, Name};
  /// # fn main() {
  /// assert_eq!(Group::from(Name::ConfidentialityRequirement), Group::Environmental);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Environmental-Metrics
  ///   "CVSS v3.1 Specification, Section 4: Environmental Metrics"
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

/// [`Metric`] name.
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
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Name {
  /// Attack Vector (`AV`) metric name.  See [`Metric::AttackVector`].
  AttackVector,

  /// Attack Complexity (`AC`) metric name.  See [`Metric::AttackComplexity`].
  AttackComplexity,

  /// Privileges Required (`PR`) metric name.  See [`Metric::PrivilegesRequired`].
  PrivilegesRequired,

  /// User Interaction (`UI`) metric name.  See [`Metric::UserInteraction`].
  UserInteraction,

  /// Scope (`S`) metric name.  See [`Metric::Scope`].
  Scope,

  /// Confidentiality (`C`) metric name.  See [`Metric::Confidentiality`].
  Confidentiality,

  /// Integrity (`I`) metric name.  See [`Metric::Integrity`].
  Integrity,

  /// Availability (`A`) metric name.  See [`Metric::Availability`].
  Availability,

  /// Exploit Code Maturity (`E`) metric name.  See [`Metric::ExploitCodeMaturity`].
  ExploitCodeMaturity,

  /// Remediation Level (`RL`) metric name.  See [`Metric::RemediationLevel`].
  RemediationLevel,

  /// Report Confidence (`RC`) metric name.  See [`Metric::ReportConfidence`].
  ReportConfidence,

  /// Confidentiality Requirement (`CR`) metric name.  See [`Metric::ConfidentialityRequirement`].
  ConfidentialityRequirement,

  /// Integrity Requirement (`IR`) metric name.  See [`Metric::IntegrityRequirement`].
  IntegrityRequirement,

  /// Availability Requirement (`AR`) metric name.  See [`Metric::AvailabilityRequirement`].
  AvailabilityRequirement,

  /// Modified Attack Vector (`MAV`) metric name.  See [`Metric::ModifiedAttackVector`].
  ModifiedAttackVector,

  /// Modified Attack Complexity (`MAC`) metric name.  See [`Metric::ModifiedAttackComplexity`].
  ModifiedAttackComplexity,

  /// Modified Privileges Required (`MPR`) metric name.  See [`Metric::ModifiedPrivilegesRequired`].
  ModifiedPrivilegesRequired,

  /// Modified User Interaction (`MUI`) metric name.  See [`Metric::ModifiedUserInteraction`].
  ModifiedUserInteraction,

  /// Modified Scope (`MS`) metric name.  See [`Metric::ModifiedScope`].
  ModifiedScope,

  /// Modified Confidentiality (`MC`) metric name.  See [`Metric::ModifiedConfidentiality`].
  ModifiedConfidentiality,

  /// Modified Integrity (`MI`) metric name.  See [`Metric::ModifiedIntegrity`].
  ModifiedIntegrity,

  /// Modified Availability (`MA`) metric name.  See [`Metric::ModifiedAvailability`].
  ModifiedAvailability,
}

impl Name {
  /// Is this metric mandatory?
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::v3::{AttackVector, Name};
  /// # fn main() {
  /// // check if metric is mandatory
  /// assert_eq!(true, Name::AttackVector.is_mandatory());
  /// # }
  /// ```
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

/// [`Metric::AttackVector`] (`AV`) values.
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
/// - Metric Group: [Base Metrics][Group::Base]
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
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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

/// [`Metric::ModifiedAttackVector`] (`MAV`) values.
///
/// # Description
///
/// Metric value which overrides the base [`Metric::AttackVector`]
/// (`AV`) metric value.
///
/// # Properties
///
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedAttackVector {
  /// Not Defined (`X`)
  NotDefined,

  /// Network (`N`)
  ///
  /// See [`AttackVector::Network`].
  Network,

  /// Adjacent (`A`)
  ///
  /// See [`AttackVector::Adjacent`].
  Adjacent,

  /// Local (`L`)
  ///
  /// See [`AttackVector::Local`].
  Local,

  /// Physical (`P`)
  ///
  /// See [`AttackVector::Physical`].
  Physical,
}

/// [`Metric::AttackComplexity`] (`AC`) values.
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
/// - Metric Group: [Base Metrics][Group::Base]
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
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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

/// [`Metric::ModifiedAttackComplexity`] (`MAC`) values.
///
/// # Description
///
/// Metric value which overrides the base [`Metric::AttackComplexity`]
/// (`AC`) metric value.
///
/// # Properties
///
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedAttackComplexity {
  /// Not Defined (`X`)
  NotDefined,

  /// Low (`L`)
  ///
  /// See [`AttackComplexity::Low`].
  Low,

  /// High (`H`)
  ///
  /// See [`AttackComplexity::High`].
  High,
}

/// [`Metric::PrivilegesRequired`] (`PR`) values.
///
/// # Description
///
/// This metric describes the level of privileges an attacker must
/// possess before successfully exploiting the vulnerability. The Base
/// Score is greatest if no privileges are required.
///
/// # Properties
///
/// - Metric Group: [Base Metrics][Group::Base]
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
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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

/// [`Metric::ModifiedPrivilegesRequired`] (`MPR`) values.
///
/// # Description
///
/// Metric value which overrides the base [`Metric::PrivilegesRequired`]
/// (`PR`) metric value.
///
/// # Properties
///
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedPrivilegesRequired {
  /// Not Defined (`X`)
  NotDefined,

  /// None (`N`)
  ///
  /// See [`PrivilegesRequired::None`]
  None,

  /// Low (`L`)
  ///
  /// See [`PrivilegesRequired::Low`]
  Low,

  /// High (`H`)
  ///
  /// See [`PrivilegesRequired::High`]
  High,
}

/// [`Metric::UserInteraction`] (`UI`) values.
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
/// - Metric Group: [Base Metrics][Group::Base]
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
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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

/// [`Metric::ModifiedUserInteraction`] (`MUI`) values.
///
/// # Description
///
/// Metric value which overrides the base [`Metric::UserInteraction`]
/// (`UI`) metric value.
///
/// # Properties
///
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedUserInteraction {
  /// Not Defined (`X`)
  NotDefined,

  /// None (`N`)
  ///
  /// See [`UserInteraction::None`].
  None,

  /// Required (`R`)
  ///
  /// See [`UserInteraction::Required`].
  Required,
}

/// [`Metric::Scope`] (`S`) values.
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
/// - Metric Group: [Base Metrics][Group::Base]
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
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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

/// [`Metric::ModifiedScope`] (`MS`) values.
///
/// # Description
///
/// Metric value which overrides the base [`Metric::Scope`]
/// (`S`) metric value.
///
/// # Properties
///
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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
/// - `C`: [`Metric::Confidentiality`]
/// - `I`: [`Metric::Integrity`]
/// - `A`: [`Metric::Availability`]
///
/// # Properties
///
/// - Metric Group: [Base Metrics][Group::Base]
/// - Base Metric Set: Impact Metrics
/// - Documentation: [CVSS v3.1 Specification, Section 2.3: Impact Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Impact-Metrics
///   "CVSS v3.1 Specification, Section 2.3: Impact Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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
/// - `MC`: [`Metric::ModifiedConfidentiality`]
/// - `MI`: [`Metric::ModifiedIntegrity`]
/// - `MA`: [`Metric::ModifiedAvailability`]
///
/// # Properties
///
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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

/// [`Metric::ExploitCodeMaturity`] (`E`) values.
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
/// - Metric Group: [Temporal Metrics][Group::Temporal]
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
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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

/// [`Metric::RemediationLevel`] (`RL`) values.
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
/// - Metric Group: [Temporal Metrics][Group::Temporal]
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
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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

/// [`Metric::ReportConfidence`] (`RC`) values.
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
/// - Metric Group: [Temporal Metrics][Group::Temporal]
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
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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
/// - `CR`: [`Metric::ConfidentialityRequirement`]
/// - `IR`: [`Metric::IntegrityRequirement`]
/// - `AR`: [`Metric::AvailabilityRequirement`]
///
/// # Properties
///
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v3.1 Specification, Section 4.1: Security Requirements][doc]
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document#Security-Requirements
///   "CVSS v3.1 Specification, Section 4.1: Security Requirements"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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

/// [`Metric`] component.
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
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Metric {
  /// [`Metric::AttackVector`] (`AV`) metric.
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
  /// - Metric Group: [Base Metrics][Group::Base]
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

  /// [`Metric::ModifiedAttackVector`] (`MAV`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::AttackVector`]
  /// (`AV`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  AttackComplexity(AttackComplexity),

  /// [`Metric::PrivilegesRequired`] (`PR`) metric.
  ///
  /// # Description
  ///
  /// This metric describes the level of privileges an attacker must
  /// possess before successfully exploiting the vulnerability. The Base
  /// Score is greatest if no privileges are required.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
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

  /// [`Metric::UserInteraction`] (`UI`) metric.
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
  /// - Metric Group: [Base Metrics][Group::Base]
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

  /// [`Metric::Scope`] (`S`) metric.
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
  /// - Metric Group: [Base Metrics][Group::Base]
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
  /// - Metric Group: [Base Metrics][Group::Base]
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
  /// - Metric Group: [Base Metrics][Group::Base]
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
  /// - Metric Group: [Base Metrics][Group::Base]
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
  /// - Metric Group: [Temporal Metrics][Group::Temporal]
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
  /// - Metric Group: [Temporal Metrics][Group::Temporal]
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
  /// - Metric Group: [Temporal Metrics][Group::Temporal]
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
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
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
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
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
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v3.1 Specification, Section 4.1: Security Requirements][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#4-1-Security-Requirements
  ///   "CVSS v3.1 Specification, Section 4.1: Security Requirements"
  AvailabilityRequirement(Requirement),

  /// Modified Attack Vector (`MAV`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::AttackVector`]
  /// (`AV`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedAttackVector(ModifiedAttackVector),

  /// Modified Attack Complexity (`MAC`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::AttackComplexity`]
  /// (`AC`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedAttackComplexity(ModifiedAttackComplexity),

  /// Modified Privileges Required (`MPR`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::PrivilegesRequired`]
  /// (`PR`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedPrivilegesRequired(ModifiedPrivilegesRequired),

  /// Modified User Interaction (`MUI`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::UserInteraction`]
  /// (`UI`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedUserInteraction(ModifiedUserInteraction),

  /// Modified Scope (`MS`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::Scope`]
  /// (`S`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedScope(ModifiedScope),

  /// Modified Confidentiality (`MC`) metric.
  ///
  /// # Description
  ///
  /// Overrides the base [`Metric::Confidentiality`] (`C`) metric.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedConfidentiality(ModifiedImpact),

  /// Modified Integrity (`MI`) metric.
  ///
  /// # Description
  ///
  /// Overrides the base [`Metric::Integrity`] (`I`) metric.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v3.1 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// [doc]: https://www.first.org/cvss/v3-1/specification-document#Modified-Base-Metrics
  ///   "CVSS v3.1 Specification, Section 4.2: Modified Base Metrics"
  ModifiedIntegrity(ModifiedImpact),

  /// Modified Availability (`MA`) metric.
  ///
  /// # Description
  ///
  /// Overrides the base [`Metric::Availability`] (`A`) metric.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
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

/// [`Vector`] iterator.
///
/// # Description
///
/// Used to iterate over the defined [`Metric`s][Metric] of a
/// [`Vector`] in the order specified in Table 15 in [Section 6 of
/// the CVSS v3.1 specification][vector-string].
///
/// Created by [`Vector::into_iter()`].
///
/// # Examples
///
/// Iterate over [`Vector`] and appending each [`Metric`]
/// to a [`std::vec::Vec`]:
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
/// Create a explicit iterator over [`Vector`] and get the first
/// [`Metric`]:
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

/// [CVSS v3][cvss31] vector.
///
/// Notes:
///
/// - Supports [CVSS v3.0][cvss30] and [CVSS v3.1][cvss31] score
///   calculations.
/// - Represented internally as a `u64`.  See "Internal Representation" below.
/// - When iterating the metrics in a [`Vector`] or converting a
///   [`Vector`] to a string, the metrics are sorted in the order
///   specified in Table 23 of [Section 7 of the CVSS v4.0
///   specification][vector-string]; the sort order of metrics within
///   the source vector string is **not** preserved. See "Examples" below.
/// - Optional metrics with a value of `Not Defined (X)` are skipped
///   when iterating the metrics in a [`Vector`] and when converting a
///   [`Vector`] to a string. See "Examples" below.
///
/// # Examples
///
/// Parse a [`&str`] into a [`Vector`]:
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
/// # use polycvss::{Err, Score, v3::{Scores, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string
/// let v: Vector = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H".parse()?;
///
/// // get scores
/// let scores = Scores::from(v);
///
/// // check result
/// assert_eq!(scores.base, Score::from(4.4));
/// # Ok(())
/// # }
/// ```
///
/// Iterate over [`Metric`s][Metric] in a [`Vector`]:
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
/// [`Vector`] back to a string:
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
/// [`Vector`] back to a string:
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
/// A CVSS v3 [`Vector`] is represented internally as a [bit
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
/// [cvss30]: https://www.first.org/cvss/v3-0/specification-document
///   "CVSS v3.0 Specification"
/// [cvss31]: https://www.first.org/cvss/v3-1/specification-document
///   "CVSS v3.1 Specification"
/// [bit-field]: https://en.wikipedia.org/wiki/Bit_field
///   "Bit field (Wikipedia)"
/// [vector-string]: https://www.first.org/cvss/v3-1/specification-document#Vector-String
///   "CVSS v3.1 Specification, Section 6: Vector String"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(try_from="String"))]
pub struct Vector(u64);

impl Vector {
  /// Get [`Metric`] from [`Vector`] by [`Name`].
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
    let mask = match vals.len() {
      2 => 1,
      3 | 4 => 0b11,
      5 => 0b111,
      _ => unreachable!(),
    };
    let ofs = ((self.0 >> shift) as usize) & mask;
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
    Score::from(Scores::from(vec))
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

/// [CVSS v3][doc] base, temporal, and environmental scores for a
/// [`Vector`].
///
/// You can convert a [`Scores`] structure to an overall vector
/// [`Score`] with [`Score::from()`].
///
/// See [CVSS v3.1 Specification, Section 7: CVSS v3.1 Equations][eqs].
///
/// # Example
///
/// Get base score for [CVSS v3][doc] vector:
///
/// ```
/// # use polycvss::{Err, Score, v3::{Scores, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v3 vector string
/// let v: Vector = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H".parse()?;
///
/// // get scores
/// let scores = Scores::from(v);
///
/// // check result
/// assert_eq!(scores.base, Score::from(4.4));
/// # Ok(())
/// # }
/// ```
///
/// Convert [`Scores`] to an overall [`Score`]:
///
/// ```
/// # use polycvss::{Err, Score, v3::Scores};
/// # fn main() -> Result<(), Err> {
/// let scores = Scores {
///   base: Score::from(4.3),
///   temporal: Some(Score::from(3.2)),
///   environmental: Some(Score::from(1.5)),
/// };
///
/// // convert to overall score
/// let score = Score::from(scores);
///
/// // check result
/// assert_eq!(score, Score::from(1.5));
/// # Ok(())
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v3-1/specification-document
///   "CVSS v3.1 Specification"
/// [eqs]: https://www.first.org/cvss/v3-1/specification-document#CVSS-v3-1-Equations
///   "CVSS v3.1 Specification, Section 7: CVSS v3.1 Equations"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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

    // println!("DEBUG: c={c}, i={i}, a={a}, I:{}", vec.get(Name::Integrity));

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

    // println!("DEBUG: iss={iss}, impact={impact}, exploitability={exploitability}");

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
    let mpr = {
      // get mpr value
      let mpr_val = match vec.get(Name::ModifiedPrivilegesRequired) {
        Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined) => {
          match vec.get(Name::PrivilegesRequired) {
            Metric::PrivilegesRequired(val) => val,
            _ => unreachable!(),
          }
        },
        Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None) => PrivilegesRequired::None,
        Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low) => PrivilegesRequired::Low,
        Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High) => PrivilegesRequired::High,
        _ => unreachable!(),
      };

      match (mpr_val, modified_scope_changed) {
        (PrivilegesRequired::None, _) => 0.85,
        (PrivilegesRequired::Low, false) => 0.62,
        (PrivilegesRequired::Low, true) => 0.68,
        (PrivilegesRequired::High, false) => 0.27,
        (PrivilegesRequired::High, true) => 0.5,
      }
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
    // println!("DEBUG: modified_exploitability={modified_exploitability}, mav={mav}, mac={mac}, mpr={mpr}, mui={mui}");

    // are any environmental metrics defined?
    let has_env_metrics = {
      // cache env metric "Not Defined" values
      let m_cr_nd = Metric::ConfidentialityRequirement(Requirement::NotDefined);
      let m_ir_nd = Metric::IntegrityRequirement(Requirement::NotDefined);
      let m_ar_nd = Metric::AvailabilityRequirement(Requirement::NotDefined);
      let m_mav_nd = Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined);
      let m_mac_nd = Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined);
      let m_mpr_nd = Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined);
      let m_mui_nd = Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined);
      let m_ms_nd = Metric::ModifiedScope(ModifiedScope::NotDefined);
      let m_mc_nd = Metric::ModifiedConfidentiality(ModifiedImpact::NotDefined);
      let m_mi_nd = Metric::ModifiedIntegrity(ModifiedImpact::NotDefined);
      let m_ma_nd = Metric::ModifiedAvailability(ModifiedImpact::NotDefined);

      vec.get(Name::ConfidentialityRequirement) != m_cr_nd ||
      vec.get(Name::IntegrityRequirement) != m_ir_nd ||
      vec.get(Name::AvailabilityRequirement) != m_ar_nd ||
      vec.get(Name::ModifiedAttackVector) != m_mav_nd ||
      vec.get(Name::ModifiedAttackComplexity) != m_mac_nd ||
      vec.get(Name::ModifiedPrivilegesRequired) != m_mpr_nd ||
      vec.get(Name::ModifiedUserInteraction) != m_mui_nd ||
      vec.get(Name::ModifiedScope) != m_ms_nd ||
      vec.get(Name::ModifiedConfidentiality) != m_mc_nd ||
      vec.get(Name::ModifiedIntegrity) != m_mi_nd ||
      vec.get(Name::ModifiedAvailability) != m_ma_nd
    };

    // println!("DEBUG: modified_impact={modified_impact}, modified_exploitability={modified_exploitability}, ecm={ecm}, rl={rl}, rc={rc}");

    // EnvironmentalScore =
    // If ModifiedImpact \<= 0  0, else
    //   If ModifiedScope is Unchanged: Roundup ( Roundup [Minimum ([ModifiedImpact + ModifiedExploitability], 10) ] × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
    // Unchanged
    //   If ModifiedScope is Changed: Roundup ( Roundup [Minimum (1.08 × [ModifiedImpact + ModifiedExploitability], 10) ] × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
    let env_score = if has_env_metrics {
      Some(if modified_impact > 0.0 {
        let factor = if modified_scope_changed { 1.08 } else { 1.0 };
        roundup(roundup((factor * (modified_impact + modified_exploitability)).min(10.0), version) * ecm * rl * rc, version)
      } else {
        0.0
      })
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

impl From<Scores> for Score {
  fn from(scores: Scores) -> Score {
    if let Some(score) = scores.environmental {
      score
    } else if let Some(score) = scores.temporal {
      score
    } else {
      scores.base
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
      ), (
        "84832a7a-I:L", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:H/E:H/RL:X/RC:C/CR:M/IR:X/AR:M/MAV:P/MAC:X/MPR:L/MUI:R/MS:U/MC:H/MI:L/MA:X", // val
        Name::Integrity, // metric name
        Metric::Integrity(Impact::Low), // exp
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
    fn test_into_score() {
      let tests = vec!((
        Scores { base: Score(43), temporal: None, environmental: None },
        Score(43), // exp score
      ), (
        Scores { base: Score(43), temporal: Some(Score(32)), environmental: None },
        Score(32), // exp score
      ), (
        Scores { base: Score(43), temporal: Some(Score(32)), environmental: Some(Score(15)) },
        Score(15), // exp score
      ));

      for (scores, exp) in tests {
        assert_eq!(Score::from(scores), exp);
      }
    }

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
            environmental: None,
          }, // exp
        ),

        (
          "CVE-2025-33053", // name
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", // val
          Scores {
            base: Score::from(8.8),
            temporal: None,
            environmental: None,
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
      // these test cases were automatically generated by doing the
      // following in the `cvss-calcs` repo:
      // 1. run `node random.js v3 1000 > v3-tests.json` to generate
      //    1000 random v3 vectors, score them, and write the results as
      //    JSON
      // 2. run `ruby v3-gen-tests.rb < v3-tests.json` to convert the
      //    test cases from JSON to Rust.
      let tests = vec!((
        "4131e324 8.5", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:L/I:N/A:H/E:F/RL:W/RC:C/CR:X/IR:L/AR:M/MAV:A/MAC:L/MPR:N/MUI:N/MS:X/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(8.5)), // exp environmental score
        }, // exp
      ), (
        "357a1370 2.4", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N/E:F/RL:O/RC:R/CR:M/IR:M/AR:X/MAV:A/MAC:X/MPR:H/MUI:X/MS:C/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "d8c2de72 6.6", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N/E:H/RL:W/RC:X/CR:X/IR:X/AR:M/MAV:N/MAC:H/MPR:N/MUI:N/MS:C/MC:N/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "fd864768 3.2", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:H/E:P/RL:O/RC:U/CR:L/IR:H/AR:L/MAV:A/MAC:L/MPR:H/MUI:R/MS:C/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "d73d79e1 1.9", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:H/E:P/RL:T/RC:R/CR:X/IR:H/AR:M/MAV:P/MAC:H/MPR:L/MUI:X/MS:X/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "cab28439 6.2", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:N/E:X/RL:X/RC:X/CR:L/IR:H/AR:M/MAV:P/MAC:H/MPR:N/MUI:R/MS:X/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "9c01727c 6.5", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:L/E:X/RL:U/RC:X/CR:M/IR:H/AR:L/MAV:A/MAC:L/MPR:X/MUI:X/MS:X/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "4a386244 6.6", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N/E:X/RL:T/RC:X/CR:M/IR:X/AR:X/MAV:A/MAC:H/MPR:N/MUI:X/MS:U/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "9e677859 3.5", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:H/E:H/RL:T/RC:R/CR:X/IR:L/AR:M/MAV:A/MAC:L/MPR:H/MUI:R/MS:X/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "2ab83ffb 2.8", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:L/E:U/RL:O/RC:U/CR:M/IR:L/AR:X/MAV:A/MAC:X/MPR:X/MUI:N/MS:X/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "20c0ece8 6.1", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:L/E:F/RL:O/RC:C/CR:M/IR:H/AR:H/MAV:N/MAC:H/MPR:X/MUI:N/MS:X/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "97951ccc 3.5", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:L/E:P/RL:U/RC:R/CR:H/IR:M/AR:M/MAV:N/MAC:L/MPR:H/MUI:N/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "4b928eb1 2.0", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:C/C:L/I:H/A:H/E:U/RL:W/RC:R/CR:X/IR:L/AR:L/MAV:A/MAC:H/MPR:L/MUI:X/MS:U/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "66ac1d0e 7.5", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:C/C:L/I:H/A:N/E:F/RL:U/RC:U/CR:H/IR:H/AR:L/MAV:N/MAC:X/MPR:N/MUI:X/MS:X/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "48276d91 3.8", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N/E:P/RL:U/RC:X/CR:M/IR:H/AR:X/MAV:P/MAC:H/MPR:L/MUI:N/MS:U/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "6972745b 3.6", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N/E:F/RL:T/RC:C/CR:H/IR:M/AR:X/MAV:X/MAC:H/MPR:N/MUI:X/MS:C/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "f6680ca7 2.7", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:H/E:F/RL:T/RC:X/CR:H/IR:L/AR:H/MAV:P/MAC:X/MPR:X/MUI:X/MS:U/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "b034657e 4.9", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:H/E:U/RL:W/RC:X/CR:X/IR:X/AR:X/MAV:L/MAC:L/MPR:N/MUI:R/MS:X/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "99fa12a9 5.4", // test name
        "CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H/E:P/RL:U/RC:X/CR:M/IR:X/AR:M/MAV:X/MAC:X/MPR:X/MUI:N/MS:U/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "0849fcfa 0.0", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:N/E:F/RL:T/RC:U/CR:L/IR:H/AR:X/MAV:N/MAC:H/MPR:L/MUI:N/MS:U/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(3.0), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "eefb5b6b 5.9", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N/E:F/RL:W/RC:X/CR:X/IR:L/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "91ae126d 7.9", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L/E:X/RL:U/RC:C/CR:M/IR:H/AR:M/MAV:A/MAC:X/MPR:N/MUI:R/MS:C/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "d1e19e38 5.6", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H/E:H/RL:O/RC:U/CR:X/IR:H/AR:L/MAV:P/MAC:X/MPR:H/MUI:R/MS:C/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "4cd0f181 6.5", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H/E:X/RL:O/RC:X/CR:H/IR:L/AR:H/MAV:L/MAC:X/MPR:N/MUI:R/MS:X/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "cd7d9de0 6.4", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H/E:H/RL:X/RC:R/CR:M/IR:H/AR:X/MAV:X/MAC:X/MPR:X/MUI:N/MS:X/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "61368147 6.1", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H/E:F/RL:U/RC:C/CR:M/IR:H/AR:M/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "921831a2 2.7", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:L/E:X/RL:O/RC:U/CR:M/IR:L/AR:L/MAV:X/MAC:X/MPR:H/MUI:X/MS:X/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "ab250e0f 5.1", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:N/E:U/RL:O/RC:R/CR:L/IR:L/AR:X/MAV:A/MAC:L/MPR:N/MUI:R/MS:X/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "1e2a6686 2.2", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N/E:X/RL:O/RC:R/CR:H/IR:L/AR:X/MAV:P/MAC:X/MPR:L/MUI:R/MS:C/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "ebb8df91 2.9", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:N/A:H/E:F/RL:W/RC:X/CR:L/IR:X/AR:H/MAV:N/MAC:X/MPR:X/MUI:X/MS:U/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "e949892b 2.8", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RL:U/RC:R/CR:X/IR:M/AR:L/MAV:X/MAC:H/MPR:H/MUI:N/MS:U/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "29c17cec 9.0", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:L/E:X/RL:U/RC:X/CR:H/IR:H/AR:M/MAV:N/MAC:L/MPR:X/MUI:X/MS:X/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(9.0)), // exp environmental score
        }, // exp
      ), (
        "6d5651d2 7.1", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:N/I:N/A:H/E:F/RL:T/RC:R/CR:X/IR:L/AR:H/MAV:A/MAC:L/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "fb1e368d 6.4", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H/E:H/RL:U/RC:R/CR:L/IR:H/AR:H/MAV:N/MAC:X/MPR:H/MUI:N/MS:X/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "e483978e 5.5", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:L/E:F/RL:T/RC:X/CR:M/IR:M/AR:H/MAV:P/MAC:L/MPR:H/MUI:R/MS:X/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "5b68fa3d 5.4", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N/E:X/RL:W/RC:R/CR:X/IR:X/AR:L/MAV:X/MAC:X/MPR:L/MUI:R/MS:U/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "a2d4da1f 7.3", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:L/E:H/RL:T/RC:X/CR:L/IR:M/AR:X/MAV:N/MAC:L/MPR:L/MUI:X/MS:C/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "46302271 4.3", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N/E:H/RL:O/RC:C/CR:H/IR:L/AR:X/MAV:L/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "af272947 5.5", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N/E:H/RL:X/RC:C/CR:X/IR:X/AR:L/MAV:A/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "39af069a 6.9", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:H/E:U/RL:T/RC:R/CR:L/IR:X/AR:M/MAV:N/MAC:X/MPR:L/MUI:N/MS:C/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "b9716739 1.9", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:L/E:H/RL:U/RC:X/CR:L/IR:X/AR:H/MAV:P/MAC:H/MPR:L/MUI:X/MS:C/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "d0ed20a4 3.8", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:H/E:H/RL:O/RC:R/CR:X/IR:H/AR:X/MAV:P/MAC:H/MPR:N/MUI:X/MS:C/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "b0f6984d 4.9", // test name
        "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H/E:H/RL:W/RC:X/CR:M/IR:M/AR:X/MAV:L/MAC:X/MPR:H/MUI:X/MS:C/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "537099a9 7.2", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:W/RC:U/CR:M/IR:H/AR:H/MAV:X/MAC:H/MPR:N/MUI:X/MS:C/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "85170fb6 4.8", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:H/E:F/RL:X/RC:R/CR:M/IR:X/AR:L/MAV:P/MAC:L/MPR:X/MUI:R/MS:C/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "04c22eac 1.8", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:H/E:P/RL:O/RC:R/CR:M/IR:H/AR:X/MAV:P/MAC:X/MPR:X/MUI:X/MS:U/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "f90c4fd1 3.7", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:L/E:H/RL:T/RC:C/CR:L/IR:M/AR:X/MAV:A/MAC:L/MPR:N/MUI:R/MS:C/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "89e51a60 7.9", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:L/E:H/RL:T/RC:X/CR:M/IR:H/AR:M/MAV:N/MAC:L/MPR:X/MUI:N/MS:U/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "5927182b 4.8", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:L/E:H/RL:X/RC:R/CR:M/IR:H/AR:M/MAV:P/MAC:X/MPR:H/MUI:R/MS:C/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "b6f9c1f4 2.6", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/E:P/RL:O/RC:R/CR:X/IR:H/AR:M/MAV:N/MAC:X/MPR:H/MUI:N/MS:X/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "b107cc96 6.7", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:N/E:F/RL:W/RC:X/CR:M/IR:H/AR:M/MAV:L/MAC:L/MPR:L/MUI:R/MS:X/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "2437ca7d 0.0", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N/E:H/RL:T/RC:X/CR:M/IR:H/AR:H/MAV:X/MAC:X/MPR:H/MUI:N/MS:C/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "b4e320e3 0.0", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L/E:H/RL:U/RC:X/CR:L/IR:M/AR:L/MAV:A/MAC:H/MPR:H/MUI:X/MS:C/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(3.1), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "dcaeea41 5.8", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N/E:X/RL:O/RC:U/CR:X/IR:L/AR:H/MAV:A/MAC:X/MPR:N/MUI:R/MS:C/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "5ef5e4ef 4.4", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N/E:F/RL:T/RC:U/CR:H/IR:L/AR:H/MAV:A/MAC:L/MPR:H/MUI:X/MS:U/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "ce765389 4.0", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:C/C:N/I:N/A:L/E:X/RL:T/RC:X/CR:L/IR:X/AR:X/MAV:L/MAC:X/MPR:N/MUI:X/MS:X/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "d1e8b64a 4.6", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N/E:X/RL:U/RC:X/CR:M/IR:X/AR:X/MAV:L/MAC:X/MPR:H/MUI:R/MS:U/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "4c12aff0 3.0", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:L/E:H/RL:O/RC:C/CR:H/IR:M/AR:M/MAV:P/MAC:H/MPR:N/MUI:N/MS:X/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "75340a0f 3.6", // test name
        "CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N/E:P/RL:T/RC:X/CR:X/IR:L/AR:L/MAV:X/MAC:L/MPR:N/MUI:R/MS:X/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "94ddfb60 6.2", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L/E:F/RL:W/RC:U/CR:M/IR:M/AR:X/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "45b33119 5.4", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N/E:F/RL:T/RC:X/CR:M/IR:X/AR:M/MAV:A/MAC:X/MPR:X/MUI:R/MS:X/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.6)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "9318f6d2 7.1", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N/E:X/RL:X/RC:R/CR:L/IR:H/AR:X/MAV:A/MAC:L/MPR:N/MUI:X/MS:U/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "fd785685 1.9", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N/E:H/RL:O/RC:R/CR:H/IR:X/AR:L/MAV:P/MAC:X/MPR:H/MUI:R/MS:C/MC:N/MI:X/MA:N", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "327450d3 5.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N/E:X/RL:O/RC:C/CR:X/IR:X/AR:H/MAV:X/MAC:L/MPR:X/MUI:N/MS:C/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "41531265 7.6", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:H/E:X/RL:O/RC:R/CR:H/IR:H/AR:L/MAV:A/MAC:L/MPR:X/MUI:X/MS:C/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "2e4774ab 5.0", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:H/E:U/RL:U/RC:R/CR:X/IR:H/AR:H/MAV:P/MAC:X/MPR:H/MUI:X/MS:X/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "e99c03c3 5.2", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:L/E:H/RL:X/RC:X/CR:L/IR:H/AR:L/MAV:X/MAC:X/MPR:L/MUI:R/MS:U/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "e03215f0 2.4", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:N/E:H/RL:W/RC:R/CR:M/IR:L/AR:H/MAV:X/MAC:H/MPR:H/MUI:X/MS:X/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "ace5c677 6.7", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:N/E:U/RL:O/RC:R/CR:H/IR:M/AR:L/MAV:X/MAC:X/MPR:L/MUI:N/MS:C/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "25ddd3b8 6.2", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:H/E:F/RL:T/RC:R/CR:L/IR:H/AR:L/MAV:N/MAC:L/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "77895a35 6.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:L/E:F/RL:T/RC:C/CR:M/IR:L/AR:M/MAV:L/MAC:L/MPR:N/MUI:R/MS:X/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "b83a4fc0 4.2", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H/E:X/RL:O/RC:U/CR:H/IR:H/AR:M/MAV:P/MAC:X/MPR:X/MUI:R/MS:U/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "47042c54 6.2", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N/E:P/RL:X/RC:C/CR:L/IR:M/AR:M/MAV:N/MAC:X/MPR:X/MUI:X/MS:X/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(2.4), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "fae0fc28 6.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:N/E:F/RL:T/RC:C/CR:X/IR:X/AR:M/MAV:N/MAC:L/MPR:H/MUI:N/MS:U/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "be2b58f5 4.0", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:N/E:X/RL:U/RC:U/CR:X/IR:L/AR:M/MAV:X/MAC:X/MPR:X/MUI:R/MS:X/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "59724162 8.6", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:H/E:F/RL:U/RC:X/CR:L/IR:L/AR:H/MAV:X/MAC:X/MPR:N/MUI:X/MS:C/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(8.6)), // exp environmental score
        }, // exp
      ), (
        "73d5c7eb 4.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:L/E:F/RL:O/RC:U/CR:X/IR:H/AR:M/MAV:L/MAC:L/MPR:N/MUI:X/MS:C/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "023bd3b7 6.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:L/E:P/RL:T/RC:R/CR:X/IR:L/AR:M/MAV:A/MAC:L/MPR:H/MUI:X/MS:C/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "91bdfcff 3.1", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:N/A:N/E:U/RL:X/RC:U/CR:M/IR:M/AR:L/MAV:A/MAC:H/MPR:H/MUI:X/MS:C/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "d619d46a 7.1", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:N/E:F/RL:X/RC:C/CR:H/IR:X/AR:H/MAV:X/MAC:H/MPR:H/MUI:N/MS:X/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "49726671 5.0", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:N/I:N/A:N/E:P/RL:W/RC:X/CR:L/IR:M/AR:M/MAV:X/MAC:X/MPR:X/MUI:N/MS:U/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "5e4b78df 3.0", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/E:X/RL:O/RC:R/CR:L/IR:H/AR:L/MAV:L/MAC:H/MPR:N/MUI:X/MS:C/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "6cd31519 4.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:U/C:L/I:H/A:H/E:U/RL:O/RC:U/CR:H/IR:L/AR:M/MAV:P/MAC:X/MPR:X/MUI:X/MS:U/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "0dde44fc 6.5", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:L/E:X/RL:T/RC:X/CR:H/IR:M/AR:H/MAV:N/MAC:L/MPR:X/MUI:N/MS:U/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "bb2b384d 6.2", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:N/E:X/RL:X/RC:R/CR:M/IR:L/AR:H/MAV:X/MAC:H/MPR:X/MUI:N/MS:X/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "7e33aa51 4.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:L/E:F/RL:X/RC:U/CR:X/IR:H/AR:M/MAV:L/MAC:X/MPR:X/MUI:X/MS:X/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "e2431e01 7.6", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:H/E:U/RL:X/RC:C/CR:X/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:X/MS:U/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "7131b298 5.6", // test name
        "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:L/E:P/RL:W/RC:U/CR:X/IR:M/AR:H/MAV:X/MAC:L/MPR:L/MUI:N/MS:X/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(1.8)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "f882e0a2 5.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N/E:X/RL:U/RC:C/CR:L/IR:X/AR:M/MAV:P/MAC:X/MPR:X/MUI:R/MS:X/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(8.7)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "c2b4f9d5 8.1", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H/E:X/RL:T/RC:X/CR:X/IR:M/AR:X/MAV:L/MAC:X/MPR:X/MUI:N/MS:X/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(8.9), // exp base score
          temporal: Some(Score::from(8.6)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "5cc912ba 3.0", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N/E:F/RL:X/RC:X/CR:L/IR:M/AR:L/MAV:X/MAC:H/MPR:H/MUI:R/MS:C/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "46daf5f4 4.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N/E:U/RL:U/RC:U/CR:M/IR:X/AR:L/MAV:P/MAC:L/MPR:N/MUI:R/MS:C/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "67f312c2 6.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L/E:X/RL:O/RC:U/CR:M/IR:M/AR:M/MAV:P/MAC:H/MPR:N/MUI:X/MS:C/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "52ebaf02 6.5", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L/E:U/RL:U/RC:X/CR:L/IR:H/AR:M/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "ea78ab00 4.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H/E:P/RL:U/RC:C/CR:H/IR:H/AR:L/MAV:L/MAC:X/MPR:X/MUI:N/MS:U/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "4d21207e 3.4", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N/E:H/RL:O/RC:C/CR:M/IR:X/AR:X/MAV:X/MAC:L/MPR:H/MUI:X/MS:X/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "008cde36 4.2", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H/E:X/RL:W/RC:R/CR:M/IR:M/AR:L/MAV:L/MAC:L/MPR:H/MUI:R/MS:X/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(8.4), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "9cdc83e6 8.2", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:L/E:H/RL:X/RC:X/CR:M/IR:H/AR:X/MAV:X/MAC:L/MPR:L/MUI:R/MS:X/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(8.2)), // exp environmental score
        }, // exp
      ), (
        "df60b9dc 7.1", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:L/E:X/RL:W/RC:R/CR:H/IR:X/AR:L/MAV:P/MAC:X/MPR:N/MUI:N/MS:C/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "d88c1b94 5.4", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:H/E:U/RL:T/RC:R/CR:H/IR:M/AR:L/MAV:L/MAC:L/MPR:X/MUI:X/MS:U/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "c2691dc2 3.4", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L/E:F/RL:T/RC:U/CR:L/IR:H/AR:L/MAV:L/MAC:L/MPR:H/MUI:N/MS:U/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "c734f55b 4.9", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N/E:F/RL:W/RC:X/CR:M/IR:M/AR:M/MAV:A/MAC:L/MPR:X/MUI:X/MS:X/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "1fe90dcd 7.7", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N/E:X/RL:W/RC:R/CR:M/IR:M/AR:X/MAV:N/MAC:H/MPR:N/MUI:R/MS:C/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(3.0), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "bd792ef4 4.6", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:L/E:X/RL:T/RC:C/CR:L/IR:L/AR:L/MAV:N/MAC:X/MPR:L/MUI:N/MS:X/MC:N/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "df358d6b 3.7", // test name
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:N/E:P/RL:X/RC:R/CR:L/IR:M/AR:M/MAV:N/MAC:X/MPR:X/MUI:R/MS:C/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "e5e0c418 4.9", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/E:U/RL:O/RC:R/CR:H/IR:M/AR:L/MAV:L/MAC:H/MPR:X/MUI:N/MS:C/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(9.6), // exp base score
          temporal: Some(Score::from(8.0)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "ca111fda 7.1", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:U/RL:W/RC:U/CR:H/IR:M/AR:M/MAV:N/MAC:X/MPR:H/MUI:N/MS:X/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "5ae05c6f 7.2", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L/E:H/RL:W/RC:X/CR:H/IR:H/AR:H/MAV:P/MAC:L/MPR:N/MUI:N/MS:X/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "50dc5983 6.5", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H/E:H/RL:O/RC:U/CR:H/IR:X/AR:X/MAV:A/MAC:L/MPR:N/MUI:R/MS:X/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(9.3), // exp base score
          temporal: Some(Score::from(8.2)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "553a2da5 5.9", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H/E:X/RL:U/RC:U/CR:X/IR:M/AR:L/MAV:X/MAC:H/MPR:X/MUI:R/MS:C/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "58379589 2.6", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N/E:X/RL:X/RC:C/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:N/MS:U/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "ddcbad06 3.8", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L/E:U/RL:X/RC:U/CR:M/IR:L/AR:M/MAV:L/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "bdf3f320 3.0", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N/E:X/RL:O/RC:R/CR:H/IR:X/AR:X/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "988adfd7 7.8", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:L/E:H/RL:U/RC:X/CR:M/IR:M/AR:L/MAV:A/MAC:X/MPR:X/MUI:N/MS:C/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "0a800696 7.6", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:L/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:L/MUI:N/MS:C/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "bb617a7a 3.4", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:H/E:F/RL:W/RC:C/CR:X/IR:M/AR:X/MAV:L/MAC:H/MPR:X/MUI:R/MS:U/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(8.2)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "9ab21941 4.9", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:X/MAV:L/MAC:X/MPR:X/MUI:R/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(8.7)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "819a0e68 4.9", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:H/E:P/RL:O/RC:R/CR:X/IR:X/AR:L/MAV:X/MAC:X/MPR:L/MUI:N/MS:U/MC:N/MI:X/MA:N", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "4dff8c57 7.1", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:L/E:U/RL:X/RC:C/CR:M/IR:H/AR:H/MAV:L/MAC:H/MPR:N/MUI:X/MS:X/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "bb913237 3.0", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:H/E:U/RL:X/RC:X/CR:L/IR:M/AR:M/MAV:P/MAC:H/MPR:H/MUI:R/MS:X/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "46c5c395 8.6", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N/E:F/RL:O/RC:C/CR:X/IR:X/AR:H/MAV:N/MAC:L/MPR:X/MUI:N/MS:C/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(8.6)), // exp environmental score
        }, // exp
      ), (
        "883fdb22 3.9", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N/E:H/RL:U/RC:R/CR:M/IR:X/AR:X/MAV:P/MAC:L/MPR:N/MUI:N/MS:C/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "f9caa85f 4.9", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:N/E:X/RL:O/RC:U/CR:X/IR:H/AR:X/MAV:P/MAC:H/MPR:L/MUI:R/MS:X/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "33426f2e 7.8", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L/E:U/RL:X/RC:X/CR:M/IR:X/AR:H/MAV:A/MAC:X/MPR:N/MUI:X/MS:C/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "d434cc1f 5.6", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N/E:F/RL:W/RC:C/CR:H/IR:X/AR:M/MAV:N/MAC:H/MPR:N/MUI:N/MS:X/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "f2c00236 9.3", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N/E:H/RL:U/RC:U/CR:X/IR:X/AR:X/MAV:N/MAC:L/MPR:X/MUI:N/MS:C/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(9.3)), // exp environmental score
        }, // exp
      ), (
        "2715e064 3.1", // test name
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H/E:X/RL:U/RC:U/CR:H/IR:M/AR:L/MAV:P/MAC:H/MPR:H/MUI:X/MS:C/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "bb4c83d0 4.1", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:H/E:H/RL:O/RC:X/CR:L/IR:M/AR:H/MAV:X/MAC:L/MPR:L/MUI:X/MS:C/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "19dda9d3 8.7", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:H/E:X/RL:O/RC:U/CR:M/IR:H/AR:M/MAV:N/MAC:L/MPR:L/MUI:X/MS:C/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(8.7)), // exp environmental score
        }, // exp
      ), (
        "8598a72f 2.6", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N/E:X/RL:U/RC:R/CR:L/IR:M/AR:M/MAV:P/MAC:L/MPR:X/MUI:R/MS:C/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "c3aaeb71 6.2", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H/E:P/RL:T/RC:R/CR:X/IR:L/AR:L/MAV:A/MAC:X/MPR:L/MUI:R/MS:C/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "e96f9296 2.6", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:N/E:P/RL:U/RC:U/CR:X/IR:L/AR:X/MAV:P/MAC:L/MPR:N/MUI:X/MS:X/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "08f5cb47 5.9", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:H/A:H/E:F/RL:T/RC:C/CR:H/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:R/MS:U/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "135b3a7d 4.3", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:H/A:N/E:P/RL:W/RC:R/CR:H/IR:X/AR:M/MAV:P/MAC:H/MPR:L/MUI:X/MS:U/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "78fadef5 6.9", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:N/I:H/A:L/E:H/RL:W/RC:C/CR:H/IR:L/AR:L/MAV:L/MAC:X/MPR:N/MUI:N/MS:U/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "21a49d06 0.0", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:H/E:U/RL:W/RC:R/CR:M/IR:L/AR:M/MAV:N/MAC:L/MPR:N/MUI:R/MS:U/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "1fbffcc8 6.3", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:H/E:H/RL:W/RC:R/CR:L/IR:L/AR:H/MAV:N/MAC:L/MPR:H/MUI:N/MS:X/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "574f70ed 5.5", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:L/E:F/RL:T/RC:C/CR:L/IR:M/AR:X/MAV:P/MAC:L/MPR:H/MUI:X/MS:C/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "55d98de8 4.7", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N/E:X/RL:X/RC:R/CR:X/IR:M/AR:H/MAV:X/MAC:L/MPR:X/MUI:R/MS:U/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "6f35ea59 4.8", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:L/E:H/RL:W/RC:X/CR:X/IR:L/AR:X/MAV:N/MAC:L/MPR:H/MUI:N/MS:U/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "4dda92db 4.4", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:H/E:X/RL:T/RC:R/CR:X/IR:H/AR:X/MAV:L/MAC:L/MPR:L/MUI:N/MS:C/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "aad8f74d 3.5", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:N/E:P/RL:U/RC:U/CR:H/IR:L/AR:L/MAV:L/MAC:X/MPR:X/MUI:X/MS:U/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "79adea01 4.9", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:N/E:X/RL:X/RC:R/CR:L/IR:M/AR:H/MAV:P/MAC:X/MPR:L/MUI:R/MS:C/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "5f04cb88 3.1", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H/E:F/RL:T/RC:R/CR:M/IR:H/AR:L/MAV:L/MAC:L/MPR:L/MUI:R/MS:U/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "7503a433 3.5", // test name
        "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L/E:U/RL:O/RC:U/CR:H/IR:X/AR:X/MAV:N/MAC:L/MPR:N/MUI:X/MS:U/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.5)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "4dc24847 7.4", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H/E:F/RL:W/RC:C/CR:H/IR:H/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:C/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "58d77a33 5.9", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N/E:P/RL:O/RC:R/CR:X/IR:M/AR:X/MAV:N/MAC:H/MPR:L/MUI:X/MS:U/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "01159f40 5.8", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H/E:U/RL:U/RC:U/CR:L/IR:H/AR:M/MAV:L/MAC:X/MPR:N/MUI:N/MS:X/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "f764fe7a 6.3", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H/E:X/RL:W/RC:U/CR:M/IR:L/AR:M/MAV:X/MAC:L/MPR:H/MUI:X/MS:C/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "1d05f3c2 6.3", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:L/E:P/RL:T/RC:U/CR:H/IR:M/AR:H/MAV:L/MAC:H/MPR:L/MUI:R/MS:X/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(4.2), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "a80ceac5 2.1", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:L/E:X/RL:O/RC:C/CR:X/IR:H/AR:M/MAV:N/MAC:X/MPR:H/MUI:N/MS:U/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.2), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "6950ad9f 5.0", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H/E:F/RL:T/RC:C/CR:L/IR:X/AR:X/MAV:N/MAC:H/MPR:X/MUI:X/MS:C/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "cc2cbced 2.4", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H/E:H/RL:T/RC:R/CR:L/IR:M/AR:M/MAV:X/MAC:X/MPR:H/MUI:X/MS:C/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "2df775fd 2.1", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:N/E:X/RL:W/RC:C/CR:X/IR:X/AR:H/MAV:P/MAC:L/MPR:L/MUI:X/MS:X/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "163be6da 4.8", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C/CR:X/IR:M/AR:H/MAV:P/MAC:H/MPR:X/MUI:R/MS:X/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "7ada095f 6.0", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H/E:U/RL:X/RC:R/CR:M/IR:H/AR:M/MAV:L/MAC:X/MPR:X/MUI:N/MS:C/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "a93abe5c 0.0", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N/E:X/RL:X/RC:X/CR:H/IR:X/AR:H/MAV:N/MAC:X/MPR:L/MUI:N/MS:U/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(2.5), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "f2d2592b 3.3", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:H/E:P/RL:W/RC:C/CR:L/IR:L/AR:L/MAV:P/MAC:X/MPR:H/MUI:N/MS:C/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "50e6df36 6.0", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:L/E:P/RL:X/RC:R/CR:X/IR:X/AR:X/MAV:L/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "31e76038 6.3", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:N/A:L/E:P/RL:U/RC:X/CR:M/IR:L/AR:X/MAV:X/MAC:H/MPR:N/MUI:X/MS:C/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "bd9f84fa 5.4", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:N/A:N/E:U/RL:U/RC:X/CR:X/IR:H/AR:M/MAV:L/MAC:L/MPR:X/MUI:R/MS:X/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "9b1dbf34 6.4", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:L/E:U/RL:O/RC:R/CR:M/IR:X/AR:X/MAV:A/MAC:L/MPR:H/MUI:R/MS:X/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "2806079f 0.0", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:H/E:P/RL:X/RC:C/CR:M/IR:M/AR:L/MAV:P/MAC:X/MPR:X/MUI:X/MS:C/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "f5b584f1 4.8", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:N/E:H/RL:U/RC:R/CR:M/IR:M/AR:M/MAV:N/MAC:H/MPR:X/MUI:N/MS:C/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(2.5), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "3bd97516 3.0", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:N/A:L/E:F/RL:O/RC:U/CR:H/IR:X/AR:M/MAV:N/MAC:H/MPR:X/MUI:N/MS:X/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(2.5), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "22eba661 5.3", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N/E:U/RL:O/RC:U/CR:H/IR:X/AR:L/MAV:A/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "92e34d6c 3.2", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N/E:U/RL:T/RC:R/CR:H/IR:L/AR:L/MAV:A/MAC:L/MPR:H/MUI:R/MS:X/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(2.2), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "6e4cebcb 6.2", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N/E:X/RL:T/RC:U/CR:L/IR:H/AR:L/MAV:L/MAC:L/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "c21bb6ff 5.5", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:H/E:F/RL:O/RC:X/CR:M/IR:X/AR:L/MAV:A/MAC:L/MPR:L/MUI:X/MS:U/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "a2121ab3 3.7", // test name
        "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H/E:F/RL:W/RC:C/CR:H/IR:L/AR:L/MAV:A/MAC:L/MPR:L/MUI:R/MS:U/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "8d170332 5.5", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:U/RC:X/CR:X/IR:X/AR:X/MAV:A/MAC:H/MPR:H/MUI:N/MS:U/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "7c866008 7.7", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:H/E:X/RL:U/RC:U/CR:H/IR:M/AR:L/MAV:N/MAC:L/MPR:L/MUI:N/MS:U/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "8a4bd434 6.5", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N/E:H/RL:O/RC:C/CR:X/IR:X/AR:H/MAV:N/MAC:X/MPR:N/MUI:X/MS:C/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "e3ddf34e 4.3", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H/E:P/RL:T/RC:R/CR:M/IR:L/AR:L/MAV:L/MAC:L/MPR:L/MUI:N/MS:X/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "a37bcbc9 3.7", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:L/E:P/RL:X/RC:R/CR:M/IR:L/AR:M/MAV:N/MAC:H/MPR:N/MUI:N/MS:C/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "038d1947 2.9", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L/E:P/RL:U/RC:R/CR:X/IR:H/AR:X/MAV:L/MAC:X/MPR:N/MUI:X/MS:X/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "11a8213e 5.6", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:U/CR:H/IR:X/AR:X/MAV:L/MAC:X/MPR:H/MUI:R/MS:U/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "ebf726d2 6.6", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:L/E:X/RL:X/RC:R/CR:X/IR:L/AR:L/MAV:A/MAC:L/MPR:N/MUI:X/MS:X/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "b41f8aae 2.2", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:H/E:H/RL:U/RC:C/CR:X/IR:M/AR:X/MAV:P/MAC:X/MPR:X/MUI:N/MS:C/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "b3386320 7.0", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L/E:P/RL:T/RC:C/CR:X/IR:H/AR:X/MAV:X/MAC:L/MPR:L/MUI:X/MS:X/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "7ee4e1e1 3.6", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H/E:U/RL:U/RC:C/CR:M/IR:H/AR:L/MAV:L/MAC:H/MPR:N/MUI:R/MS:X/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "d9a1755f 0.0", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L/E:U/RL:U/RC:U/CR:M/IR:H/AR:H/MAV:L/MAC:H/MPR:N/MUI:X/MS:C/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "0a7fdba5 6.4", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L/E:X/RL:T/RC:C/CR:H/IR:H/AR:H/MAV:P/MAC:L/MPR:X/MUI:R/MS:X/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "397e267e 5.1", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L/E:F/RL:T/RC:U/CR:L/IR:X/AR:L/MAV:N/MAC:L/MPR:H/MUI:X/MS:U/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "c4c7f472 3.6", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H/E:H/RL:X/RC:U/CR:X/IR:H/AR:L/MAV:X/MAC:X/MPR:H/MUI:X/MS:X/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "9fc302de 4.8", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H/E:F/RL:T/RC:U/CR:H/IR:H/AR:X/MAV:P/MAC:H/MPR:X/MUI:R/MS:U/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "71f3aa74 6.8", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:H/E:H/RL:O/RC:R/CR:X/IR:M/AR:M/MAV:L/MAC:X/MPR:L/MUI:R/MS:C/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "9002756c 5.5", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L/E:P/RL:O/RC:C/CR:M/IR:L/AR:H/MAV:N/MAC:L/MPR:L/MUI:R/MS:X/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "33afea29 4.2", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:L/E:X/RL:X/RC:R/CR:L/IR:L/AR:L/MAV:L/MAC:H/MPR:L/MUI:X/MS:U/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "dc99424e 6.9", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N/E:H/RL:X/RC:U/CR:X/IR:M/AR:H/MAV:A/MAC:H/MPR:N/MUI:R/MS:X/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "b48f7dc0 6.5", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:U/RC:U/CR:M/IR:L/AR:M/MAV:N/MAC:X/MPR:L/MUI:R/MS:C/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "a44c4fbf 5.7", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:H/E:U/RL:T/RC:R/CR:M/IR:M/AR:M/MAV:X/MAC:L/MPR:L/MUI:R/MS:C/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "04e58356 5.1", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H/E:F/RL:W/RC:U/CR:M/IR:H/AR:M/MAV:X/MAC:H/MPR:L/MUI:R/MS:X/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "a8d87b03 6.1", // test name
        "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N/E:U/RL:W/RC:U/CR:H/IR:H/AR:H/MAV:L/MAC:X/MPR:L/MUI:R/MS:C/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(2.5), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "a3e5b22e 4.9", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:H/E:U/RL:U/RC:R/CR:X/IR:L/AR:H/MAV:N/MAC:H/MPR:L/MUI:N/MS:C/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "2140c5cf 8.7", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:L/E:U/RL:U/RC:X/CR:X/IR:X/AR:H/MAV:A/MAC:X/MPR:N/MUI:N/MS:C/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(8.7)), // exp environmental score
        }, // exp
      ), (
        "4ec72dbc 6.6", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:H/E:H/RL:U/RC:R/CR:X/IR:X/AR:M/MAV:L/MAC:X/MPR:L/MUI:R/MS:U/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "612955e4 4.3", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N/E:U/RL:X/RC:R/CR:L/IR:H/AR:L/MAV:L/MAC:X/MPR:L/MUI:X/MS:C/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "c72f6e49 5.4", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N/E:F/RL:X/RC:U/CR:M/IR:L/AR:H/MAV:P/MAC:L/MPR:H/MUI:N/MS:U/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "86497329 6.5", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H/E:H/RL:U/RC:R/CR:M/IR:X/AR:M/MAV:L/MAC:L/MPR:H/MUI:X/MS:X/MC:X/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "ca23ccd1 5.7", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:L/E:U/RL:W/RC:X/CR:X/IR:X/AR:H/MAV:P/MAC:H/MPR:N/MUI:X/MS:X/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "458cb3e4 3.5", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:H/E:X/RL:O/RC:R/CR:X/IR:L/AR:X/MAV:N/MAC:L/MPR:X/MUI:N/MS:X/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "44e05435 7.3", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N/E:H/RL:W/RC:U/CR:L/IR:X/AR:H/MAV:X/MAC:H/MPR:N/MUI:X/MS:C/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "2e1344be 5.9", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:H/I:N/A:L/E:P/RL:X/RC:R/CR:X/IR:X/AR:L/MAV:X/MAC:H/MPR:N/MUI:R/MS:X/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "470c68cc 6.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:H/E:F/RL:W/RC:R/CR:M/IR:L/AR:M/MAV:N/MAC:L/MPR:L/MUI:X/MS:U/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "05218192 7.5", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:X/CR:M/IR:H/AR:M/MAV:X/MAC:X/MPR:L/MUI:R/MS:X/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "d56ca5a4 1.2", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:L/I:N/A:N/E:U/RL:X/RC:U/CR:L/IR:H/AR:L/MAV:P/MAC:L/MPR:N/MUI:X/MS:C/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "30fee97e 0.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:L/E:U/RL:W/RC:R/CR:H/IR:X/AR:X/MAV:X/MAC:H/MPR:N/MUI:N/MS:C/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "49e7ebfa 4.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:N/E:F/RL:T/RC:U/CR:M/IR:X/AR:L/MAV:A/MAC:H/MPR:X/MUI:X/MS:U/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "99ecf78d 2.4", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:N/I:N/A:L/E:P/RL:W/RC:X/CR:L/IR:X/AR:X/MAV:N/MAC:H/MPR:X/MUI:R/MS:X/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "a429d031 6.2", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H/E:F/RL:X/RC:X/CR:M/IR:L/AR:L/MAV:N/MAC:H/MPR:N/MUI:X/MS:X/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "ba85d750 7.9", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:L/E:X/RL:W/RC:X/CR:X/IR:X/AR:L/MAV:A/MAC:X/MPR:N/MUI:R/MS:C/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(3.1), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "c8078def 6.5", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:L/E:X/RL:X/RC:R/CR:L/IR:X/AR:X/MAV:N/MAC:H/MPR:L/MUI:N/MS:C/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(3.1), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "6778bc57 2.7", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:N/E:F/RL:W/RC:C/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:L/MUI:X/MS:X/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(2.0), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "4ec4771e 4.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:L/E:H/RL:O/RC:R/CR:M/IR:L/AR:M/MAV:A/MAC:X/MPR:X/MUI:R/MS:U/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(3.1), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "8973e18e 5.4", // test name
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:N/E:F/RL:T/RC:U/CR:L/IR:H/AR:H/MAV:N/MAC:X/MPR:N/MUI:X/MS:U/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "6dd16332 8.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L/E:H/RL:U/RC:X/CR:H/IR:M/AR:H/MAV:N/MAC:L/MPR:L/MUI:R/MS:U/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(8.0)), // exp environmental score
        }, // exp
      ), (
        "6cf885a5 3.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N/E:P/RL:T/RC:C/CR:L/IR:L/AR:M/MAV:P/MAC:X/MPR:N/MUI:N/MS:C/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "efd5d83c 2.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L/E:U/RL:T/RC:U/CR:H/IR:M/AR:M/MAV:P/MAC:L/MPR:L/MUI:N/MS:X/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "3bd1a1f1 2.6", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N/E:X/RL:W/RC:X/CR:H/IR:H/AR:X/MAV:L/MAC:H/MPR:H/MUI:X/MS:U/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "af011c5b 0.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:F/RL:W/RC:U/CR:L/IR:M/AR:L/MAV:X/MAC:H/MPR:H/MUI:R/MS:X/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "6aa74f12 5.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L/E:U/RL:X/RC:X/CR:L/IR:L/AR:X/MAV:A/MAC:H/MPR:H/MUI:X/MS:C/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "ae65d77c 5.6", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/E:U/RL:T/RC:R/CR:H/IR:M/AR:X/MAV:A/MAC:H/MPR:N/MUI:R/MS:U/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "33005b23 1.9", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L/E:X/RL:U/RC:U/CR:X/IR:X/AR:L/MAV:P/MAC:X/MPR:H/MUI:X/MS:C/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "140a8bf3 6.1", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:H/E:H/RL:U/RC:X/CR:H/IR:H/AR:M/MAV:X/MAC:H/MPR:H/MUI:R/MS:U/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(8.1)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "5c33a97c 3.3", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:N/E:U/RL:U/RC:U/CR:X/IR:L/AR:H/MAV:X/MAC:H/MPR:X/MUI:N/MS:U/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "a0a16abc 5.8", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N/E:P/RL:U/RC:U/CR:L/IR:H/AR:H/MAV:P/MAC:L/MPR:X/MUI:N/MS:U/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "354e3d65 2.3", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N/E:H/RL:U/RC:R/CR:M/IR:X/AR:M/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(2.3)), // exp environmental score
        }, // exp
      ), (
        "51b069ee 5.8", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N/E:P/RL:T/RC:R/CR:H/IR:X/AR:X/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "586f8283 4.3", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:L/E:X/RL:X/RC:R/CR:H/IR:X/AR:L/MAV:X/MAC:H/MPR:L/MUI:R/MS:X/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "c2cbc8a9 6.3", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:F/RL:T/RC:C/CR:X/IR:X/AR:X/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "3157d993 0.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:H/E:U/RL:T/RC:C/CR:H/IR:M/AR:X/MAV:X/MAC:X/MPR:H/MUI:N/MS:C/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "cdb15bb4 8.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:H/E:H/RL:T/RC:C/CR:L/IR:X/AR:H/MAV:A/MAC:X/MPR:X/MUI:R/MS:C/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(8.0)), // exp environmental score
        }, // exp
      ), (
        "5144b75d 3.8", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:H/E:X/RL:O/RC:U/CR:H/IR:H/AR:M/MAV:A/MAC:X/MPR:X/MUI:R/MS:C/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "a1ac3830 4.7", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L/E:H/RL:X/RC:R/CR:X/IR:M/AR:L/MAV:N/MAC:H/MPR:X/MUI:R/MS:X/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(3.9), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "09bb1824 5.9", // test name
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L/E:P/RL:U/RC:X/CR:H/IR:L/AR:H/MAV:A/MAC:X/MPR:H/MUI:R/MS:U/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(3.9), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "d9b6b652 4.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/E:X/RL:X/RC:R/CR:X/IR:L/AR:M/MAV:A/MAC:L/MPR:L/MUI:N/MS:C/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(9.2), // exp base score
          temporal: Some(Score::from(8.9)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "309ba2e9 6.7", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:X/RL:X/RC:R/CR:M/IR:L/AR:H/MAV:X/MAC:L/MPR:L/MUI:N/MS:X/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "d6d311da 4.1", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L/E:F/RL:W/RC:X/CR:X/IR:H/AR:X/MAV:X/MAC:L/MPR:N/MUI:X/MS:X/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "b480c95c 7.8", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H/E:U/RL:O/RC:C/CR:H/IR:L/AR:H/MAV:A/MAC:L/MPR:L/MUI:N/MS:X/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(7.8)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "8b1419b6 5.6", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H/E:X/RL:X/RC:R/CR:H/IR:X/AR:L/MAV:X/MAC:L/MPR:L/MUI:R/MS:U/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(8.7)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "a6d5e596 5.7", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:T/RC:R/CR:M/IR:M/AR:X/MAV:P/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(8.4), // exp base score
          temporal: Some(Score::from(7.8)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "408f30f3 6.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/E:P/RL:W/RC:U/CR:X/IR:M/AR:L/MAV:L/MAC:X/MPR:L/MUI:X/MS:X/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "57d8463b 5.3", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H/E:U/RL:T/RC:R/CR:H/IR:H/AR:L/MAV:P/MAC:H/MPR:X/MUI:R/MS:U/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "cc4f999e 7.2", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N/E:H/RL:T/RC:C/CR:M/IR:M/AR:L/MAV:N/MAC:L/MPR:N/MUI:X/MS:C/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "30fffe32 4.6", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N/E:H/RL:W/RC:C/CR:L/IR:M/AR:X/MAV:A/MAC:L/MPR:N/MUI:N/MS:C/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "4d9b73c4 5.2", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:L/E:X/RL:W/RC:C/CR:X/IR:L/AR:X/MAV:N/MAC:X/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "fceafbe9 8.9", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:F/RL:U/RC:X/CR:X/IR:H/AR:H/MAV:N/MAC:X/MPR:H/MUI:N/MS:C/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(7.6)), // exp temporal score
          environmental: Some(Score::from(8.9)), // exp environmental score
        }, // exp
      ), (
        "f46f39f4 2.6", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N/E:X/RL:O/RC:X/CR:M/IR:X/AR:L/MAV:A/MAC:X/MPR:H/MUI:N/MS:X/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "fd61b92c 6.8", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L/E:X/RL:T/RC:R/CR:H/IR:L/AR:H/MAV:X/MAC:X/MPR:N/MUI:X/MS:X/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "01cedaea 6.8", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L/E:P/RL:O/RC:C/CR:H/IR:X/AR:X/MAV:X/MAC:H/MPR:X/MUI:N/MS:C/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "bc245289 4.7", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N/E:P/RL:X/RC:X/CR:L/IR:M/AR:M/MAV:N/MAC:X/MPR:H/MUI:X/MS:U/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "e3558835 7.8", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H/E:H/RL:W/RC:U/CR:X/IR:L/AR:H/MAV:N/MAC:X/MPR:X/MUI:X/MS:X/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "dec0bda1 0.0", // test name
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H/E:P/RL:W/RC:U/CR:X/IR:X/AR:H/MAV:A/MAC:X/MPR:X/MUI:N/MS:U/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "12dc337a 8.3", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L/E:X/RL:T/RC:R/CR:X/IR:H/AR:X/MAV:A/MAC:L/MPR:L/MUI:N/MS:C/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(8.3)), // exp environmental score
        }, // exp
      ), (
        "e4732d4f 7.2", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:N/E:U/RL:X/RC:R/CR:M/IR:H/AR:M/MAV:A/MAC:X/MPR:N/MUI:N/MS:C/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "8cc5f6b2 5.4", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:N/E:X/RL:X/RC:U/CR:M/IR:L/AR:L/MAV:P/MAC:X/MPR:L/MUI:X/MS:C/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "278f3d62 7.4", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:L/E:F/RL:U/RC:C/CR:H/IR:H/AR:M/MAV:A/MAC:H/MPR:H/MUI:N/MS:C/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "a84e7ed1 5.8", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:N/E:F/RL:T/RC:U/CR:X/IR:X/AR:X/MAV:A/MAC:H/MPR:L/MUI:X/MS:U/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "cfe46816 4.2", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:L/I:N/A:H/E:X/RL:O/RC:R/CR:X/IR:X/AR:X/MAV:L/MAC:L/MPR:H/MUI:X/MS:C/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "d4d9636e 4.2", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:L/E:P/RL:W/RC:X/CR:X/IR:X/AR:X/MAV:P/MAC:H/MPR:L/MUI:N/MS:U/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(3.0), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "f31865f7 3.7", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:L/E:X/RL:X/RC:X/CR:X/IR:L/AR:M/MAV:L/MAC:X/MPR:X/MUI:R/MS:C/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(3.0), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "f65494f3 3.4", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:H/E:F/RL:O/RC:R/CR:L/IR:H/AR:L/MAV:X/MAC:H/MPR:X/MUI:X/MS:X/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "f0811923 6.2", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:H/E:X/RL:T/RC:U/CR:H/IR:H/AR:H/MAV:P/MAC:H/MPR:N/MUI:R/MS:C/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "0b68321f 5.9", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:L/E:U/RL:O/RC:R/CR:M/IR:L/AR:H/MAV:N/MAC:L/MPR:X/MUI:N/MS:X/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "138b8484 4.3", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N/E:F/RL:T/RC:X/CR:H/IR:L/AR:M/MAV:X/MAC:H/MPR:H/MUI:R/MS:X/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(2.2), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "53d54b9d 3.8", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:H/E:X/RL:X/RC:U/CR:H/IR:L/AR:L/MAV:X/MAC:H/MPR:L/MUI:X/MS:C/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "2ba54fc9 6.5", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:H/A:H/E:U/RL:U/RC:C/CR:X/IR:H/AR:X/MAV:P/MAC:H/MPR:N/MUI:N/MS:C/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "a41776a4 6.5", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:H/E:F/RL:W/RC:R/CR:H/IR:M/AR:H/MAV:A/MAC:X/MPR:N/MUI:R/MS:U/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "333fcb2a 5.5", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:L/E:H/RL:W/RC:R/CR:X/IR:L/AR:M/MAV:L/MAC:X/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "e945614f 8.1", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:N/I:H/A:H/E:H/RL:U/RC:R/CR:L/IR:H/AR:H/MAV:A/MAC:L/MPR:X/MUI:N/MS:X/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "8075ba92 5.4", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:N/I:H/A:L/E:P/RL:U/RC:C/CR:M/IR:X/AR:L/MAV:P/MAC:H/MPR:X/MUI:R/MS:X/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "634a5505 2.6", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:L/A:H/E:H/RL:T/RC:U/CR:M/IR:X/AR:L/MAV:N/MAC:L/MPR:H/MUI:R/MS:X/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "39698405 6.1", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:L/E:F/RL:X/RC:X/CR:H/IR:L/AR:X/MAV:P/MAC:H/MPR:L/MUI:R/MS:X/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "07dbf31c 4.8", // test name
        "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:H/A:H/E:P/RL:U/RC:R/CR:M/IR:M/AR:M/MAV:A/MAC:X/MPR:H/MUI:N/MS:U/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "454319af 6.1", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H/E:F/RL:X/RC:C/CR:X/IR:L/AR:X/MAV:A/MAC:H/MPR:X/MUI:R/MS:U/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(8.3)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "2e7b40a6 6.6", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N/E:F/RL:O/RC:C/CR:X/IR:X/AR:X/MAV:N/MAC:X/MPR:X/MUI:R/MS:C/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "bd828c8a 6.9", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:U/RL:U/RC:R/CR:H/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:X/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "93b5cfde 8.8", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:H/E:U/RL:U/RC:R/CR:H/IR:L/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:X/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(8.8)), // exp environmental score
        }, // exp
      ), (
        "e16dd032 7.5", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:H/A:H/E:U/RL:U/RC:R/CR:X/IR:H/AR:X/MAV:X/MAC:X/MPR:L/MUI:N/MS:C/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "5af9988d 6.0", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:L/E:U/RL:W/RC:U/CR:M/IR:M/AR:H/MAV:N/MAC:H/MPR:X/MUI:X/MS:U/MC:X/MI:L/MA:H", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "d34ae878 2.3", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L/E:P/RL:T/RC:U/CR:L/IR:X/AR:L/MAV:L/MAC:X/MPR:H/MUI:R/MS:U/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(2.3)), // exp environmental score
        }, // exp
      ), (
        "b35b8b15 2.0", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:M/AR:H/MAV:X/MAC:H/MPR:H/MUI:R/MS:X/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "ac9635ba 6.1", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:N/E:H/RL:W/RC:U/CR:M/IR:L/AR:L/MAV:N/MAC:H/MPR:H/MUI:N/MS:X/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "137beb24 3.1", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:N/E:U/RL:U/RC:X/CR:L/IR:L/AR:X/MAV:A/MAC:X/MPR:N/MUI:R/MS:X/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "14b9a7d5 3.8", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:X/RL:X/RC:X/CR:L/IR:H/AR:X/MAV:L/MAC:L/MPR:L/MUI:N/MS:C/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "d434713e 5.4", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:N/A:H/E:P/RL:U/RC:R/CR:X/IR:M/AR:X/MAV:X/MAC:X/MPR:L/MUI:N/MS:U/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "b2ef8c28 5.7", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N/E:H/RL:W/RC:R/CR:H/IR:X/AR:X/MAV:L/MAC:X/MPR:X/MUI:X/MS:C/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "8ba507b7 4.0", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L/E:P/RL:W/RC:C/CR:L/IR:L/AR:H/MAV:X/MAC:L/MPR:H/MUI:R/MS:U/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "77a41bd7 2.4", // test name
        "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:N/E:H/RL:X/RC:C/CR:L/IR:X/AR:L/MAV:N/MAC:X/MPR:N/MUI:X/MS:U/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "c529f4bd 4.4", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L/E:U/RL:U/RC:C/CR:M/IR:L/AR:X/MAV:N/MAC:X/MPR:H/MUI:N/MS:X/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(8.9), // exp base score
          temporal: Some(Score::from(8.1)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "aca01271 6.4", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N/E:X/RL:T/RC:X/CR:M/IR:H/AR:X/MAV:A/MAC:L/MPR:H/MUI:R/MS:U/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "aab91bdd 8.1", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N/E:H/RL:O/RC:C/CR:L/IR:M/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "5f89e6c8 8.1", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:H/E:U/RL:X/RC:C/CR:L/IR:M/AR:X/MAV:X/MAC:L/MPR:L/MUI:N/MS:X/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(8.9), // exp base score
          temporal: Some(Score::from(8.1)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "3d7752a9 0.0", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:H/E:U/RL:W/RC:R/CR:M/IR:M/AR:M/MAV:L/MAC:X/MPR:N/MUI:R/MS:U/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "3ebe6cf0 5.6", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:L/E:P/RL:T/RC:C/CR:H/IR:L/AR:H/MAV:X/MAC:H/MPR:H/MUI:N/MS:C/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "0dc4407e 6.3", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:L/E:F/RL:W/RC:U/CR:H/IR:M/AR:L/MAV:X/MAC:H/MPR:H/MUI:N/MS:C/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "230718da 3.8", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N/E:H/RL:W/RC:X/CR:L/IR:X/AR:L/MAV:P/MAC:H/MPR:X/MUI:N/MS:C/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "0a699dfc 6.7", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:L/E:U/RL:U/RC:X/CR:H/IR:H/AR:L/MAV:L/MAC:H/MPR:X/MUI:N/MS:U/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "6d3faca4 4.1", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L/E:H/RL:T/RC:U/CR:M/IR:H/AR:L/MAV:L/MAC:X/MPR:N/MUI:X/MS:X/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "830a9ed3 6.5", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:X/MS:X/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "17cebb9c 6.1", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H/E:F/RL:U/RC:C/CR:M/IR:X/AR:H/MAV:N/MAC:X/MPR:H/MUI:R/MS:X/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "55fbfe8e 6.2", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/E:F/RL:W/RC:C/CR:H/IR:X/AR:M/MAV:N/MAC:X/MPR:N/MUI:X/MS:U/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "bf7eeeda 2.4", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/E:H/RL:U/RC:X/CR:L/IR:X/AR:L/MAV:N/MAC:X/MPR:H/MUI:R/MS:U/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "97f3f6f9 6.9", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N/E:U/RL:O/RC:R/CR:H/IR:X/AR:X/MAV:X/MAC:H/MPR:X/MUI:R/MS:X/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "322f9aa3 7.4", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:H/E:U/RL:O/RC:R/CR:H/IR:L/AR:M/MAV:N/MAC:H/MPR:X/MUI:N/MS:X/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "47ed0cc6 4.0", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:H/E:X/RL:X/RC:X/CR:H/IR:X/AR:X/MAV:L/MAC:X/MPR:N/MUI:N/MS:U/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "f497801f 3.6", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:N/E:U/RL:O/RC:X/CR:H/IR:X/AR:H/MAV:P/MAC:L/MPR:H/MUI:X/MS:C/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "28fe178e 3.0", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:N/A:L/E:X/RL:O/RC:X/CR:M/IR:L/AR:M/MAV:N/MAC:X/MPR:X/MUI:X/MS:U/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "029cdfaa 3.8", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N/E:X/RL:X/RC:U/CR:L/IR:L/AR:M/MAV:N/MAC:X/MPR:L/MUI:R/MS:C/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "d0132b5d 3.5", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H/E:U/RL:T/RC:R/CR:X/IR:X/AR:L/MAV:N/MAC:L/MPR:L/MUI:X/MS:X/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "abab307d 2.7", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:H/E:U/RL:X/RC:U/CR:M/IR:L/AR:H/MAV:L/MAC:H/MPR:H/MUI:X/MS:X/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "4bfdec90 4.6", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H/E:X/RL:X/RC:C/CR:L/IR:L/AR:H/MAV:N/MAC:L/MPR:N/MUI:X/MS:C/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "c6b822d3 8.3", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:H/E:H/RL:X/RC:C/CR:H/IR:X/AR:H/MAV:X/MAC:L/MPR:N/MUI:R/MS:U/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(8.3)), // exp environmental score
        }, // exp
      ), (
        "7364a802 5.0", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L/E:H/RL:W/RC:R/CR:L/IR:M/AR:L/MAV:X/MAC:L/MPR:X/MUI:N/MS:U/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(3.1), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "c75e6f83 1.8", // test name
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N/E:F/RL:X/RC:C/CR:H/IR:M/AR:X/MAV:P/MAC:H/MPR:N/MUI:R/MS:X/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "b238f93b 5.6", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:L/E:U/RL:T/RC:U/CR:X/IR:X/AR:X/MAV:N/MAC:X/MPR:X/MUI:R/MS:C/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "5e4e25d3 5.6", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N/E:X/RL:T/RC:C/CR:L/IR:M/AR:M/MAV:P/MAC:H/MPR:H/MUI:X/MS:X/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "5c0f91bd 8.9", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:N/E:H/RL:T/RC:U/CR:H/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(8.9)), // exp environmental score
        }, // exp
      ), (
        "632ef6f5 4.2", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:H/E:U/RL:O/RC:U/CR:L/IR:L/AR:M/MAV:P/MAC:H/MPR:L/MUI:N/MS:X/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "cae07392 7.2", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:H/E:X/RL:X/RC:X/CR:M/IR:X/AR:M/MAV:X/MAC:X/MPR:N/MUI:N/MS:X/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "fea03d93 5.2", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H/E:P/RL:X/RC:U/CR:M/IR:M/AR:M/MAV:P/MAC:L/MPR:N/MUI:R/MS:X/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "51af85c8 5.1", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N/E:X/RL:O/RC:U/CR:X/IR:M/AR:L/MAV:N/MAC:L/MPR:X/MUI:R/MS:U/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "c05b3ba6 6.5", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H/E:X/RL:O/RC:U/CR:M/IR:X/AR:X/MAV:N/MAC:L/MPR:L/MUI:N/MS:C/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "337bf910 5.7", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:N/E:U/RL:W/RC:U/CR:M/IR:M/AR:H/MAV:P/MAC:X/MPR:X/MUI:X/MS:C/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "84b4c596 7.3", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:N/E:U/RL:X/RC:U/CR:X/IR:M/AR:X/MAV:A/MAC:X/MPR:N/MUI:X/MS:X/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "8c5d45c7 2.8", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:N/I:L/A:L/E:P/RL:T/RC:X/CR:L/IR:X/AR:M/MAV:X/MAC:H/MPR:H/MUI:R/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "4a52d185 1.9", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:N/I:L/A:N/E:H/RL:T/RC:R/CR:X/IR:M/AR:X/MAV:L/MAC:X/MPR:H/MUI:R/MS:U/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "89af3748 2.2", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:N/E:F/RL:O/RC:X/CR:L/IR:L/AR:H/MAV:L/MAC:X/MPR:H/MUI:N/MS:C/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "5717a59c 5.8", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N/E:X/RL:O/RC:X/CR:M/IR:M/AR:M/MAV:L/MAC:L/MPR:L/MUI:N/MS:U/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "5bd8a82b 8.9", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:H/A:L/E:X/RL:X/RC:U/CR:L/IR:H/AR:X/MAV:X/MAC:L/MPR:N/MUI:N/MS:X/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(8.9)), // exp environmental score
        }, // exp
      ), (
        "0a0ad309 4.0", // test name
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:H/E:X/RL:W/RC:C/CR:H/IR:H/AR:L/MAV:L/MAC:H/MPR:L/MUI:X/MS:X/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "fc142e34 5.3", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L/E:P/RL:O/RC:R/CR:L/IR:L/AR:X/MAV:X/MAC:L/MPR:L/MUI:X/MS:X/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "6e5723f9 9.0", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:L/E:F/RL:U/RC:U/CR:L/IR:H/AR:H/MAV:X/MAC:L/MPR:N/MUI:X/MS:X/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.6)), // exp temporal score
          environmental: Some(Score::from(9.0)), // exp environmental score
        }, // exp
      ), (
        "9126438f 7.8", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:L/E:P/RL:O/RC:R/CR:M/IR:M/AR:L/MAV:N/MAC:X/MPR:N/MUI:X/MS:C/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "a08940e1 5.4", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N/E:X/RL:X/RC:R/CR:L/IR:L/AR:L/MAV:A/MAC:L/MPR:X/MUI:N/MS:U/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "8052f8de 4.6", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H/E:F/RL:X/RC:X/CR:M/IR:M/AR:L/MAV:X/MAC:X/MPR:X/MUI:R/MS:X/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(8.3)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "6532ae5b 0.0", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L/E:P/RL:O/RC:C/CR:M/IR:H/AR:X/MAV:P/MAC:L/MPR:L/MUI:X/MS:U/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "7d8ba4db 7.8", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N/E:U/RL:T/RC:X/CR:M/IR:M/AR:M/MAV:N/MAC:X/MPR:L/MUI:R/MS:C/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "78749d55 7.6", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L/E:P/RL:W/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:L/MUI:N/MS:U/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "cf9ebb17 7.0", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H/E:F/RL:X/RC:X/CR:H/IR:X/AR:L/MAV:X/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(8.1)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "be139600 4.1", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L/E:F/RL:X/RC:R/CR:M/IR:H/AR:X/MAV:P/MAC:L/MPR:H/MUI:X/MS:C/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "1f0266c7 6.1", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H/E:F/RL:X/RC:C/CR:M/IR:X/AR:M/MAV:N/MAC:H/MPR:H/MUI:N/MS:X/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "a187e274 2.4", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H/E:U/RL:X/RC:U/CR:H/IR:L/AR:H/MAV:N/MAC:X/MPR:X/MUI:R/MS:U/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "3430dc50 8.4", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N/E:P/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:A/MAC:L/MPR:L/MUI:N/MS:C/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "a1022d53 6.8", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:L/E:X/RL:X/RC:X/CR:L/IR:X/AR:M/MAV:A/MAC:H/MPR:X/MUI:N/MS:C/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "bbc3626c 2.6", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:H/E:X/RL:T/RC:X/CR:L/IR:L/AR:H/MAV:L/MAC:L/MPR:H/MUI:X/MS:X/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(8.9), // exp base score
          temporal: Some(Score::from(8.6)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "8c81618d 8.8", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L/E:X/RL:X/RC:U/CR:H/IR:L/AR:H/MAV:X/MAC:L/MPR:N/MUI:N/MS:X/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(7.6)), // exp temporal score
          environmental: Some(Score::from(8.8)), // exp environmental score
        }, // exp
      ), (
        "2b115081 5.7", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H/E:U/RL:T/RC:X/CR:X/IR:X/AR:M/MAV:A/MAC:X/MPR:N/MUI:N/MS:U/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "b9eb658d 6.7", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H/E:U/RL:X/RC:C/CR:M/IR:L/AR:L/MAV:A/MAC:X/MPR:N/MUI:N/MS:X/MC:X/MI:N/MA:X", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "221364a9 5.8", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:F/RL:T/RC:X/CR:M/IR:H/AR:L/MAV:L/MAC:H/MPR:H/MUI:N/MS:U/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "b1d2df92 6.1", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N/E:U/RL:W/RC:R/CR:M/IR:M/AR:M/MAV:X/MAC:H/MPR:L/MUI:N/MS:C/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "5b0ff996 6.0", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:H/E:P/RL:T/RC:X/CR:L/IR:H/AR:H/MAV:N/MAC:H/MPR:X/MUI:N/MS:C/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "d32a180a 7.2", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:L/E:F/RL:T/RC:U/CR:M/IR:M/AR:M/MAV:A/MAC:L/MPR:X/MUI:X/MS:C/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "889c7c06 7.4", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N/E:P/RL:X/RC:R/CR:H/IR:X/AR:X/MAV:X/MAC:L/MPR:N/MUI:N/MS:U/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "0ee25a5f 7.9", // test name
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:H/E:P/RL:O/RC:U/CR:H/IR:X/AR:H/MAV:X/MAC:X/MPR:N/MUI:X/MS:C/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "4a0406e1 8.6", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:P/RL:T/RC:R/CR:X/IR:M/AR:M/MAV:N/MAC:X/MPR:X/MUI:N/MS:X/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(10.0), // exp base score
          temporal: Some(Score::from(8.7)), // exp temporal score
          environmental: Some(Score::from(8.6)), // exp environmental score
        }, // exp
      ), (
        "759f2b0b 7.1", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:H/E:X/RL:O/RC:U/CR:M/IR:L/AR:X/MAV:A/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(10.0), // exp base score
          temporal: Some(Score::from(8.8)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "08a2fefd 8.8", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:X/RL:X/RC:X/CR:X/IR:L/AR:H/MAV:A/MAC:L/MPR:X/MUI:N/MS:U/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(8.6), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(8.8)), // exp environmental score
        }, // exp
      ), (
        "50631c9c 0.0", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N/E:H/RL:W/RC:C/CR:L/IR:L/AR:M/MAV:P/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "f0d85020 7.2", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:W/RC:X/CR:M/IR:H/AR:H/MAV:X/MAC:H/MPR:N/MUI:X/MS:U/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(9.8), // exp base score
          temporal: Some(Score::from(8.7)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "42988b28 5.6", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N/E:U/RL:T/RC:X/CR:X/IR:X/AR:M/MAV:X/MAC:X/MPR:L/MUI:R/MS:X/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "7b4dcdf1 4.3", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N/E:P/RL:W/RC:R/CR:M/IR:L/AR:H/MAV:A/MAC:L/MPR:N/MUI:X/MS:X/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "67e1b872 2.9", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:U/RL:U/RC:C/CR:H/IR:L/AR:H/MAV:L/MAC:H/MPR:H/MUI:X/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "2457398e 8.9", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L/E:P/RL:O/RC:X/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:L/MUI:N/MS:X/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(9.6), // exp base score
          temporal: Some(Score::from(8.6)), // exp temporal score
          environmental: Some(Score::from(8.9)), // exp environmental score
        }, // exp
      ), (
        "9b64b153 3.7", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L/E:P/RL:U/RC:R/CR:M/IR:H/AR:M/MAV:P/MAC:X/MPR:H/MUI:R/MS:C/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(9.6), // exp base score
          temporal: Some(Score::from(8.7)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "bd5dd3c5 3.6", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:H/E:F/RL:W/RC:U/CR:L/IR:M/AR:X/MAV:P/MAC:L/MPR:L/MUI:R/MS:X/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(9.6), // exp base score
          temporal: Some(Score::from(8.4)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "f3c0f784 5.4", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:H/E:P/RL:T/RC:U/CR:L/IR:X/AR:L/MAV:A/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(9.6), // exp base score
          temporal: Some(Score::from(8.0)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "032f2eb9 3.6", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L/E:X/RL:U/RC:X/CR:L/IR:L/AR:H/MAV:N/MAC:H/MPR:H/MUI:R/MS:U/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "ec4d1563 8.4", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:H/E:U/RL:T/RC:X/CR:H/IR:X/AR:M/MAV:N/MAC:X/MPR:N/MUI:X/MS:C/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(9.3), // exp base score
          temporal: Some(Score::from(8.2)), // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "1a6ceffe 6.2", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H/E:F/RL:T/RC:C/CR:X/IR:X/AR:L/MAV:A/MAC:L/MPR:N/MUI:X/MS:X/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "f29596cf 5.4", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:H/RL:T/RC:X/CR:L/IR:M/AR:H/MAV:A/MAC:H/MPR:H/MUI:X/MS:C/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "91ed2f5d 7.6", // test name
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L/E:U/RL:W/RC:X/CR:H/IR:H/AR:M/MAV:X/MAC:X/MPR:N/MUI:N/MS:X/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "f0f3ffa3 2.4", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:X/CR:H/IR:H/AR:H/MAV:X/MAC:X/MPR:L/MUI:R/MS:U/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "2a0c5c23 1.6", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:L/E:H/RL:O/RC:U/CR:X/IR:M/AR:H/MAV:X/MAC:X/MPR:X/MUI:R/MS:C/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "465d9bf4 5.4", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H/E:P/RL:W/RC:U/CR:M/IR:X/AR:M/MAV:A/MAC:H/MPR:H/MUI:N/MS:X/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "7bd58028 4.3", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:N/E:F/RL:T/RC:U/CR:M/IR:L/AR:H/MAV:N/MAC:L/MPR:L/MUI:X/MS:X/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "ee36ef09 6.0", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:L/E:U/RL:U/RC:R/CR:M/IR:M/AR:X/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "e265cb9a 2.9", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N/E:P/RL:W/RC:C/CR:X/IR:X/AR:X/MAV:A/MAC:X/MPR:H/MUI:N/MS:X/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "0925a9e3 6.2", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:H/E:X/RL:U/RC:X/CR:L/IR:H/AR:M/MAV:L/MAC:H/MPR:X/MUI:X/MS:U/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "6631ea22 5.8", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H/E:F/RL:U/RC:U/CR:X/IR:H/AR:X/MAV:P/MAC:L/MPR:L/MUI:R/MS:U/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "4758defe 2.9", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N/E:U/RL:U/RC:R/CR:L/IR:L/AR:X/MAV:L/MAC:H/MPR:X/MUI:N/MS:X/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(1.6), // exp base score
          temporal: Some(Score::from(1.4)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "1ac4c6d7 5.4", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H/E:X/RL:X/RC:C/CR:X/IR:X/AR:M/MAV:A/MAC:L/MPR:N/MUI:X/MS:U/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "03567f29 2.3", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L/E:H/RL:O/RC:U/CR:H/IR:L/AR:M/MAV:A/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(1.6), // exp base score
          temporal: Some(Score::from(1.4)), // exp temporal score
          environmental: Some(Score::from(2.3)), // exp environmental score
        }, // exp
      ), (
        "2ad98b5f 2.6", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:L/E:H/RL:O/RC:U/CR:L/IR:H/AR:H/MAV:P/MAC:L/MPR:X/MUI:X/MS:C/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "e18812d6 7.3", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:H/E:P/RL:X/RC:U/CR:L/IR:H/AR:H/MAV:A/MAC:L/MPR:H/MUI:N/MS:X/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "2ae8882b 2.8", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:H/A:N/E:U/RL:O/RC:X/CR:L/IR:L/AR:L/MAV:X/MAC:X/MPR:N/MUI:R/MS:U/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "3d5d9cc3 7.4", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:L/E:X/RL:U/RC:U/CR:M/IR:M/AR:H/MAV:L/MAC:X/MPR:N/MUI:N/MS:C/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "a55d6552 6.0", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:L/E:X/RL:T/RC:R/CR:L/IR:M/AR:H/MAV:L/MAC:H/MPR:N/MUI:X/MS:C/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "d80ffb5a 6.7", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:L/E:X/RL:W/RC:X/CR:X/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:N/MS:C/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "828369ad 6.0", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:L/A:H/E:F/RL:W/RC:C/CR:H/IR:L/AR:H/MAV:P/MAC:X/MPR:N/MUI:X/MS:X/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "3576581b 3.8", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:L/A:L/E:P/RL:W/RC:R/CR:L/IR:X/AR:M/MAV:L/MAC:L/MPR:N/MUI:X/MS:C/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "49a646b0 5.1", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:L/A:L/E:U/RL:X/RC:U/CR:H/IR:X/AR:M/MAV:X/MAC:X/MPR:H/MUI:R/MS:X/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "ae13d380 7.4", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:H/A:H/E:H/RL:O/RC:C/CR:L/IR:X/AR:M/MAV:L/MAC:L/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "a74c1d2c 5.8", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N/E:F/RL:W/RC:C/CR:M/IR:M/AR:X/MAV:P/MAC:X/MPR:L/MUI:X/MS:C/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "66613c13 6.7", // test name
        "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:H/E:U/RL:X/RC:R/CR:H/IR:H/AR:L/MAV:A/MAC:H/MPR:L/MUI:X/MS:C/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "5452823f 2.6", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:L/IR:M/AR:L/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:X/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "5b1e0737 4.3", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:H/E:F/RL:X/RC:X/CR:H/IR:M/AR:X/MAV:A/MAC:H/MPR:H/MUI:R/MS:X/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "455c6be0 8.2", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:H/E:U/RL:X/RC:C/CR:L/IR:H/AR:M/MAV:N/MAC:L/MPR:L/MUI:R/MS:X/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(8.2)), // exp environmental score
        }, // exp
      ), (
        "c24605e2 1.2", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L/E:F/RL:X/RC:X/CR:H/IR:L/AR:M/MAV:P/MAC:H/MPR:X/MUI:N/MS:X/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "d595e4f0 7.4", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:N/I:H/A:L/E:H/RL:U/RC:U/CR:X/IR:L/AR:H/MAV:N/MAC:X/MPR:H/MUI:N/MS:C/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "432b2425 5.2", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:N/I:H/A:N/E:F/RL:W/RC:X/CR:H/IR:H/AR:X/MAV:L/MAC:X/MPR:X/MUI:N/MS:C/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "18d74b98 3.3", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:N/E:X/RL:O/RC:R/CR:M/IR:X/AR:M/MAV:X/MAC:H/MPR:H/MUI:X/MS:U/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "8bcb78fb 1.4", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N/E:F/RL:O/RC:X/CR:L/IR:M/AR:M/MAV:N/MAC:H/MPR:H/MUI:X/MS:U/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "6266c5d1 3.7", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:H/E:H/RL:O/RC:U/CR:M/IR:M/AR:H/MAV:L/MAC:H/MPR:L/MUI:N/MS:X/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "c94daa63 2.8", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:L/E:U/RL:W/RC:X/CR:L/IR:L/AR:L/MAV:P/MAC:X/MPR:N/MUI:X/MS:X/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "5d7b08b9 0.0", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N/E:H/RL:O/RC:X/CR:X/IR:H/AR:M/MAV:P/MAC:H/MPR:H/MUI:R/MS:U/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9fd72c48 6.4", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:N/A:H/E:P/RL:W/RC:C/CR:H/IR:H/AR:H/MAV:X/MAC:H/MPR:L/MUI:N/MS:X/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "1e1534c7 3.9", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H/E:X/RL:W/RC:R/CR:M/IR:L/AR:L/MAV:X/MAC:H/MPR:H/MUI:R/MS:U/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "bef724e7 5.0", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:L/E:P/RL:W/RC:U/CR:L/IR:L/AR:L/MAV:A/MAC:H/MPR:N/MUI:N/MS:X/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "df63f6d6 2.7", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:N/I:N/A:H/E:P/RL:X/RC:C/CR:H/IR:M/AR:M/MAV:L/MAC:H/MPR:X/MUI:N/MS:X/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "8bab924c 7.3", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N/E:F/RL:U/RC:C/CR:L/IR:H/AR:L/MAV:L/MAC:X/MPR:H/MUI:N/MS:C/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "75b0ea7f 5.7", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:L/E:F/RL:X/RC:U/CR:H/IR:X/AR:H/MAV:X/MAC:H/MPR:X/MUI:N/MS:X/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "a349dd46 4.6", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:L/E:H/RL:W/RC:R/CR:M/IR:X/AR:L/MAV:P/MAC:H/MPR:N/MUI:R/MS:U/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "730614c0 5.4", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:L/E:P/RL:T/RC:R/CR:X/IR:M/AR:L/MAV:P/MAC:L/MPR:X/MUI:N/MS:C/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "07d41fdd 4.5", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:H/E:F/RL:U/RC:X/CR:L/IR:X/AR:L/MAV:X/MAC:L/MPR:N/MUI:R/MS:X/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "be62a658 3.2", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:H/E:U/RL:O/RC:C/CR:L/IR:X/AR:M/MAV:A/MAC:H/MPR:X/MUI:N/MS:X/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "660877d7 3.1", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:L/E:P/RL:T/RC:U/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:X/MUI:R/MS:C/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "53062128 3.3", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:L/E:U/RL:O/RC:R/CR:L/IR:M/AR:X/MAV:L/MAC:X/MPR:N/MUI:R/MS:U/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "40a899e6 5.8", // test name
        "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N/E:X/RL:X/RC:R/CR:L/IR:M/AR:H/MAV:N/MAC:L/MPR:X/MUI:R/MS:X/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "6aae5ed4 6.8", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N/E:H/RL:W/RC:R/CR:L/IR:M/AR:L/MAV:A/MAC:L/MPR:H/MUI:N/MS:C/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "3cb4b4df 4.0", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:H/E:U/RL:X/RC:R/CR:X/IR:L/AR:L/MAV:L/MAC:L/MPR:L/MUI:R/MS:U/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "12127d88 3.9", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H/E:H/RL:T/RC:X/CR:L/IR:H/AR:X/MAV:P/MAC:X/MPR:X/MUI:N/MS:U/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "d5726b64 3.4", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:H/RL:T/RC:X/CR:M/IR:H/AR:H/MAV:P/MAC:X/MPR:X/MUI:R/MS:X/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "8a6b24c7 3.1", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N/E:U/RL:T/RC:C/CR:X/IR:X/AR:X/MAV:A/MAC:L/MPR:H/MUI:N/MS:U/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "c381c5f1 4.2", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H/E:H/RL:O/RC:R/CR:H/IR:X/AR:L/MAV:N/MAC:H/MPR:L/MUI:X/MS:U/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "0104aa15 1.0", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L/E:F/RL:O/RC:C/CR:L/IR:M/AR:X/MAV:X/MAC:H/MPR:H/MUI:N/MS:C/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(2.0), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "8c8ece24 2.9", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/E:X/RL:W/RC:C/CR:M/IR:X/AR:L/MAV:X/MAC:X/MPR:L/MUI:N/MS:U/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "71e7d1fc 5.5", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N/E:F/RL:T/RC:C/CR:L/IR:X/AR:H/MAV:N/MAC:H/MPR:X/MUI:N/MS:U/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "0f56c43c 4.3", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:H/E:H/RL:T/RC:R/CR:M/IR:H/AR:M/MAV:P/MAC:X/MPR:N/MUI:X/MS:U/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "70546b7e 4.9", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N/E:U/RL:T/RC:R/CR:H/IR:X/AR:M/MAV:X/MAC:H/MPR:H/MUI:N/MS:U/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "e0b8a50f 4.3", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L/E:X/RL:T/RC:U/CR:M/IR:L/AR:M/MAV:X/MAC:H/MPR:X/MUI:R/MS:X/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "79b93f64 5.2", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:L/E:U/RL:T/RC:X/CR:H/IR:L/AR:X/MAV:P/MAC:L/MPR:L/MUI:R/MS:X/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "72d79128 1.9", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N/E:F/RL:W/RC:R/CR:H/IR:L/AR:M/MAV:A/MAC:X/MPR:N/MUI:X/MS:X/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "53c6aced 3.6", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:L/E:U/RL:O/RC:C/CR:H/IR:H/AR:X/MAV:P/MAC:L/MPR:L/MUI:X/MS:U/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "8effaaa9 4.4", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:N/I:N/A:L/E:P/RL:X/RC:C/CR:L/IR:H/AR:L/MAV:N/MAC:X/MPR:N/MUI:N/MS:U/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(2.0), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "b1e3b773 4.8", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N/E:U/RL:X/RC:R/CR:L/IR:M/AR:M/MAV:X/MAC:L/MPR:L/MUI:R/MS:U/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "d92f2632 4.9", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L/E:P/RL:U/RC:U/CR:X/IR:X/AR:H/MAV:A/MAC:X/MPR:N/MUI:X/MS:C/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "808018d8 5.3", // test name
        "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L/E:X/RL:W/RC:R/CR:M/IR:M/AR:H/MAV:L/MAC:L/MPR:X/MUI:N/MS:U/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "63444c2a 6.4", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N/E:F/RL:O/RC:X/CR:X/IR:H/AR:M/MAV:A/MAC:H/MPR:L/MUI:N/MS:X/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "3e9776cb 4.8", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:H/E:F/RL:W/RC:X/CR:X/IR:X/AR:M/MAV:L/MAC:H/MPR:L/MUI:R/MS:U/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "25585f0c 4.4", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N/E:X/RL:U/RC:U/CR:H/IR:H/AR:L/MAV:P/MAC:H/MPR:L/MUI:X/MS:C/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "6481477c 3.4", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H/E:X/RL:T/RC:C/CR:L/IR:M/AR:M/MAV:A/MAC:L/MPR:L/MUI:X/MS:X/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "d6054438 7.2", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:H/E:U/RL:W/RC:R/CR:M/IR:X/AR:L/MAV:N/MAC:L/MPR:N/MUI:R/MS:C/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "dc6f4d2e 3.0", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:L/E:P/RL:X/RC:R/CR:X/IR:L/AR:L/MAV:N/MAC:L/MPR:H/MUI:R/MS:U/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "512d5bfa 5.8", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:H/E:X/RL:U/RC:U/CR:L/IR:L/AR:X/MAV:L/MAC:L/MPR:H/MUI:X/MS:C/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "e61f6d59 2.5", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:C/C:L/I:N/A:N/E:P/RL:X/RC:R/CR:L/IR:X/AR:M/MAV:L/MAC:L/MPR:N/MUI:X/MS:X/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(2.0), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(2.5)), // exp environmental score
        }, // exp
      ), (
        "ab0e95c3 4.2", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:L/E:U/RL:U/RC:C/CR:X/IR:X/AR:X/MAV:A/MAC:X/MPR:N/MUI:R/MS:U/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "509956e9 6.7", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:C/C:N/I:L/A:L/E:F/RL:W/RC:C/CR:X/IR:H/AR:X/MAV:N/MAC:X/MPR:L/MUI:X/MS:X/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "6bace374 3.8", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H/E:U/RL:T/RC:C/CR:X/IR:H/AR:L/MAV:X/MAC:X/MPR:N/MUI:R/MS:U/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "3d81dc74 7.8", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:U/C:H/I:L/A:H/E:H/RL:O/RC:R/CR:M/IR:M/AR:L/MAV:N/MAC:X/MPR:N/MUI:R/MS:C/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "f9fb18a5 4.2", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:U/C:H/I:L/A:L/E:U/RL:T/RC:X/CR:X/IR:H/AR:X/MAV:L/MAC:L/MPR:X/MUI:R/MS:X/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "7df8d666 5.3", // test name
        "CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:U/C:N/I:H/A:H/E:F/RL:O/RC:C/CR:L/IR:L/AR:L/MAV:L/MAC:X/MPR:N/MUI:X/MS:C/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "8de7e2d4 2.4", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N/E:H/RL:U/RC:X/CR:L/IR:X/AR:H/MAV:A/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "8fa4e8fe 7.5", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N/E:U/RL:X/RC:C/CR:H/IR:X/AR:L/MAV:N/MAC:H/MPR:N/MUI:R/MS:X/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "8d475068 3.2", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H/E:P/RL:X/RC:R/CR:L/IR:L/AR:L/MAV:X/MAC:L/MPR:L/MUI:N/MS:C/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "ca073143 4.8", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:H/E:P/RL:U/RC:U/CR:M/IR:X/AR:M/MAV:L/MAC:L/MPR:L/MUI:N/MS:U/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "d125330d 4.5", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L/E:H/RL:W/RC:R/CR:X/IR:X/AR:X/MAV:P/MAC:L/MPR:L/MUI:R/MS:U/MC:X/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "8d96e718 5.7", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N/E:P/RL:W/RC:R/CR:X/IR:M/AR:L/MAV:A/MAC:L/MPR:X/MUI:X/MS:U/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "8740e095 6.2", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L/E:U/RL:X/RC:X/CR:X/IR:X/AR:M/MAV:N/MAC:X/MPR:X/MUI:R/MS:X/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "02bf8835 5.8", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N/E:H/RL:O/RC:C/CR:M/IR:M/AR:L/MAV:P/MAC:X/MPR:X/MUI:R/MS:U/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "67d08275 5.2", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L/E:P/RL:W/RC:X/CR:X/IR:L/AR:H/MAV:A/MAC:L/MPR:H/MUI:N/MS:X/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "4b65b4da 8.0", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L/E:U/RL:W/RC:X/CR:H/IR:H/AR:X/MAV:N/MAC:H/MPR:N/MUI:N/MS:C/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(8.0)), // exp environmental score
        }, // exp
      ), (
        "3b961005 6.5", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H/E:U/RL:O/RC:R/CR:X/IR:H/AR:M/MAV:N/MAC:L/MPR:X/MUI:N/MS:U/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "fea502cd 1.8", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L/E:H/RL:T/RC:R/CR:L/IR:L/AR:M/MAV:X/MAC:H/MPR:X/MUI:R/MS:C/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "e3167400 5.9", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N/E:P/RL:O/RC:X/CR:H/IR:L/AR:X/MAV:A/MAC:L/MPR:X/MUI:N/MS:X/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "defb8df4 3.9", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L/E:U/RL:U/RC:C/CR:L/IR:L/AR:X/MAV:X/MAC:H/MPR:L/MUI:R/MS:X/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "8ca5363f 7.2", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H/E:P/RL:O/RC:X/CR:M/IR:H/AR:X/MAV:A/MAC:X/MPR:L/MUI:N/MS:U/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "4e433d46 7.8", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H/E:X/RL:W/RC:U/CR:L/IR:M/AR:M/MAV:N/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "73bd8e8e 6.2", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:N/E:U/RL:U/RC:C/CR:M/IR:H/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "21db7258 5.6", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N/E:P/RL:W/RC:X/CR:M/IR:X/AR:X/MAV:P/MAC:X/MPR:H/MUI:R/MS:U/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(2.2), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "df91466a 6.0", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:L/E:H/RL:X/RC:C/CR:H/IR:L/AR:M/MAV:A/MAC:L/MPR:H/MUI:N/MS:U/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "30505ebe 0.0", // test name
        "CVSS:3.0/AV:P/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:L/E:P/RL:T/RC:R/CR:M/IR:H/AR:X/MAV:A/MAC:H/MPR:X/MUI:N/MS:U/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "88424c8b 6.1", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:H/E:P/RL:U/RC:U/CR:X/IR:L/AR:X/MAV:L/MAC:L/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "49d56e2d 8.6", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L/E:U/RL:W/RC:X/CR:H/IR:H/AR:L/MAV:A/MAC:L/MPR:N/MUI:X/MS:X/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(8.6)), // exp environmental score
        }, // exp
      ), (
        "f57cdefe 6.6", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N/E:F/RL:T/RC:X/CR:H/IR:H/AR:M/MAV:L/MAC:H/MPR:L/MUI:N/MS:U/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "04028e09 6.7", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:H/E:P/RL:T/RC:C/CR:H/IR:L/AR:M/MAV:N/MAC:L/MPR:N/MUI:R/MS:C/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "deedc8d4 3.3", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N/E:H/RL:W/RC:X/CR:L/IR:M/AR:H/MAV:L/MAC:X/MPR:N/MUI:N/MS:X/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "cde706b1 5.6", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N/E:U/RL:T/RC:U/CR:H/IR:H/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:X/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "07021fdf 2.4", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H/E:F/RL:O/RC:R/CR:X/IR:M/AR:X/MAV:P/MAC:X/MPR:N/MUI:N/MS:X/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "bbc95c43 1.6", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N/E:P/RL:W/RC:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MPR:N/MUI:R/MS:U/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "64da683e 4.0", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L/E:P/RL:W/RC:R/CR:M/IR:X/AR:X/MAV:X/MAC:L/MPR:H/MUI:R/MS:U/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "bad13334 3.7", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H/E:P/RL:W/RC:U/CR:H/IR:X/AR:L/MAV:X/MAC:L/MPR:X/MUI:X/MS:C/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "35c76d31 4.4", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L/E:P/RL:O/RC:U/CR:X/IR:M/AR:X/MAV:N/MAC:L/MPR:X/MUI:X/MS:X/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "afc6c730 2.5", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L/E:X/RL:U/RC:U/CR:X/IR:L/AR:L/MAV:N/MAC:H/MPR:H/MUI:N/MS:U/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(2.5)), // exp environmental score
        }, // exp
      ), (
        "84df539f 3.5", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:U/RL:U/RC:R/CR:X/IR:M/AR:X/MAV:A/MAC:H/MPR:H/MUI:R/MS:U/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "261ba1a0 6.4", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N/E:F/RL:T/RC:U/CR:H/IR:L/AR:X/MAV:X/MAC:X/MPR:L/MUI:N/MS:C/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "2a83eeb8 7.5", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L/E:P/RL:U/RC:X/CR:X/IR:X/AR:H/MAV:L/MAC:X/MPR:L/MUI:X/MS:C/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "33c0aec5 3.5", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L/E:U/RL:T/RC:U/CR:M/IR:X/AR:L/MAV:L/MAC:X/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "e3d5c4fb 6.5", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:H/E:H/RL:X/RC:U/CR:M/IR:X/AR:H/MAV:X/MAC:L/MPR:N/MUI:N/MS:X/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "1d48a4b8 4.2", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L/E:X/RL:X/RC:U/CR:X/IR:L/AR:H/MAV:P/MAC:H/MPR:L/MUI:R/MS:X/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "8fdc3797 5.0", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N/E:P/RL:X/RC:R/CR:L/IR:L/AR:L/MAV:A/MAC:H/MPR:X/MUI:X/MS:X/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "248e3454 8.7", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N/E:X/RL:U/RC:R/CR:X/IR:H/AR:H/MAV:N/MAC:H/MPR:N/MUI:N/MS:X/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(8.7)), // exp environmental score
        }, // exp
      ), (
        "6abf68b0 5.7", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:H/E:X/RL:T/RC:X/CR:X/IR:H/AR:X/MAV:X/MAC:H/MPR:L/MUI:R/MS:U/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "5af7d4e4 6.1", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L/E:X/RL:U/RC:X/CR:M/IR:X/AR:L/MAV:P/MAC:L/MPR:X/MUI:X/MS:C/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "8c3894a2 5.6", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:H/E:X/RL:U/RC:C/CR:H/IR:X/AR:X/MAV:P/MAC:L/MPR:H/MUI:X/MS:X/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "598a2e6c 7.2", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:L/E:P/RL:U/RC:X/CR:X/IR:H/AR:X/MAV:N/MAC:X/MPR:L/MUI:X/MS:C/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "21e9e8ab 4.9", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:H/E:F/RL:T/RC:C/CR:X/IR:M/AR:X/MAV:X/MAC:X/MPR:X/MUI:N/MS:U/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "f12b3202 6.0", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L/E:U/RL:O/RC:X/CR:M/IR:L/AR:M/MAV:N/MAC:X/MPR:H/MUI:R/MS:C/MC:X/MI:N/MA:X", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "6415caec 2.9", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L/E:P/RL:W/RC:C/CR:M/IR:X/AR:X/MAV:L/MAC:X/MPR:H/MUI:X/MS:X/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "43b86fd8 4.1", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H/E:F/RL:U/RC:R/CR:H/IR:X/AR:L/MAV:P/MAC:X/MPR:X/MUI:N/MS:U/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "7271f048 4.4", // test name
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N/E:U/RL:U/RC:X/CR:L/IR:L/AR:X/MAV:X/MAC:H/MPR:X/MUI:R/MS:U/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "9430a20c 5.5", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:N/E:P/RL:O/RC:X/CR:H/IR:H/AR:X/MAV:A/MAC:L/MPR:H/MUI:N/MS:X/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "54511e49 3.4", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:N/E:U/RL:U/RC:X/CR:M/IR:M/AR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "6a99e1c9 6.5", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:C/C:L/I:N/A:N/E:X/RL:X/RC:C/CR:M/IR:L/AR:H/MAV:A/MAC:L/MPR:L/MUI:N/MS:C/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "41de1208 7.3", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:H/E:X/RL:T/RC:R/CR:X/IR:M/AR:H/MAV:L/MAC:X/MPR:L/MUI:N/MS:C/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "21916427 7.5", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:H/E:H/RL:O/RC:X/CR:H/IR:X/AR:X/MAV:X/MAC:H/MPR:N/MUI:X/MS:X/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "63b520f4 4.1", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:H/E:P/RL:U/RC:R/CR:L/IR:L/AR:H/MAV:A/MAC:H/MPR:L/MUI:X/MS:C/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "b3e37fb7 2.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H/E:P/RL:U/RC:R/CR:H/IR:L/AR:L/MAV:L/MAC:L/MPR:H/MUI:X/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "3fa24c00 5.8", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:N/E:H/RL:X/RC:X/CR:X/IR:M/AR:M/MAV:P/MAC:L/MPR:X/MUI:N/MS:U/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "ba78c924 5.6", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:N/E:U/RL:W/RC:U/CR:M/IR:H/AR:H/MAV:A/MAC:L/MPR:X/MUI:X/MS:U/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "3c6af940 8.2", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N/E:F/RL:X/RC:X/CR:H/IR:X/AR:X/MAV:A/MAC:X/MPR:N/MUI:X/MS:C/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(4.2), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(8.2)), // exp environmental score
        }, // exp
      ), (
        "cde1bf9a 4.5", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:H/E:F/RL:T/RC:R/CR:M/IR:M/AR:H/MAV:A/MAC:X/MPR:N/MUI:R/MS:C/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "202c5a9b 6.2", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:N/E:F/RL:W/RC:U/CR:H/IR:X/AR:L/MAV:A/MAC:H/MPR:N/MUI:X/MS:X/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(4.2), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "c0843363 3.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L/E:P/RL:O/RC:R/CR:L/IR:L/AR:M/MAV:P/MAC:X/MPR:N/MUI:N/MS:X/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(2.0), // exp base score
          temporal: Some(Score::from(1.8)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "7efbf73c 0.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:N/E:H/RL:T/RC:R/CR:H/IR:L/AR:M/MAV:X/MAC:X/MPR:N/MUI:R/MS:X/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "0e5a856f 6.8", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:H/E:U/RL:W/RC:C/CR:H/IR:X/AR:M/MAV:L/MAC:H/MPR:X/MUI:N/MS:C/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "254f779d 3.7", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N/E:H/RL:O/RC:R/CR:M/IR:X/AR:M/MAV:A/MAC:H/MPR:L/MUI:R/MS:X/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "91050f83 6.8", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:N/I:H/A:H/E:P/RL:T/RC:X/CR:M/IR:H/AR:M/MAV:L/MAC:H/MPR:L/MUI:R/MS:C/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "2734a814 5.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:N/I:H/A:L/E:U/RL:O/RC:X/CR:L/IR:M/AR:H/MAV:L/MAC:L/MPR:H/MUI:R/MS:U/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "9ce354a4 4.8", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:H/RL:T/RC:C/CR:H/IR:L/AR:X/MAV:L/MAC:X/MPR:H/MUI:X/MS:C/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "80c31e5c 5.4", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:H/A:H/E:F/RL:T/RC:U/CR:H/IR:H/AR:L/MAV:P/MAC:L/MPR:X/MUI:N/MS:X/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "877d8e14 3.4", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:L/E:H/RL:T/RC:R/CR:H/IR:X/AR:H/MAV:P/MAC:H/MPR:N/MUI:N/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "c6862996 2.9", // test name
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:H/E:X/RL:U/RC:X/CR:X/IR:M/AR:L/MAV:X/MAC:X/MPR:L/MUI:X/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "d8c0aab6 8.4", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:X/MAV:N/MAC:L/MPR:H/MUI:N/MS:X/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "dad9606e 4.8", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L/E:X/RL:O/RC:U/CR:L/IR:H/AR:L/MAV:L/MAC:X/MPR:X/MUI:R/MS:X/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "95829f43 6.1", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:F/RL:O/RC:U/CR:X/IR:X/AR:X/MAV:N/MAC:X/MPR:L/MUI:X/MS:X/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "f5f1ae74 8.1", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H/E:H/RL:X/RC:U/CR:X/IR:H/AR:H/MAV:L/MAC:L/MPR:L/MUI:N/MS:C/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "b840a83e 5.8", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:N/E:F/RL:X/RC:R/CR:L/IR:X/AR:L/MAV:A/MAC:L/MPR:H/MUI:X/MS:C/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(3.0), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "27017bc3 3.2", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H/E:P/RL:X/RC:R/CR:H/IR:L/AR:X/MAV:A/MAC:X/MPR:L/MUI:X/MS:C/MC:N/MI:X/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "00bd1bd8 2.8", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:L/E:P/RL:O/RC:U/CR:H/IR:M/AR:M/MAV:X/MAC:L/MPR:X/MUI:R/MS:C/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "9d004013 4.7", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:H/E:P/RL:W/RC:X/CR:M/IR:M/AR:X/MAV:P/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "a8a4967b 3.3", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L/E:F/RL:T/RC:U/CR:H/IR:H/AR:X/MAV:P/MAC:L/MPR:X/MUI:N/MS:U/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "def5b114 3.1", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H/E:P/RL:X/RC:C/CR:H/IR:L/AR:L/MAV:A/MAC:H/MPR:L/MUI:R/MS:X/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "bd265ca1 4.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L/E:X/RL:O/RC:U/CR:H/IR:X/AR:M/MAV:P/MAC:L/MPR:X/MUI:N/MS:U/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "6ce4c6b1 1.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N/E:U/RL:O/RC:X/CR:H/IR:L/AR:H/MAV:P/MAC:H/MPR:X/MUI:N/MS:U/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "1df00245 4.4", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H/E:F/RL:O/RC:R/CR:L/IR:X/AR:X/MAV:L/MAC:H/MPR:H/MUI:N/MS:U/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "94f4732b 4.9", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:L/E:P/RL:W/RC:U/CR:M/IR:M/AR:X/MAV:L/MAC:X/MPR:N/MUI:R/MS:U/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "c3e22bda 3.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:L/E:F/RL:W/RC:U/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:H/MUI:X/MS:U/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "fbf5ce5c 5.4", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:H/E:H/RL:U/RC:X/CR:M/IR:X/AR:M/MAV:A/MAC:X/MPR:X/MUI:N/MS:U/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "58f5b1d0 4.9", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:N/E:H/RL:U/RC:C/CR:M/IR:X/AR:H/MAV:P/MAC:L/MPR:L/MUI:R/MS:X/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "877af206 6.9", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:X/RC:R/CR:H/IR:X/AR:L/MAV:P/MAC:H/MPR:N/MUI:R/MS:C/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "0618be8a 3.8", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:L/I:H/A:N/E:P/RL:T/RC:R/CR:H/IR:H/AR:M/MAV:P/MAC:H/MPR:H/MUI:X/MS:U/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "3ffe6445 3.5", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:H/E:P/RL:T/RC:U/CR:L/IR:L/AR:L/MAV:L/MAC:X/MPR:X/MUI:N/MS:X/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "e976db6f 6.3", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:L/E:H/RL:W/RC:C/CR:X/IR:X/AR:X/MAV:N/MAC:X/MPR:L/MUI:R/MS:U/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "a3e8a74f 2.2", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H/E:U/RL:U/RC:C/CR:M/IR:X/AR:L/MAV:N/MAC:H/MPR:H/MUI:X/MS:X/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "3f68042d 4.7", // test name
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L/E:U/RL:X/RC:R/CR:M/IR:H/AR:X/MAV:N/MAC:X/MPR:L/MUI:N/MS:U/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "4ff9730c 6.6", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L/E:X/RL:X/RC:C/CR:H/IR:M/AR:H/MAV:N/MAC:H/MPR:H/MUI:X/MS:U/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "eb8ae552 3.3", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:H/E:U/RL:X/RC:X/CR:M/IR:M/AR:L/MAV:A/MAC:X/MPR:N/MUI:X/MS:U/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "d3f15ebc 6.3", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:H/E:X/RL:O/RC:R/CR:X/IR:L/AR:H/MAV:P/MAC:X/MPR:N/MUI:R/MS:C/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "eb1d4740 7.4", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N/E:X/RL:O/RC:X/CR:X/IR:M/AR:X/MAV:L/MAC:L/MPR:H/MUI:R/MS:C/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "8b8684c9 3.9", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N/E:X/RL:O/RC:R/CR:X/IR:M/AR:X/MAV:A/MAC:X/MPR:X/MUI:N/MS:U/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "b4bd10b2 5.3", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H/E:H/RL:W/RC:C/CR:X/IR:M/AR:L/MAV:L/MAC:X/MPR:N/MUI:X/MS:U/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.8)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "97f4495b 3.6", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:L/E:P/RL:O/RC:R/CR:X/IR:H/AR:L/MAV:L/MAC:X/MPR:X/MUI:N/MS:U/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "3c03efd3 4.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:F/RL:W/RC:C/CR:L/IR:L/AR:L/MAV:N/MAC:H/MPR:H/MUI:N/MS:U/MC:X/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "9f8e2f27 2.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:L/E:F/RL:W/RC:C/CR:X/IR:X/AR:M/MAV:P/MAC:L/MPR:L/MUI:N/MS:U/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "5a97f880 4.5", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L/E:F/RL:X/RC:U/CR:H/IR:M/AR:X/MAV:L/MAC:X/MPR:L/MUI:R/MS:U/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "6589e805 6.4", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:L/E:X/RL:O/RC:R/CR:H/IR:X/AR:M/MAV:P/MAC:H/MPR:L/MUI:R/MS:X/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "612d9adf 4.8", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:H/E:H/RL:O/RC:C/CR:H/IR:L/AR:M/MAV:A/MAC:H/MPR:N/MUI:R/MS:X/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "88e277e2 2.6", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:C/C:N/I:N/A:H/E:U/RL:W/RC:C/CR:L/IR:H/AR:X/MAV:X/MAC:X/MPR:X/MUI:R/MS:X/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "31f7a26c 3.7", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:C/C:N/I:N/A:N/E:X/RL:O/RC:C/CR:H/IR:L/AR:M/MAV:A/MAC:H/MPR:H/MUI:X/MS:C/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "0bb70500 8.2", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:H/E:P/RL:U/RC:R/CR:H/IR:L/AR:M/MAV:N/MAC:L/MPR:X/MUI:N/MS:U/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(8.2)), // exp environmental score
        }, // exp
      ), (
        "c12be03b 4.8", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H/E:F/RL:W/RC:X/CR:L/IR:X/AR:L/MAV:A/MAC:X/MPR:N/MUI:X/MS:U/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "a665c81c 4.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N/E:X/RL:X/RC:C/CR:L/IR:X/AR:X/MAV:P/MAC:X/MPR:X/MUI:X/MS:U/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "201d9806 7.0", // test name
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H/E:P/RL:O/RC:X/CR:H/IR:H/AR:M/MAV:L/MAC:L/MPR:H/MUI:R/MS:C/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "9edd4438 3.8", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L/E:U/RL:O/RC:C/CR:M/IR:H/AR:L/MAV:X/MAC:X/MPR:X/MUI:N/MS:U/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "b902fdff 6.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:H/E:P/RL:U/RC:X/CR:H/IR:M/AR:H/MAV:A/MAC:H/MPR:L/MUI:X/MS:U/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "2f310c8e 5.8", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:H/E:H/RL:O/RC:X/CR:X/IR:X/AR:X/MAV:P/MAC:X/MPR:N/MUI:X/MS:U/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "0a0773d7 6.8", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:H/E:U/RL:W/RC:C/CR:H/IR:X/AR:H/MAV:A/MAC:H/MPR:X/MUI:X/MS:C/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "d319aa92 6.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:L/E:F/RL:X/RC:U/CR:M/IR:X/AR:M/MAV:A/MAC:L/MPR:L/MUI:R/MS:X/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "76bb3c4f 8.1", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:N/E:H/RL:X/RC:U/CR:H/IR:X/AR:H/MAV:X/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "e4dbf509 4.8", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L/E:X/RL:U/RC:C/CR:L/IR:H/AR:H/MAV:X/MAC:H/MPR:L/MUI:X/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "0a668861 4.3", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:L/E:P/RL:U/RC:R/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:H/MUI:X/MS:X/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "74df00f2 4.9", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N/E:H/RL:W/RC:X/CR:H/IR:H/AR:X/MAV:L/MAC:H/MPR:X/MUI:N/MS:X/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(2.4), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "8864da8e 6.3", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N/E:P/RL:W/RC:U/CR:X/IR:X/AR:L/MAV:L/MAC:L/MPR:L/MUI:N/MS:U/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "e234881b 5.5", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H/E:U/RL:O/RC:R/CR:L/IR:H/AR:H/MAV:X/MAC:X/MPR:X/MUI:R/MS:U/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "b7dcb69f 1.6", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H/E:U/RL:W/RC:X/CR:M/IR:X/AR:H/MAV:P/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "cec4e050 7.6", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:L/E:X/RL:T/RC:C/CR:X/IR:M/AR:X/MAV:N/MAC:H/MPR:X/MUI:N/MS:X/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "6f4b211b 6.0", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:H/I:N/A:L/E:X/RL:O/RC:C/CR:H/IR:X/AR:X/MAV:A/MAC:H/MPR:H/MUI:R/MS:U/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "4b501ff5 5.8", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:L/E:H/RL:O/RC:R/CR:M/IR:H/AR:M/MAV:X/MAC:X/MPR:X/MUI:R/MS:U/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "758854a1 7.6", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:L/E:P/RL:O/RC:X/CR:H/IR:X/AR:L/MAV:A/MAC:L/MPR:H/MUI:N/MS:C/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "b7a2f779 5.6", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:L/E:P/RL:U/RC:X/CR:L/IR:M/AR:L/MAV:X/MAC:H/MPR:H/MUI:X/MS:X/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "7e9488f5 6.1", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:N/A:N/E:F/RL:U/RC:X/CR:X/IR:X/AR:M/MAV:P/MAC:X/MPR:H/MUI:X/MS:C/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "6f45f606 7.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:L/E:F/RL:O/RC:R/CR:X/IR:X/AR:X/MAV:N/MAC:X/MPR:N/MUI:R/MS:U/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "3db8d12d 4.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:U/C:H/I:L/A:L/E:P/RL:X/RC:R/CR:L/IR:M/AR:X/MAV:N/MAC:H/MPR:L/MUI:X/MS:U/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "4769b4ab 3.9", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:U/C:H/I:L/A:N/E:F/RL:U/RC:C/CR:L/IR:H/AR:M/MAV:L/MAC:L/MPR:N/MUI:X/MS:U/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "0e783298 2.5", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:U/C:H/I:L/A:N/E:H/RL:W/RC:U/CR:H/IR:X/AR:X/MAV:A/MAC:H/MPR:X/MUI:N/MS:X/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(2.5)), // exp environmental score
        }, // exp
      ), (
        "6ff4ffdf 7.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:U/C:H/I:L/A:N/E:P/RL:W/RC:U/CR:H/IR:H/AR:X/MAV:N/MAC:X/MPR:N/MUI:X/MS:U/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "26c7fbc4 4.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:N/E:X/RL:O/RC:R/CR:M/IR:M/AR:M/MAV:A/MAC:H/MPR:H/MUI:R/MS:X/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "f538c096 3.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:L/E:X/RL:O/RC:X/CR:M/IR:H/AR:M/MAV:P/MAC:X/MPR:L/MUI:N/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "060b0841 6.0", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H/E:P/RL:T/RC:C/CR:M/IR:X/AR:L/MAV:L/MAC:X/MPR:H/MUI:R/MS:X/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "8fbfe84f 5.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:H/E:U/RL:X/RC:C/CR:M/IR:H/AR:M/MAV:A/MAC:H/MPR:X/MUI:R/MS:C/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "1472be22 7.6", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H/E:P/RL:T/RC:C/CR:M/IR:L/AR:H/MAV:X/MAC:L/MPR:H/MUI:X/MS:C/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "8b18d90c 6.8", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L/E:F/RL:T/RC:X/CR:H/IR:H/AR:M/MAV:A/MAC:L/MPR:L/MUI:R/MS:X/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "338bc5c5 4.2", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L/E:F/RL:O/RC:C/CR:L/IR:H/AR:X/MAV:X/MAC:X/MPR:L/MUI:X/MS:C/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "67817d5c 9.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H/E:H/RL:W/RC:X/CR:L/IR:M/AR:X/MAV:A/MAC:X/MPR:N/MUI:X/MS:C/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(9.4)), // exp environmental score
        }, // exp
      ), (
        "19c22887 3.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L/E:P/RL:T/RC:X/CR:H/IR:M/AR:M/MAV:A/MAC:X/MPR:L/MUI:R/MS:X/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "3afc2638 6.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N/E:X/RL:U/RC:X/CR:H/IR:M/AR:H/MAV:L/MAC:L/MPR:X/MUI:X/MS:X/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "d036899b 5.1", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H/E:F/RL:X/RC:U/CR:X/IR:M/AR:L/MAV:A/MAC:X/MPR:L/MUI:X/MS:X/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "652d99fd 5.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N/E:U/RL:U/RC:X/CR:H/IR:X/AR:X/MAV:N/MAC:H/MPR:L/MUI:N/MS:U/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "3ec8f5ef 6.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:H/E:F/RL:W/RC:X/CR:M/IR:L/AR:X/MAV:L/MAC:L/MPR:X/MUI:R/MS:C/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "83cf1f0e 3.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:L/E:P/RL:X/RC:C/CR:L/IR:L/AR:L/MAV:X/MAC:L/MPR:L/MUI:X/MS:C/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "026264f8 8.6", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:H/E:H/RL:X/RC:X/CR:X/IR:H/AR:X/MAV:L/MAC:L/MPR:L/MUI:N/MS:X/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(8.6)), // exp environmental score
        }, // exp
      ), (
        "d1753adb 4.1", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:H/RL:X/RC:R/CR:H/IR:M/AR:M/MAV:L/MAC:X/MPR:H/MUI:X/MS:U/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "68922cd3 5.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:L/E:H/RL:O/RC:U/CR:M/IR:H/AR:M/MAV:X/MAC:H/MPR:L/MUI:R/MS:U/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "9886505b 4.8", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:C/C:N/I:N/A:L/E:F/RL:T/RC:X/CR:H/IR:H/AR:M/MAV:N/MAC:H/MPR:H/MUI:X/MS:U/MC:X/MI:L/MA:H", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "c16879a2 6.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:X/IR:M/AR:H/MAV:N/MAC:H/MPR:H/MUI:X/MS:U/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "adaa680a 6.8", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:H/E:F/RL:W/RC:C/CR:H/IR:M/AR:L/MAV:P/MAC:L/MPR:X/MUI:R/MS:C/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "059c4781 5.2", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:X/RC:C/CR:L/IR:X/AR:L/MAV:N/MAC:L/MPR:H/MUI:N/MS:U/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "d8944230 2.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:L/E:U/RL:T/RC:X/CR:X/IR:X/AR:X/MAV:A/MAC:H/MPR:X/MUI:N/MS:C/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "b4287e2a 3.5", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:H/E:X/RL:X/RC:U/CR:X/IR:M/AR:H/MAV:X/MAC:X/MPR:X/MUI:R/MS:U/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "638521b7 6.3", // test name
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L/E:H/RL:U/RC:C/CR:X/IR:H/AR:M/MAV:X/MAC:X/MPR:H/MUI:N/MS:X/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "ab154c7a 5.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H/E:F/RL:T/RC:U/CR:H/IR:H/AR:M/MAV:P/MAC:H/MPR:X/MUI:R/MS:U/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(9.6), // exp base score
          temporal: Some(Score::from(8.3)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "dc8f1b18 7.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N/E:P/RL:O/RC:C/CR:H/IR:H/AR:L/MAV:X/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "ea350aef 5.1", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:L/E:U/RL:W/RC:C/CR:H/IR:L/AR:X/MAV:N/MAC:X/MPR:L/MUI:N/MS:C/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "cd759662 6.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H/E:H/RL:O/RC:R/CR:H/IR:L/AR:M/MAV:A/MAC:X/MPR:N/MUI:X/MS:U/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(9.3), // exp base score
          temporal: Some(Score::from(8.5)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "e31ea422 4.5", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H/E:U/RL:X/RC:R/CR:L/IR:H/AR:H/MAV:P/MAC:L/MPR:L/MUI:N/MS:X/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(9.3), // exp base score
          temporal: Some(Score::from(8.2)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "826a6d60 6.1", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H/E:U/RL:W/RC:U/CR:H/IR:M/AR:H/MAV:N/MAC:H/MPR:X/MUI:R/MS:X/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "3ad3193f 7.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:T/RC:C/CR:X/IR:H/AR:M/MAV:X/MAC:L/MPR:X/MUI:R/MS:X/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.8)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "138caad3 2.1", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H/E:X/RL:X/RC:R/CR:H/IR:M/AR:M/MAV:A/MAC:X/MPR:H/MUI:R/MS:X/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(8.0)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "01a9de81 4.5", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L/E:U/RL:O/RC:X/CR:M/IR:L/AR:M/MAV:A/MAC:H/MPR:L/MUI:X/MS:U/MC:X/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "4d4e05f1 4.3", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N/E:H/RL:W/RC:U/CR:H/IR:M/AR:M/MAV:P/MAC:X/MPR:H/MUI:R/MS:X/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "dd99d704 4.5", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:U/RL:W/RC:U/CR:H/IR:L/AR:X/MAV:X/MAC:X/MPR:H/MUI:X/MS:U/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "6ef1a06c 3.2", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L/E:P/RL:O/RC:X/CR:L/IR:H/AR:L/MAV:A/MAC:H/MPR:X/MUI:X/MS:U/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(7.8)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "b2ae7952 3.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L/E:F/RL:U/RC:U/CR:L/IR:L/AR:X/MAV:N/MAC:H/MPR:H/MUI:R/MS:U/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "3fb69ef9 3.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:L/E:F/RL:X/RC:C/CR:L/IR:X/AR:L/MAV:P/MAC:X/MPR:L/MUI:N/MS:C/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.8)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "ecba301c 3.3", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:H/RL:O/RC:C/CR:X/IR:H/AR:M/MAV:P/MAC:X/MPR:H/MUI:R/MS:C/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "af187ec6 4.3", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:L/E:P/RL:T/RC:C/CR:M/IR:X/AR:M/MAV:N/MAC:X/MPR:N/MUI:R/MS:C/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "378d6ea4 3.5", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:L/E:X/RL:T/RC:U/CR:L/IR:M/AR:M/MAV:L/MAC:L/MPR:L/MUI:X/MS:X/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "fac24d14 4.9", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N/E:F/RL:T/RC:C/CR:X/IR:X/AR:H/MAV:A/MAC:X/MPR:H/MUI:N/MS:U/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "2198bed0 4.9", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:H/E:H/RL:W/RC:C/CR:M/IR:X/AR:H/MAV:L/MAC:X/MPR:N/MUI:R/MS:C/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "8dfe7380 5.4", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N/E:F/RL:O/RC:U/CR:X/IR:M/AR:L/MAV:L/MAC:H/MPR:X/MUI:X/MS:C/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "252bd412 6.6", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:H/E:X/RL:U/RC:X/CR:X/IR:M/AR:L/MAV:X/MAC:L/MPR:H/MUI:N/MS:C/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(7.6)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "4cdf1370 5.7", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:H/E:X/RL:W/RC:R/CR:X/IR:H/AR:L/MAV:X/MAC:X/MPR:N/MUI:R/MS:U/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "a0fa00ce 6.0", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N/E:X/RL:O/RC:U/CR:H/IR:L/AR:M/MAV:X/MAC:H/MPR:L/MUI:X/MS:U/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "9c2c0866 4.9", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L/E:H/RL:U/RC:R/CR:H/IR:L/AR:L/MAV:N/MAC:H/MPR:X/MUI:N/MS:C/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "56042e42 3.6", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L/E:U/RL:T/RC:C/CR:M/IR:X/AR:M/MAV:X/MAC:L/MPR:L/MUI:R/MS:U/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "c2231843 7.2", // test name
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N/E:X/RL:O/RC:X/CR:H/IR:L/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "5475921e 6.6", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:N/E:F/RL:X/RC:C/CR:M/IR:H/AR:M/MAV:L/MAC:X/MPR:L/MUI:X/MS:X/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "88bcb495 1.7", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:N/E:F/RL:O/RC:C/CR:X/IR:X/AR:X/MAV:P/MAC:H/MPR:X/MUI:R/MS:C/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "96ff174e 4.5", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N/E:P/RL:T/RC:R/CR:X/IR:M/AR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:U/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "fb6da3e3 5.5", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N/E:U/RL:T/RC:U/CR:H/IR:X/AR:L/MAV:X/MAC:H/MPR:N/MUI:R/MS:X/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "5c83bc24 7.6", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:H/E:H/RL:O/RC:R/CR:X/IR:M/AR:M/MAV:N/MAC:L/MPR:L/MUI:X/MS:U/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "7a25bb04 4.6", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N/E:F/RL:X/RC:C/CR:M/IR:L/AR:H/MAV:X/MAC:L/MPR:N/MUI:R/MS:X/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "5ac6cedf 4.8", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H/E:H/RL:T/RC:C/CR:L/IR:X/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:U/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "c567bcc1 6.3", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N/E:H/RL:T/RC:X/CR:H/IR:H/AR:L/MAV:L/MAC:L/MPR:H/MUI:N/MS:X/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "b6a6e7c3 7.8", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:F/RL:O/RC:C/CR:L/IR:H/AR:H/MAV:A/MAC:L/MPR:X/MUI:N/MS:C/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "28681312 4.6", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:H/E:P/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:A/MAC:H/MPR:X/MUI:N/MS:U/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "d15e7c20 2.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:N/E:P/RL:X/RC:R/CR:L/IR:M/AR:M/MAV:L/MAC:X/MPR:L/MUI:X/MS:U/MC:N/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "43f8279f 1.7", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:H/A:N/E:H/RL:T/RC:R/CR:M/IR:H/AR:X/MAV:A/MAC:X/MPR:H/MUI:X/MS:U/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "7fef726b 5.7", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N/E:U/RL:U/RC:C/CR:M/IR:H/AR:L/MAV:N/MAC:L/MPR:X/MUI:N/MS:X/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "9a6e8aa4 0.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N/E:F/RL:U/RC:X/CR:M/IR:L/AR:H/MAV:X/MAC:L/MPR:H/MUI:R/MS:U/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "b4df935b 5.8", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:H/E:X/RL:T/RC:U/CR:H/IR:L/AR:H/MAV:X/MAC:L/MPR:X/MUI:N/MS:X/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "96e3cf1d 4.6", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N/E:P/RL:W/RC:X/CR:L/IR:M/AR:H/MAV:N/MAC:X/MPR:X/MUI:R/MS:U/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "a7abdced 7.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L/E:H/RL:U/RC:R/CR:M/IR:L/AR:H/MAV:N/MAC:H/MPR:L/MUI:X/MS:C/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "afe6d7f0 6.2", // test name
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L/E:P/RL:T/RC:U/CR:M/IR:M/AR:H/MAV:A/MAC:H/MPR:H/MUI:R/MS:C/MC:X/MI:L/MA:H", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "e16db08e 2.9", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N/E:U/RL:X/RC:C/CR:H/IR:L/AR:M/MAV:P/MAC:X/MPR:N/MUI:X/MS:X/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "59a975bd 9.3", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:L/E:F/RL:U/RC:R/CR:M/IR:M/AR:X/MAV:N/MAC:L/MPR:N/MUI:N/MS:X/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(9.3)), // exp environmental score
        }, // exp
      ), (
        "7ee26531 2.8", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:H/E:H/RL:T/RC:U/CR:M/IR:M/AR:L/MAV:N/MAC:X/MPR:N/MUI:N/MS:C/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "69c83a2b 6.1", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:H/E:U/RL:X/RC:C/CR:M/IR:L/AR:M/MAV:A/MAC:L/MPR:N/MUI:R/MS:C/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "c99ccc2c 5.4", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L/E:U/RL:T/RC:U/CR:M/IR:M/AR:M/MAV:L/MAC:X/MPR:X/MUI:R/MS:X/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "0b1fc7b5 5.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:L/E:H/RL:X/RC:X/CR:H/IR:M/AR:H/MAV:A/MAC:H/MPR:H/MUI:R/MS:U/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "b02b00eb 6.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L/E:F/RL:X/RC:X/CR:L/IR:L/AR:X/MAV:N/MAC:L/MPR:X/MUI:N/MS:U/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "17ffcf29 5.6", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H/E:U/RL:X/RC:C/CR:L/IR:L/AR:M/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "1ba32fb0 2.6", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:L/E:P/RL:T/RC:R/CR:L/IR:H/AR:L/MAV:P/MAC:L/MPR:X/MUI:X/MS:U/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "4941470a 4.2", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N/E:U/RL:U/RC:R/CR:X/IR:L/AR:X/MAV:X/MAC:H/MPR:H/MUI:N/MS:X/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(2.5), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "e0c9fd30 4.6", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H/E:H/RL:T/RC:X/CR:X/IR:X/AR:L/MAV:L/MAC:H/MPR:L/MUI:N/MS:X/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "142d2543 5.1", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:N/E:X/RL:X/RC:X/CR:X/IR:H/AR:M/MAV:L/MAC:X/MPR:N/MUI:X/MS:U/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "1e910526 5.8", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:H/E:X/RL:T/RC:X/CR:L/IR:H/AR:X/MAV:P/MAC:H/MPR:X/MUI:X/MS:U/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "7b7a1d12 2.8", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:X/RC:R/CR:L/IR:L/AR:L/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "891522b1 4.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H/E:X/RL:T/RC:X/CR:H/IR:L/AR:H/MAV:N/MAC:H/MPR:H/MUI:X/MS:X/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "720cc644 6.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H/E:X/RL:U/RC:C/CR:M/IR:M/AR:H/MAV:X/MAC:H/MPR:H/MUI:X/MS:U/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "1a53a8f4 6.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N/E:X/RL:X/RC:X/CR:M/IR:M/AR:M/MAV:L/MAC:H/MPR:X/MUI:X/MS:C/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(2.5), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "50f57286 7.1", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:L/E:H/RL:X/RC:X/CR:H/IR:H/AR:M/MAV:P/MAC:H/MPR:N/MUI:X/MS:X/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "6d51c9b4 3.5", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:N/A:N/E:U/RL:T/RC:X/CR:M/IR:X/AR:X/MAV:L/MAC:X/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "390f926f 3.8", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N/E:U/RL:W/RC:U/CR:M/IR:H/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:C/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "88553e34 1.8", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N/E:X/RL:W/RC:C/CR:L/IR:L/AR:H/MAV:L/MAC:X/MPR:N/MUI:X/MS:U/MC:X/MI:N/MA:X", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "f7742255 4.7", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:L/E:H/RL:T/RC:R/CR:X/IR:M/AR:H/MAV:X/MAC:X/MPR:L/MUI:R/MS:X/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "da8dc156 4.2", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N/E:H/RL:X/RC:X/CR:M/IR:M/AR:L/MAV:L/MAC:L/MPR:H/MUI:R/MS:X/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "34f4fa02 3.1", // test name
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N/E:P/RL:W/RC:R/CR:X/IR:L/AR:X/MAV:L/MAC:X/MPR:L/MUI:N/MS:C/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(2.2), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "fcd3c312 7.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L/E:H/RL:T/RC:U/CR:X/IR:X/AR:H/MAV:X/MAC:L/MPR:X/MUI:N/MS:C/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "a9c27633 5.9", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:L/E:P/RL:U/RC:C/CR:H/IR:H/AR:L/MAV:X/MAC:H/MPR:N/MUI:N/MS:C/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "e48c9145 2.9", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L/E:F/RL:O/RC:R/CR:M/IR:L/AR:M/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "7a5f1210 2.3", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H/E:P/RL:W/RC:U/CR:H/IR:L/AR:L/MAV:A/MAC:X/MPR:H/MUI:X/MS:U/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(2.3)), // exp environmental score
        }, // exp
      ), (
        "d8b02895 4.6", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L/E:H/RL:X/RC:R/CR:M/IR:L/AR:H/MAV:P/MAC:L/MPR:N/MUI:R/MS:U/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "236a3223 3.1", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L/E:U/RL:T/RC:X/CR:H/IR:X/AR:L/MAV:P/MAC:X/MPR:H/MUI:N/MS:X/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "e6bcc4dc 3.1", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H/E:H/RL:W/RC:X/CR:M/IR:M/AR:M/MAV:P/MAC:X/MPR:X/MUI:N/MS:X/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "71482b78 5.6", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:L/E:P/RL:U/RC:U/CR:M/IR:H/AR:L/MAV:N/MAC:H/MPR:H/MUI:R/MS:U/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "a32cd612 6.4", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:H/E:F/RL:T/RC:R/CR:M/IR:M/AR:L/MAV:A/MAC:X/MPR:N/MUI:N/MS:X/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "52da715e 4.2", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N/E:U/RL:O/RC:U/CR:X/IR:X/AR:M/MAV:L/MAC:L/MPR:H/MUI:X/MS:X/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "e287f9d4 5.3", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L/E:P/RL:O/RC:R/CR:H/IR:M/AR:H/MAV:A/MAC:X/MPR:L/MUI:X/MS:C/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "916f02f1 2.3", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H/E:X/RL:T/RC:U/CR:L/IR:H/AR:L/MAV:X/MAC:H/MPR:X/MUI:X/MS:C/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(2.3)), // exp environmental score
        }, // exp
      ), (
        "78bfd8bf 3.9", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N/E:P/RL:W/RC:C/CR:H/IR:L/AR:X/MAV:N/MAC:H/MPR:X/MUI:N/MS:X/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "0de8b4f8 2.0", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L/E:F/RL:U/RC:X/CR:X/IR:X/AR:M/MAV:N/MAC:H/MPR:H/MUI:X/MS:U/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "c31ffd3f 4.2", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L/E:P/RL:X/RC:X/CR:H/IR:M/AR:L/MAV:L/MAC:X/MPR:X/MUI:R/MS:X/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "be185295 4.2", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L/E:U/RL:W/RC:C/CR:L/IR:X/AR:H/MAV:P/MAC:X/MPR:N/MUI:N/MS:C/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "786adc9a 5.9", // test name
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L/E:X/RL:T/RC:R/CR:X/IR:L/AR:X/MAV:X/MAC:H/MPR:N/MUI:N/MS:X/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(2.5), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "7cc17860 3.7", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:H/E:P/RL:W/RC:C/CR:L/IR:X/AR:X/MAV:L/MAC:H/MPR:H/MUI:R/MS:U/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "8ddba187 4.9", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N/E:U/RL:O/RC:U/CR:M/IR:X/AR:M/MAV:X/MAC:L/MPR:N/MUI:R/MS:U/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "8f0325f1 9.7", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N/E:X/RL:U/RC:C/CR:X/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:R/MS:C/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(9.7)), // exp environmental score
        }, // exp
      ), (
        "de69c093 7.2", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:X/AR:X/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "20a762f0 5.5", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:F/RL:U/RC:R/CR:M/IR:M/AR:X/MAV:L/MAC:X/MPR:H/MUI:R/MS:U/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "6fb39a53 3.8", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:N/E:P/RL:T/RC:X/CR:L/IR:L/AR:H/MAV:N/MAC:H/MPR:H/MUI:R/MS:X/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "08f2251c 6.2", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N/E:X/RL:W/RC:C/CR:M/IR:M/AR:M/MAV:L/MAC:X/MPR:X/MUI:N/MS:X/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "7dc85bb6 6.6", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N/E:X/RL:W/RC:X/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:X/MUI:X/MS:C/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "c4beed23 3.8", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H/E:P/RL:O/RC:C/CR:L/IR:L/AR:M/MAV:P/MAC:X/MPR:X/MUI:X/MS:X/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "3d7d54f3 4.9", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:H/I:N/A:L/E:F/RL:X/RC:R/CR:X/IR:L/AR:X/MAV:P/MAC:L/MPR:L/MUI:N/MS:X/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "cafd366c 2.0", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:L/I:N/A:N/E:U/RL:O/RC:U/CR:M/IR:H/AR:L/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "11a91231 7.3", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:H/E:F/RL:U/RC:R/CR:X/IR:M/AR:H/MAV:L/MAC:H/MPR:L/MUI:N/MS:C/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "90e9b05d 4.5", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:N/E:H/RL:W/RC:C/CR:M/IR:X/AR:H/MAV:L/MAC:H/MPR:X/MUI:N/MS:C/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "d17f1744 5.1", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:N/I:N/A:H/E:H/RL:U/RC:C/CR:M/IR:M/AR:M/MAV:P/MAC:X/MPR:N/MUI:X/MS:X/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "a507db16 6.8", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:N/I:N/A:L/E:F/RL:T/RC:C/CR:H/IR:X/AR:L/MAV:N/MAC:H/MPR:X/MUI:X/MS:X/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "b8571ab0 6.2", // test name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:L/E:F/RL:O/RC:R/CR:M/IR:M/AR:X/MAV:N/MAC:L/MPR:X/MUI:X/MS:C/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(3.1), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "9289a68b 2.1", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H/E:X/RL:O/RC:R/CR:X/IR:L/AR:M/MAV:X/MAC:L/MPR:H/MUI:N/MS:U/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(8.4), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "bdd1c8bf 2.9", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H/E:X/RL:X/RC:R/CR:L/IR:H/AR:X/MAV:A/MAC:H/MPR:L/MUI:N/MS:C/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(8.4)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "d8cb8c79 6.1", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:U/RC:R/CR:L/IR:X/AR:X/MAV:X/MAC:L/MPR:H/MUI:X/MS:X/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "e3b80cff 5.6", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L/E:U/RL:O/RC:X/CR:X/IR:X/AR:X/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "1f126508 5.2", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:H/E:U/RL:T/RC:R/CR:M/IR:H/AR:L/MAV:X/MAC:H/MPR:X/MUI:N/MS:C/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "0fcbcc64 3.3", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N/E:U/RL:T/RC:U/CR:H/IR:H/AR:L/MAV:N/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "aa9db596 7.2", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N/E:X/RL:W/RC:X/CR:X/IR:M/AR:M/MAV:L/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "f5a3814d 3.0", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N/E:P/RL:W/RC:X/CR:M/IR:M/AR:M/MAV:L/MAC:X/MPR:H/MUI:N/MS:X/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "5cbd6121 2.2", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L/E:U/RL:X/RC:R/CR:H/IR:M/AR:M/MAV:L/MAC:H/MPR:H/MUI:R/MS:U/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "a7aae3b8 2.9", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H/E:F/RL:X/RC:C/CR:X/IR:M/AR:X/MAV:P/MAC:H/MPR:X/MUI:N/MS:U/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "22557d79 3.6", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N/E:H/RL:T/RC:C/CR:H/IR:L/AR:X/MAV:X/MAC:X/MPR:N/MUI:X/MS:U/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "efab2204 3.8", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L/E:H/RL:T/RC:R/CR:H/IR:M/AR:L/MAV:X/MAC:X/MPR:L/MUI:X/MS:C/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "4c737000 2.9", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:L/E:U/RL:U/RC:R/CR:L/IR:X/AR:X/MAV:A/MAC:H/MPR:H/MUI:N/MS:C/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "2ef88322 4.7", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N/E:H/RL:X/RC:U/CR:X/IR:L/AR:M/MAV:P/MAC:H/MPR:H/MUI:N/MS:C/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "3558e391 8.0", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:H/E:H/RL:U/RC:X/CR:M/IR:X/AR:L/MAV:X/MAC:X/MPR:L/MUI:R/MS:C/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(8.0)), // exp environmental score
        }, // exp
      ), (
        "266ad00a 4.2", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L/E:P/RL:U/RC:X/CR:X/IR:H/AR:M/MAV:X/MAC:X/MPR:H/MUI:X/MS:U/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "5568dde6 3.0", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N/E:X/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:L/MAC:L/MPR:X/MUI:X/MS:X/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(3.9), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "6c3e53a8 5.3", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N/E:F/RL:O/RC:U/CR:M/IR:M/AR:H/MAV:L/MAC:H/MPR:L/MUI:R/MS:U/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "1f355bfb 4.0", // test name
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N/E:U/RL:X/RC:X/CR:X/IR:M/AR:H/MAV:N/MAC:L/MPR:N/MUI:X/MS:X/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "ea27ff10 7.3", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:W/RC:C/CR:X/IR:X/AR:X/MAV:N/MAC:L/MPR:X/MUI:N/MS:U/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(9.3), // exp base score
          temporal: Some(Score::from(9.1)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "04f6cbe2 8.0", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/E:X/RL:O/RC:X/CR:M/IR:H/AR:M/MAV:A/MAC:H/MPR:N/MUI:X/MS:X/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(9.2), // exp base score
          temporal: Some(Score::from(8.8)), // exp temporal score
          environmental: Some(Score::from(8.0)), // exp environmental score
        }, // exp
      ), (
        "dd5d2858 0.0", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/E:F/RL:T/RC:R/CR:L/IR:M/AR:L/MAV:P/MAC:X/MPR:N/MUI:X/MS:U/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(8.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "17a44e3f 5.5", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L/E:P/RL:X/RC:U/CR:H/IR:L/AR:M/MAV:P/MAC:H/MPR:N/MUI:N/MS:C/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "5abe5e71 7.3", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N/E:X/RL:X/RC:R/CR:H/IR:X/AR:H/MAV:X/MAC:H/MPR:N/MUI:R/MS:C/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "fa964187 2.6", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:L/E:P/RL:U/RC:U/CR:M/IR:M/AR:L/MAV:P/MAC:X/MPR:N/MUI:R/MS:C/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "0073e305 6.8", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:H/E:U/RL:O/RC:C/CR:X/IR:M/AR:L/MAV:N/MAC:H/MPR:N/MUI:N/MS:X/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "e00effea 3.5", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N/E:U/RL:U/RC:U/CR:H/IR:L/AR:X/MAV:A/MAC:H/MPR:H/MUI:X/MS:X/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "2a6ffa30 4.3", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:H/RL:U/RC:U/CR:X/IR:H/AR:X/MAV:A/MAC:L/MPR:X/MUI:R/MS:X/MC:X/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "02caa6af 6.9", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/E:U/RL:O/RC:X/CR:H/IR:H/AR:M/MAV:X/MAC:H/MPR:L/MUI:N/MS:C/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "7f2dd0a2 3.7", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:H/E:X/RL:T/RC:R/CR:H/IR:H/AR:M/MAV:P/MAC:H/MPR:L/MUI:X/MS:C/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "d8b89f0c 3.8", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L/E:P/RL:X/RC:U/CR:X/IR:L/AR:M/MAV:L/MAC:X/MPR:N/MUI:N/MS:C/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "d79166d2 4.0", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L/E:X/RL:T/RC:R/CR:H/IR:X/AR:L/MAV:P/MAC:X/MPR:H/MUI:N/MS:C/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "69f88325 4.7", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:L/E:P/RL:X/RC:X/CR:M/IR:L/AR:L/MAV:A/MAC:X/MPR:N/MUI:X/MS:U/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "066d26e2 5.9", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:L/E:X/RL:W/RC:C/CR:L/IR:X/AR:M/MAV:A/MAC:X/MPR:L/MUI:X/MS:U/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "eb824064 1.9", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N/E:U/RL:O/RC:U/CR:M/IR:X/AR:X/MAV:P/MAC:L/MPR:X/MUI:R/MS:C/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "2a01ec9a 4.2", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L/E:P/RL:X/RC:C/CR:L/IR:H/AR:L/MAV:L/MAC:X/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "c41106b0 7.2", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:H/E:H/RL:T/RC:X/CR:M/IR:M/AR:X/MAV:A/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "6c5d5c93 6.4", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:L/E:F/RL:U/RC:U/CR:H/IR:X/AR:M/MAV:N/MAC:L/MPR:H/MUI:N/MS:U/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "4a91a0ce 6.0", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:L/E:X/RL:W/RC:X/CR:M/IR:M/AR:L/MAV:N/MAC:H/MPR:N/MUI:X/MS:U/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "023cb198 0.0", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H/E:P/RL:T/RC:C/CR:H/IR:M/AR:L/MAV:X/MAC:X/MPR:N/MUI:N/MS:X/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "3af5eb25 7.0", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N/E:P/RL:W/RC:U/CR:L/IR:H/AR:X/MAV:N/MAC:L/MPR:N/MUI:R/MS:X/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "53484e87 7.3", // test name
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L/E:H/RL:U/RC:X/CR:H/IR:M/AR:L/MAV:P/MAC:X/MPR:N/MUI:R/MS:C/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "ecf06cd9 5.8", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:N/E:H/RL:U/RC:C/CR:L/IR:M/AR:H/MAV:P/MAC:H/MPR:L/MUI:X/MS:X/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "61353842 7.1", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:L/I:H/A:L/E:H/RL:O/RC:U/CR:M/IR:M/AR:M/MAV:N/MAC:H/MPR:N/MUI:X/MS:C/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "67e30c63 3.3", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:L/I:H/A:N/E:H/RL:X/RC:U/CR:M/IR:M/AR:X/MAV:N/MAC:L/MPR:L/MUI:R/MS:U/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "d1f6df62 3.2", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:N/E:P/RL:W/RC:R/CR:L/IR:X/AR:M/MAV:P/MAC:X/MPR:N/MUI:N/MS:X/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "7203bcb3 6.8", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N/E:H/RL:U/RC:X/CR:L/IR:X/AR:L/MAV:X/MAC:L/MPR:L/MUI:R/MS:C/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "e1d1835f 5.8", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:H/E:F/RL:X/RC:C/CR:M/IR:H/AR:M/MAV:P/MAC:X/MPR:L/MUI:R/MS:X/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "57d42dc6 1.7", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:H/E:F/RL:O/RC:X/CR:M/IR:H/AR:X/MAV:P/MAC:X/MPR:L/MUI:N/MS:X/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "ceeca264 4.4", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:L/E:H/RL:X/RC:U/CR:L/IR:M/AR:H/MAV:P/MAC:H/MPR:H/MUI:X/MS:C/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "48c64b9b 6.9", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:L/E:P/RL:U/RC:X/CR:L/IR:X/AR:X/MAV:A/MAC:L/MPR:N/MUI:X/MS:U/MC:X/MI:L/MA:H", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "ab41fbfb 3.8", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:L/E:U/RL:W/RC:U/CR:M/IR:X/AR:X/MAV:A/MAC:L/MPR:L/MUI:N/MS:U/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "f42af1df 6.5", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N/E:F/RL:U/RC:X/CR:M/IR:H/AR:H/MAV:N/MAC:L/MPR:X/MUI:X/MS:U/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(2.2), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "b17749c0 4.5", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:L/E:U/RL:W/RC:C/CR:M/IR:L/AR:X/MAV:X/MAC:H/MPR:H/MUI:R/MS:U/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "2a2aa235 6.9", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:H/A:L/E:F/RL:X/RC:U/CR:X/IR:L/AR:H/MAV:X/MAC:X/MPR:H/MUI:R/MS:X/MC:X/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "42d51522 7.1", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:L/E:F/RL:O/RC:X/CR:X/IR:X/AR:L/MAV:L/MAC:L/MPR:L/MUI:N/MS:C/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "75ebd13d 0.0", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:N/I:H/A:L/E:X/RL:T/RC:R/CR:H/IR:L/AR:H/MAV:L/MAC:H/MPR:N/MUI:R/MS:X/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "43ec073b 9.0", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:N/E:F/RL:T/RC:C/CR:M/IR:L/AR:M/MAV:X/MAC:L/MPR:N/MUI:N/MS:C/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(9.0)), // exp environmental score
        }, // exp
      ), (
        "06e3ea55 6.2", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H/E:H/RL:W/RC:C/CR:L/IR:H/AR:H/MAV:X/MAC:H/MPR:X/MUI:R/MS:X/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "6dac0d40 4.7", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:H/A:H/E:X/RL:X/RC:R/CR:H/IR:H/AR:X/MAV:P/MAC:L/MPR:H/MUI:X/MS:C/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "1e93d1c3 2.5", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:L/E:U/RL:W/RC:X/CR:H/IR:H/AR:M/MAV:P/MAC:L/MPR:N/MUI:X/MS:U/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(2.5)), // exp environmental score
        }, // exp
      ), (
        "79a3e8fa 4.2", // test name
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:N/E:U/RL:X/RC:U/CR:H/IR:L/AR:X/MAV:L/MAC:X/MPR:H/MUI:N/MS:U/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(4.2), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "c530875d 2.9", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:H/E:F/RL:T/RC:R/CR:H/IR:H/AR:M/MAV:L/MAC:X/MPR:N/MUI:X/MS:C/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(8.4), // exp base score
          temporal: Some(Score::from(7.6)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "78d72677 3.9", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H/E:H/RL:O/RC:X/CR:L/IR:L/AR:L/MAV:X/MAC:H/MPR:H/MUI:X/MS:X/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "f9f1cbca 7.1", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:H/E:U/RL:O/RC:R/CR:M/IR:H/AR:H/MAV:X/MAC:H/MPR:X/MUI:X/MS:C/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "5ab8b8ad 8.4", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:H/A:N/E:F/RL:O/RC:X/CR:X/IR:M/AR:H/MAV:N/MAC:L/MPR:N/MUI:R/MS:C/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "cb35aa43 0.0", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:H/E:U/RL:T/RC:R/CR:L/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MS:X/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "3a6356f7 2.6", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:L/E:X/RL:U/RC:U/CR:M/IR:L/AR:H/MAV:L/MAC:H/MPR:L/MUI:N/MS:X/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "b093d186 6.4", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N/E:U/RL:X/RC:U/CR:L/IR:X/AR:H/MAV:L/MAC:H/MPR:L/MUI:R/MS:C/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "4c14458d 6.6", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:H/E:F/RL:U/RC:U/CR:X/IR:L/AR:X/MAV:N/MAC:L/MPR:N/MUI:R/MS:X/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "f0be4e3e 1.1", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:H/E:P/RL:T/RC:U/CR:L/IR:M/AR:H/MAV:P/MAC:L/MPR:H/MUI:N/MS:C/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "3e8628c4 5.5", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H/E:F/RL:T/RC:X/CR:M/IR:M/AR:X/MAV:P/MAC:H/MPR:L/MUI:X/MS:X/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "edfcd7b1 3.9", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N/E:F/RL:X/RC:X/CR:M/IR:X/AR:M/MAV:P/MAC:X/MPR:L/MUI:X/MS:U/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "c0ac5388 4.7", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:N/A:L/E:H/RL:X/RC:C/CR:X/IR:H/AR:M/MAV:P/MAC:H/MPR:X/MUI:X/MS:X/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "5ee505f0 7.1", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:N/A:N/E:U/RL:U/RC:X/CR:X/IR:M/AR:H/MAV:L/MAC:H/MPR:X/MUI:N/MS:X/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "2da0e609 8.1", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H/E:H/RL:T/RC:U/CR:H/IR:X/AR:H/MAV:X/MAC:L/MPR:X/MUI:R/MS:X/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "c0b308ea 6.2", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:N/E:P/RL:X/RC:U/CR:M/IR:H/AR:X/MAV:P/MAC:X/MPR:L/MUI:N/MS:X/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "1c09bab8 3.7", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N/E:F/RL:T/RC:C/CR:M/IR:X/AR:L/MAV:L/MAC:H/MPR:N/MUI:N/MS:C/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "8a18cd9b 3.2", // test name
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:L/E:X/RL:U/RC:C/CR:X/IR:H/AR:L/MAV:L/MAC:H/MPR:N/MUI:X/MS:X/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "63dd074b 7.4", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N/E:X/RL:T/RC:R/CR:H/IR:X/AR:X/MAV:X/MAC:L/MPR:L/MUI:R/MS:C/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(8.1)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "efbab1bd 7.8", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N/E:X/RL:W/RC:C/CR:X/IR:H/AR:H/MAV:A/MAC:L/MPR:H/MUI:R/MS:X/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(8.5)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "d020f109 5.0", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N/E:F/RL:T/RC:X/CR:M/IR:M/AR:M/MAV:L/MAC:H/MPR:L/MUI:X/MS:U/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "4a2f8e99 7.4", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:L/E:P/RL:T/RC:X/CR:H/IR:X/AR:X/MAV:X/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "a2bd57bc 4.4", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N/E:F/RL:O/RC:R/CR:X/IR:L/AR:X/MAV:N/MAC:L/MPR:X/MUI:N/MS:X/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "4776f7be 7.8", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:H/E:P/RL:U/RC:R/CR:M/IR:H/AR:M/MAV:N/MAC:X/MPR:L/MUI:X/MS:X/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "ab5464ae 7.1", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N/E:F/RL:T/RC:R/CR:H/IR:L/AR:H/MAV:N/MAC:X/MPR:L/MUI:R/MS:C/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "c1237009 5.2", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N/E:U/RL:W/RC:R/CR:L/IR:X/AR:L/MAV:X/MAC:H/MPR:H/MUI:R/MS:X/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "39d352ec 2.4", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:L/E:X/RL:W/RC:X/CR:L/IR:L/AR:M/MAV:X/MAC:X/MPR:L/MUI:X/MS:U/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "33eed348 2.4", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:H/E:U/RL:W/RC:X/CR:M/IR:L/AR:L/MAV:P/MAC:L/MPR:H/MUI:X/MS:C/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "554e3990 3.4", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:L/E:P/RL:O/RC:R/CR:X/IR:M/AR:H/MAV:P/MAC:L/MPR:H/MUI:X/MS:U/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "ae70a2bd 7.2", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:L/E:U/RL:U/RC:U/CR:H/IR:M/AR:H/MAV:X/MAC:L/MPR:H/MUI:R/MS:X/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "96b76b18 5.6", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:U/RL:X/RC:R/CR:M/IR:M/AR:X/MAV:P/MAC:X/MPR:N/MUI:N/MS:X/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "3c46c07c 5.9", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:H/E:X/RL:X/RC:X/CR:M/IR:M/AR:X/MAV:P/MAC:H/MPR:L/MUI:X/MS:U/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "028e0a9e 4.5", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L/E:U/RL:T/RC:C/CR:X/IR:X/AR:L/MAV:L/MAC:X/MPR:N/MUI:X/MS:U/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "6e955a47 2.1", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H/E:U/RL:T/RC:R/CR:M/IR:M/AR:M/MAV:L/MAC:H/MPR:L/MUI:N/MS:X/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "ec3c999a 6.0", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H/E:F/RL:O/RC:C/CR:M/IR:M/AR:X/MAV:A/MAC:L/MPR:X/MUI:X/MS:X/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "a2b12163 6.6", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L/E:U/RL:W/RC:U/CR:M/IR:H/AR:H/MAV:X/MAC:X/MPR:H/MUI:N/MS:C/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "cc2bf403 3.2", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/E:H/RL:O/RC:R/CR:L/IR:L/AR:L/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "3711d004 4.8", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L/E:P/RL:X/RC:C/CR:L/IR:L/AR:M/MAV:A/MAC:H/MPR:N/MUI:X/MS:U/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "f5f73162 7.4", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N/E:F/RL:T/RC:R/CR:H/IR:L/AR:H/MAV:N/MAC:H/MPR:N/MUI:X/MS:X/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "5c9b83e0 7.3", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H/E:H/RL:W/RC:C/CR:M/IR:L/AR:X/MAV:N/MAC:X/MPR:N/MUI:N/MS:C/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "dc7196bb 2.6", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:L/E:X/RL:U/RC:R/CR:L/IR:X/AR:L/MAV:A/MAC:H/MPR:L/MUI:R/MS:X/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "c03bba5d 2.0", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:R/CR:M/IR:X/AR:M/MAV:P/MAC:X/MPR:L/MUI:N/MS:C/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "07b64a1e 6.0", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:L/E:U/RL:O/RC:U/CR:H/IR:M/AR:H/MAV:N/MAC:X/MPR:L/MUI:N/MS:X/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "c9f7d8d6 4.2", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:N/E:H/RL:X/RC:C/CR:H/IR:H/AR:M/MAV:N/MAC:H/MPR:N/MUI:X/MS:C/MC:X/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "e921e596 6.2", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:R/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:L/MUI:R/MS:U/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "dacf6792 6.8", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H/E:X/RL:W/RC:U/CR:X/IR:X/AR:M/MAV:L/MAC:X/MPR:X/MUI:R/MS:C/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "e46c928a 1.6", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N/E:F/RL:X/RC:U/CR:L/IR:L/AR:M/MAV:P/MAC:L/MPR:N/MUI:N/MS:C/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(3.1), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "c1dac5b9 4.4", // test name
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L/E:F/RL:X/RC:U/CR:X/IR:X/AR:X/MAV:P/MAC:X/MPR:H/MUI:R/MS:U/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(3.1), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "dc0b575b 6.4", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H/E:X/RL:T/RC:U/CR:H/IR:X/AR:X/MAV:P/MAC:X/MPR:H/MUI:N/MS:C/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(9.1), // exp base score
          temporal: Some(Score::from(8.1)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "f0698f68 4.6", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:H/E:X/RL:U/RC:X/CR:L/IR:H/AR:L/MAV:L/MAC:H/MPR:H/MUI:X/MS:X/MC:X/MI:N/MA:X", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(8.7)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "6b7ee371 3.3", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L/E:H/RL:O/RC:X/CR:L/IR:L/AR:L/MAV:A/MAC:X/MPR:H/MUI:R/MS:C/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(7.8)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "2357f54d 5.5", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N/E:X/RL:O/RC:U/CR:L/IR:M/AR:H/MAV:A/MAC:H/MPR:L/MUI:N/MS:C/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "42335ec5 1.3", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:N/E:H/RL:U/RC:R/CR:H/IR:X/AR:L/MAV:P/MAC:X/MPR:X/MUI:X/MS:C/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "18d120d6 0.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:L/E:U/RL:O/RC:U/CR:M/IR:H/AR:H/MAV:A/MAC:H/MPR:X/MUI:X/MS:C/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "12bff33c 6.6", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:U/RL:U/RC:R/CR:X/IR:L/AR:L/MAV:N/MAC:L/MPR:L/MUI:N/MS:U/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "fc4424fb 2.2", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L/E:F/RL:U/RC:C/CR:M/IR:L/AR:H/MAV:P/MAC:X/MPR:X/MUI:R/MS:U/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "d4e9f593 6.8", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:L/E:F/RL:T/RC:X/CR:M/IR:L/AR:L/MAV:N/MAC:X/MPR:L/MUI:R/MS:C/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "4f6a9be4 4.9", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:L/E:F/RL:X/RC:R/CR:M/IR:M/AR:L/MAV:L/MAC:H/MPR:L/MUI:R/MS:X/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "1c114a37 2.1", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:H/E:P/RL:T/RC:C/CR:L/IR:H/AR:X/MAV:L/MAC:H/MPR:N/MUI:N/MS:C/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "31d1e59e 5.7", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L/E:H/RL:T/RC:R/CR:L/IR:L/AR:M/MAV:A/MAC:L/MPR:H/MUI:R/MS:C/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "76effd2d 4.8", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N/E:U/RL:O/RC:C/CR:M/IR:X/AR:L/MAV:N/MAC:L/MPR:H/MUI:X/MS:C/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "e84d0a6f 6.6", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:L/E:P/RL:U/RC:X/CR:H/IR:H/AR:L/MAV:L/MAC:H/MPR:N/MUI:N/MS:X/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "c538a345 7.1", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N/E:F/RL:U/RC:C/CR:H/IR:L/AR:X/MAV:N/MAC:X/MPR:L/MUI:R/MS:C/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "eac85700 2.6", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L/E:F/RL:O/RC:X/CR:L/IR:H/AR:X/MAV:L/MAC:L/MPR:H/MUI:R/MS:C/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "65249fb9 6.3", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:N/A:H/E:U/RL:O/RC:C/CR:H/IR:L/AR:L/MAV:P/MAC:X/MPR:L/MUI:X/MS:C/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "5c139d45 4.2", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:N/E:F/RL:X/RC:C/CR:M/IR:M/AR:M/MAV:A/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "9ce9e74b 4.7", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:N/I:L/A:N/E:X/RL:T/RC:U/CR:X/IR:H/AR:M/MAV:P/MAC:X/MPR:X/MUI:N/MS:U/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "db8e90e7 3.2", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:N/I:N/A:L/E:X/RL:X/RC:U/CR:M/IR:H/AR:X/MAV:L/MAC:H/MPR:X/MUI:N/MS:X/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "c089a3bb 2.5", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H/E:P/RL:O/RC:X/CR:M/IR:X/AR:M/MAV:N/MAC:L/MPR:X/MUI:N/MS:U/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(2.5)), // exp environmental score
        }, // exp
      ), (
        "a72073d3 7.9", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:H/A:L/E:X/RL:T/RC:R/CR:H/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:X/MS:X/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "e5e5d473 6.5", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:L/E:F/RL:W/RC:C/CR:L/IR:L/AR:M/MAV:A/MAC:X/MPR:H/MUI:X/MS:C/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "1ea2fbfb 2.1", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:N/E:U/RL:U/RC:C/CR:M/IR:M/AR:H/MAV:P/MAC:L/MPR:N/MUI:X/MS:C/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "ec46bd3d 7.1", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:H/E:F/RL:O/RC:C/CR:X/IR:M/AR:H/MAV:X/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "f84b8e2d 6.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:H/A:N/E:F/RL:T/RC:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MPR:N/MUI:R/MS:C/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "f5c2b4fc 4.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:L/E:U/RL:U/RC:C/CR:X/IR:M/AR:L/MAV:P/MAC:X/MPR:L/MUI:N/MS:C/MC:L/MI:L/MA:X", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "5d5be887 6.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N/E:X/RL:W/RC:C/CR:H/IR:X/AR:M/MAV:X/MAC:L/MPR:X/MUI:R/MS:X/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(9.6), // exp base score
          temporal: Some(Score::from(9.4)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "a41cc3b8 5.9", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:H/E:F/RL:T/RC:R/CR:X/IR:L/AR:M/MAV:L/MAC:L/MPR:N/MUI:X/MS:U/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(9.9), // exp base score
          temporal: Some(Score::from(8.9)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "4a1cabaa 3.6", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L/E:F/RL:W/RC:C/CR:M/IR:M/AR:M/MAV:P/MAC:L/MPR:L/MUI:N/MS:X/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(9.1), // exp base score
          temporal: Some(Score::from(8.6)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "73909102 5.6", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:L/E:P/RL:T/RC:C/CR:M/IR:H/AR:L/MAV:P/MAC:L/MPR:X/MUI:X/MS:U/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "0cc74241 7.6", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:L/E:X/RL:X/RC:C/CR:M/IR:X/AR:H/MAV:L/MAC:H/MPR:N/MUI:X/MS:C/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "259ea1bf 7.2", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:H/RL:T/RC:X/CR:M/IR:H/AR:H/MAV:X/MAC:X/MPR:N/MUI:N/MS:U/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(8.8), // exp base score
          temporal: Some(Score::from(8.5)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "f41eb52a 6.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H/E:H/RL:T/RC:U/CR:L/IR:X/AR:H/MAV:N/MAC:L/MPR:H/MUI:N/MS:X/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "f78c132e 6.5", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/E:X/RL:T/RC:R/CR:X/IR:L/AR:L/MAV:P/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "c7ce3e19 6.3", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L/E:P/RL:U/RC:X/CR:X/IR:L/AR:H/MAV:L/MAC:X/MPR:H/MUI:N/MS:X/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "a6dba4dd 9.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:H/E:P/RL:O/RC:C/CR:M/IR:X/AR:L/MAV:X/MAC:L/MPR:N/MUI:N/MS:X/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(8.9), // exp base score
          temporal: Some(Score::from(8.0)), // exp temporal score
          environmental: Some(Score::from(9.0)), // exp environmental score
        }, // exp
      ), (
        "e6067f9f 3.6", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:H/E:P/RL:U/RC:U/CR:L/IR:X/AR:L/MAV:N/MAC:L/MPR:H/MUI:N/MS:U/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(8.9), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "e46e3907 5.4", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:H/E:X/RL:W/RC:X/CR:H/IR:L/AR:H/MAV:A/MAC:L/MPR:L/MUI:N/MS:C/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(8.0)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "f896607a 6.8", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:L/E:P/RL:U/RC:C/CR:M/IR:H/AR:M/MAV:P/MAC:X/MPR:L/MUI:R/MS:C/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "84f87e22 6.6", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:L/E:H/RL:X/RC:R/CR:L/IR:M/AR:M/MAV:X/MAC:L/MPR:X/MUI:R/MS:C/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "45c277e8 3.3", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:L/E:F/RL:W/RC:X/CR:H/IR:H/AR:L/MAV:L/MAC:X/MPR:X/MUI:R/MS:X/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "8860aea5 1.3", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N/E:X/RL:X/RC:R/CR:H/IR:H/AR:L/MAV:A/MAC:H/MPR:H/MUI:N/MS:X/MC:N/MI:N/MA:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "56b153c2 3.8", // test name
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:H/E:U/RL:U/RC:U/CR:H/IR:M/AR:X/MAV:P/MAC:L/MPR:H/MUI:R/MS:U/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "f77293ba 6.9", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:X/RC:R/CR:H/IR:X/AR:H/MAV:P/MAC:H/MPR:L/MUI:X/MS:X/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(10.0), // exp base score
          temporal: Some(Score::from(9.6)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "eb9af383 6.8", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/E:F/RL:T/RC:C/CR:H/IR:L/AR:M/MAV:N/MAC:L/MPR:L/MUI:R/MS:X/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(10.0), // exp base score
          temporal: Some(Score::from(9.4)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "4d2be82c 8.4", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H/E:H/RL:U/RC:R/CR:H/IR:M/AR:H/MAV:A/MAC:X/MPR:N/MUI:R/MS:X/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(10.0), // exp base score
          temporal: Some(Score::from(9.6)), // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "aacf81ab 7.9", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:L/E:H/RL:T/RC:R/CR:H/IR:L/AR:M/MAV:X/MAC:L/MPR:L/MUI:N/MS:U/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(9.9), // exp base score
          temporal: Some(Score::from(9.2)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "c0e26947 0.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L/E:U/RL:T/RC:X/CR:X/IR:H/AR:M/MAV:P/MAC:H/MPR:H/MUI:X/MS:U/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "99789742 8.5", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N/E:F/RL:O/RC:C/CR:X/IR:M/AR:M/MAV:L/MAC:L/MPR:X/MUI:X/MS:X/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(8.5)), // exp environmental score
        }, // exp
      ), (
        "11781943 6.7", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:H/E:P/RL:W/RC:U/CR:L/IR:H/AR:H/MAV:L/MAC:H/MPR:L/MUI:N/MS:X/MC:H/MI:N/MA:H", // vec
        Scores {
          base: Score::from(9.3), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "dbdab9ec 5.8", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H/E:P/RL:O/RC:C/CR:L/IR:M/AR:H/MAV:P/MAC:X/MPR:N/MUI:X/MS:U/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(8.6), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "516c4188 4.7", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/E:P/RL:W/RC:X/CR:L/IR:L/AR:X/MAV:N/MAC:H/MPR:N/MUI:N/MS:X/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(9.1), // exp base score
          temporal: Some(Score::from(8.3)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "61a16a05 4.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H/E:U/RL:T/RC:X/CR:L/IR:H/AR:X/MAV:N/MAC:L/MPR:H/MUI:R/MS:X/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(9.4), // exp base score
          temporal: Some(Score::from(8.3)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "ee5693a5 5.1", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:U/RL:O/RC:R/CR:M/IR:M/AR:L/MAV:L/MAC:L/MPR:N/MUI:R/MS:X/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "9e4036c7 7.5", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/E:X/RL:O/RC:C/CR:L/IR:H/AR:H/MAV:N/MAC:L/MPR:L/MUI:R/MS:X/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "2eb1489c 0.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:X/RL:U/RC:X/CR:L/IR:X/AR:H/MAV:X/MAC:H/MPR:X/MUI:N/MS:U/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "ad36c515 2.6", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:P/RL:O/RC:C/CR:L/IR:M/AR:H/MAV:P/MAC:H/MPR:H/MUI:X/MS:C/MC:N/MI:X/MA:X", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "73632813 9.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/E:H/RL:U/RC:R/CR:X/IR:X/AR:M/MAV:X/MAC:X/MPR:N/MUI:R/MS:C/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(9.6), // exp base score
          temporal: Some(Score::from(9.3)), // exp temporal score
          environmental: Some(Score::from(9.0)), // exp environmental score
        }, // exp
      ), (
        "d76e5cd5 8.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:H/E:H/RL:O/RC:X/CR:X/IR:X/AR:M/MAV:L/MAC:L/MPR:X/MUI:N/MS:X/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(9.6), // exp base score
          temporal: Some(Score::from(9.2)), // exp temporal score
          environmental: Some(Score::from(8.0)), // exp environmental score
        }, // exp
      ), (
        "840136be 5.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:H/E:H/RL:W/RC:U/CR:L/IR:H/AR:X/MAV:P/MAC:X/MPR:X/MUI:R/MS:X/MC:L/MI:N/MA:X", // vec
        Scores {
          base: Score::from(8.8), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "cdcfcc61 9.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:H/E:X/RL:X/RC:R/CR:L/IR:L/AR:M/MAV:X/MAC:L/MPR:X/MUI:N/MS:C/MC:X/MI:L/MA:H", // vec
        Scores {
          base: Score::from(8.8), // exp base score
          temporal: Some(Score::from(8.5)), // exp temporal score
          environmental: Some(Score::from(9.0)), // exp environmental score
        }, // exp
      ), (
        "3b3e5a97 7.3", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:L/E:F/RL:T/RC:C/CR:X/IR:X/AR:H/MAV:L/MAC:X/MPR:N/MUI:X/MS:U/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "379586c2 4.9", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:L/E:P/RL:T/RC:C/CR:X/IR:M/AR:X/MAV:N/MAC:H/MPR:H/MUI:X/MS:C/MC:N/MI:H/MA:N", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "e5f70396 8.1", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L/E:X/RL:U/RC:R/CR:X/IR:M/AR:H/MAV:L/MAC:X/MPR:N/MUI:N/MS:X/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "8bec3b34 3.9", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N/E:H/RL:U/RC:X/CR:L/IR:H/AR:L/MAV:A/MAC:L/MPR:H/MUI:N/MS:C/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "4b5e9c25 6.6", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H/E:F/RL:O/RC:X/CR:H/IR:M/AR:X/MAV:X/MAC:L/MPR:L/MUI:N/MS:X/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(8.1), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "f203f9b4 1.0", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L/E:U/RL:W/RC:C/CR:M/IR:H/AR:L/MAV:P/MAC:H/MPR:N/MUI:R/MS:X/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "8e5d16eb 3.5", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N/E:F/RL:X/RC:U/CR:H/IR:L/AR:H/MAV:A/MAC:L/MPR:X/MUI:X/MS:U/MC:N/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "91df7940 3.7", // test name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N/E:P/RL:O/RC:U/CR:H/IR:L/AR:H/MAV:P/MAC:H/MPR:X/MUI:R/MS:C/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "ebf5b034 2.9", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:L/E:H/RL:X/RC:X/CR:H/IR:M/AR:H/MAV:P/MAC:H/MPR:N/MUI:R/MS:X/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "70f1a11d 6.0", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:N/E:P/RL:U/RC:U/CR:H/IR:H/AR:L/MAV:X/MAC:X/MPR:X/MUI:R/MS:C/MC:X/MI:L/MA:X", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "b3c6e29c 5.7", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:L/I:H/A:H/E:X/RL:X/RC:R/CR:H/IR:H/AR:M/MAV:P/MAC:H/MPR:L/MUI:R/MS:C/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "9cf58a7a 5.9", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:L/I:N/A:N/E:F/RL:W/RC:C/CR:L/IR:X/AR:M/MAV:A/MAC:X/MPR:X/MUI:N/MS:C/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.8)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "c2c8dbbd 5.2", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:H/E:H/RL:T/RC:R/CR:M/IR:X/AR:X/MAV:P/MAC:H/MPR:L/MUI:X/MS:C/MC:H/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "abbb1814 7.4", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:N/E:F/RL:W/RC:C/CR:X/IR:H/AR:M/MAV:L/MAC:L/MPR:X/MUI:R/MS:X/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.8)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "f46dfce3 5.5", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:L/E:X/RL:T/RC:U/CR:X/IR:M/AR:H/MAV:A/MAC:L/MPR:X/MUI:X/MS:C/MC:N/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "06367982 4.7", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N/E:P/RL:U/RC:X/CR:H/IR:L/AR:H/MAV:X/MAC:H/MPR:N/MUI:N/MS:C/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "be39d874 5.3", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:L/E:U/RL:X/RC:U/CR:X/IR:L/AR:H/MAV:N/MAC:H/MPR:H/MUI:R/MS:X/MC:L/MI:L/MA:H", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "a4e675df 0.0", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:N/E:F/RL:U/RC:U/CR:H/IR:L/AR:L/MAV:X/MAC:L/MPR:N/MUI:R/MS:C/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "6cc16175 8.1", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:H/E:H/RL:X/RC:X/CR:M/IR:X/AR:H/MAV:N/MAC:X/MPR:N/MUI:N/MS:U/MC:L/MI:H/MA:X", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "2bd65db6 4.5", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:L/E:U/RL:O/RC:C/CR:L/IR:X/AR:L/MAV:L/MAC:L/MPR:X/MUI:R/MS:U/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "39a8d6ce 7.9", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:H/E:P/RL:O/RC:C/CR:X/IR:H/AR:X/MAV:N/MAC:L/MPR:L/MUI:N/MS:U/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "6ce3d444 6.9", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:L/E:H/RL:O/RC:C/CR:H/IR:X/AR:L/MAV:P/MAC:L/MPR:H/MUI:N/MS:C/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "625f598c 3.3", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:N/E:F/RL:W/RC:X/CR:X/IR:L/AR:X/MAV:L/MAC:L/MPR:X/MUI:R/MS:C/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "92582bf4 5.4", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:L/E:U/RL:X/RC:C/CR:M/IR:X/AR:M/MAV:P/MAC:X/MPR:L/MUI:N/MS:U/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "c71b5a64 6.3", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N/E:P/RL:U/RC:C/CR:L/IR:X/AR:L/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "c7bab9f6 4.7", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:L/E:F/RL:W/RC:R/CR:M/IR:M/AR:L/MAV:X/MAC:X/MPR:N/MUI:R/MS:C/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "d90143fb 6.7", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:H/A:H/E:U/RL:O/RC:C/CR:H/IR:L/AR:H/MAV:A/MAC:H/MPR:H/MUI:N/MS:C/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "1e1eeb3f 5.7", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:H/A:L/E:H/RL:W/RC:X/CR:M/IR:M/AR:L/MAV:P/MAC:L/MPR:X/MUI:R/MS:X/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "ecfa9369 5.5", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/E:H/RL:O/RC:U/CR:H/IR:X/AR:H/MAV:X/MAC:X/MPR:L/MUI:X/MS:U/MC:H/MI:L/MA:X", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "2879b5a7 6.3", // test name
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:X/RL:X/RC:R/CR:X/IR:M/AR:H/MAV:N/MAC:L/MPR:H/MUI:X/MS:X/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(1.6), // exp base score
          temporal: Some(Score::from(1.6)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "a1927a98 3.0", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N/E:P/RL:W/RC:C/CR:X/IR:X/AR:L/MAV:L/MAC:L/MPR:X/MUI:R/MS:C/MC:N/MI:L/MA:N", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "c2545690 4.9", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:H/E:U/RL:U/RC:R/CR:M/IR:H/AR:X/MAV:N/MAC:X/MPR:X/MUI:X/MS:X/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "0f29d945 8.1", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:H/E:P/RL:U/RC:X/CR:X/IR:H/AR:X/MAV:N/MAC:X/MPR:L/MUI:X/MS:X/MC:L/MI:H/MA:L", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "11f2e78a 5.8", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:H/E:F/RL:X/RC:C/CR:H/IR:X/AR:M/MAV:P/MAC:X/MPR:L/MUI:R/MS:U/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "32c0c605 3.9", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L/E:U/RL:W/RC:X/CR:H/IR:L/AR:L/MAV:P/MAC:L/MPR:L/MUI:X/MS:U/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "9ccb83e6 1.5", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L/E:X/RL:X/RC:U/CR:M/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:N/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "f4ad547d 5.3", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:N/E:F/RL:U/RC:X/CR:X/IR:M/AR:H/MAV:P/MAC:H/MPR:X/MUI:X/MS:U/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "56305f31 6.4", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:N/E:P/RL:X/RC:U/CR:H/IR:H/AR:H/MAV:L/MAC:L/MPR:L/MUI:X/MS:U/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "b8710a53 7.6", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N/E:F/RL:W/RC:X/CR:H/IR:H/AR:M/MAV:A/MAC:L/MPR:L/MUI:N/MS:U/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.8)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "d9000c72 4.2", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:C/C:N/I:N/A:H/E:P/RL:O/RC:X/CR:X/IR:L/AR:X/MAV:N/MAC:X/MPR:X/MUI:N/MS:U/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "2e021d3d 3.6", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L/E:H/RL:X/RC:U/CR:L/IR:X/AR:M/MAV:L/MAC:H/MPR:L/MUI:R/MS:C/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "16469b43 5.0", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L/E:P/RL:X/RC:X/CR:M/IR:X/AR:L/MAV:X/MAC:H/MPR:N/MUI:R/MS:X/MC:H/MI:L/MA:H", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "b5f716e4 5.6", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N/E:X/RL:X/RC:U/CR:H/IR:L/AR:M/MAV:L/MAC:X/MPR:N/MUI:N/MS:X/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "f9b34e72 6.7", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N/E:H/RL:O/RC:C/CR:H/IR:M/AR:L/MAV:P/MAC:X/MPR:X/MUI:X/MS:C/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(3.9), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "469cf1dd 6.4", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:H/E:F/RL:O/RC:X/CR:X/IR:H/AR:L/MAV:N/MAC:X/MPR:X/MUI:X/MS:U/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "1cb8d35d 4.6", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H/E:H/RL:X/RC:U/CR:L/IR:L/AR:L/MAV:L/MAC:X/MPR:N/MUI:X/MS:C/MC:X/MI:H/MA:X", // vec
        Scores {
          base: Score::from(3.9), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "1f3f46a4 2.2", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L/E:P/RL:X/RC:X/CR:X/IR:L/AR:M/MAV:P/MAC:H/MPR:H/MUI:X/MS:C/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.6)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "d0ed1aaa 5.6", // test name
        "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L/E:U/RL:O/RC:X/CR:L/IR:X/AR:M/MAV:L/MAC:X/MPR:N/MUI:X/MS:X/MC:L/MI:H/MA:H", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.5)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "4eed2301 0.9", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N/E:F/RL:T/RC:R/CR:L/IR:H/AR:H/MAV:P/MAC:L/MPR:H/MUI:X/MS:U/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(0.9)), // exp environmental score
        }, // exp
      ), (
        "3a744b55 7.2", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N/E:U/RL:X/RC:R/CR:X/IR:H/AR:M/MAV:L/MAC:H/MPR:N/MUI:N/MS:C/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "88cadced 5.2", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:H/E:P/RL:U/RC:X/CR:L/IR:X/AR:L/MAV:N/MAC:X/MPR:N/MUI:N/MS:U/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "561e6fd4 4.1", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:L/E:F/RL:T/RC:C/CR:L/IR:M/AR:M/MAV:L/MAC:L/MPR:N/MUI:X/MS:C/MC:X/MI:N/MA:X", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "a06d2154 0.0", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:H/RL:X/RC:C/CR:X/IR:L/AR:X/MAV:N/MAC:L/MPR:X/MUI:N/MS:C/MC:N/MI:N/MA:X", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "04bc662a 5.5", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:X/RL:X/RC:R/CR:M/IR:X/AR:M/MAV:P/MAC:L/MPR:H/MUI:X/MS:C/MC:N/MI:L/MA:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "f623de68 3.6", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L/E:P/RL:W/RC:U/CR:M/IR:X/AR:X/MAV:P/MAC:X/MPR:X/MUI:N/MS:U/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(3.1), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "5e8b985a 5.1", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L/E:F/RL:T/RC:R/CR:H/IR:H/AR:H/MAV:X/MAC:X/MPR:H/MUI:X/MS:X/MC:X/MI:H/MA:N", // vec
        Scores {
          base: Score::from(3.1), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "e0bcc092 2.9", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N/E:X/RL:W/RC:X/CR:H/IR:X/AR:L/MAV:X/MAC:X/MPR:L/MUI:N/MS:C/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(2.0), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "ca293bbe 2.2", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/E:P/RL:O/RC:R/CR:L/IR:H/AR:L/MAV:P/MAC:L/MPR:L/MUI:N/MS:U/MC:H/MI:X/MA:N", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "c82e8664 1.9", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:L/E:H/RL:X/RC:C/CR:L/IR:X/AR:L/MAV:L/MAC:H/MPR:L/MUI:N/MS:X/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "a3f8feb4 2.6", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:H/E:F/RL:U/RC:R/CR:H/IR:L/AR:X/MAV:X/MAC:H/MPR:H/MUI:R/MS:X/MC:L/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "14211e17 4.2", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N/E:H/RL:W/RC:C/CR:H/IR:L/AR:L/MAV:P/MAC:X/MPR:H/MUI:N/MS:C/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "0e84582f 3.1", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L/E:F/RL:T/RC:X/CR:X/IR:M/AR:X/MAV:X/MAC:X/MPR:L/MUI:R/MS:C/MC:X/MI:N/MA:X", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "54ee4602 4.2", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:L/E:H/RL:O/RC:R/CR:L/IR:M/AR:M/MAV:P/MAC:X/MPR:X/MUI:X/MS:X/MC:N/MI:X/MA:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "fa18bb92 5.8", // test name
        "CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N/E:P/RL:W/RC:C/CR:L/IR:M/AR:X/MAV:L/MAC:X/MPR:X/MUI:R/MS:C/MC:N/MI:H/MA:L", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "9924198d 6.2", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L/E:X/RL:U/RC:U/CR:X/IR:X/AR:L/MAV:X/MAC:H/MPR:X/MUI:X/MS:X/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "54f393bb 4.4", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:N/E:X/RL:W/RC:C/CR:X/IR:L/AR:L/MAV:A/MAC:L/MPR:X/MUI:X/MS:U/MC:H/MI:N/MA:N", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "465ce5ff 2.9", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N/E:F/RL:X/RC:R/CR:L/IR:L/AR:X/MAV:L/MAC:X/MPR:H/MUI:X/MS:C/MC:L/MI:L/MA:N", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "a18cdd99 1.8", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:H/E:P/RL:X/RC:C/CR:X/IR:L/AR:L/MAV:X/MAC:H/MPR:X/MUI:X/MS:C/MC:L/MI:X/MA:N", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "a94a0b06 3.7", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:H/E:U/RL:W/RC:R/CR:H/IR:L/AR:L/MAV:P/MAC:L/MPR:N/MUI:X/MS:U/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "4c18707a 2.7", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:N/E:X/RL:T/RC:R/CR:H/IR:H/AR:L/MAV:X/MAC:X/MPR:L/MUI:N/MS:X/MC:N/MI:N/MA:H", // vec
        Scores {
          base: Score::from(2.2), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "c0e3f066 7.2", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:F/RL:T/RC:X/CR:H/IR:L/AR:M/MAV:N/MAC:L/MPR:L/MUI:R/MS:U/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "89f9b493 3.7", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H/E:X/RL:O/RC:R/CR:H/IR:H/AR:L/MAV:L/MAC:X/MPR:L/MUI:R/MS:U/MC:L/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "657e8854 7.5", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:L/E:H/RL:W/RC:U/CR:L/IR:M/AR:M/MAV:N/MAC:X/MPR:N/MUI:R/MS:C/MC:H/MI:H/MA:N", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "c355b7b4 9.1", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:L/E:H/RL:U/RC:R/CR:H/IR:M/AR:H/MAV:L/MAC:X/MPR:N/MUI:X/MS:C/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(9.1)), // exp environmental score
        }, // exp
      ), (
        "1e0fcf72 4.0", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N/E:F/RL:X/RC:U/CR:X/IR:H/AR:M/MAV:A/MAC:H/MPR:H/MUI:N/MS:U/MC:L/MI:L/MA:L", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "0084e159 4.6", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H/E:U/RL:O/RC:U/CR:X/IR:X/AR:H/MAV:P/MAC:X/MPR:X/MUI:X/MS:C/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(3.9), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "a720fcb4 7.8", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N/E:F/RL:U/RC:X/CR:H/IR:L/AR:M/MAV:A/MAC:L/MPR:L/MUI:X/MS:U/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "52e22e66 6.6", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:L/E:F/RL:T/RC:R/CR:M/IR:X/AR:X/MAV:L/MAC:L/MPR:L/MUI:X/MS:C/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "b974bfbc 6.6", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:R/S:C/C:H/I:N/A:L/E:U/RL:U/RC:X/CR:X/IR:M/AR:H/MAV:X/MAC:X/MPR:N/MUI:X/MS:X/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "abe92956 5.0", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:N/E:U/RL:O/RC:X/CR:M/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:X/MS:C/MC:L/MI:X/MA:X", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "f0a24cb8 6.5", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:L/E:X/RL:W/RC:C/CR:M/IR:H/AR:H/MAV:N/MAC:L/MPR:H/MUI:X/MS:U/MC:L/MI:H/MA:N", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "846c91ff 7.5", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:L/E:H/RL:W/RC:U/CR:X/IR:H/AR:M/MAV:N/MAC:H/MPR:N/MUI:X/MS:X/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "7a5e8a7b 3.8", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:R/S:U/C:H/I:L/A:H/E:X/RL:O/RC:R/CR:X/IR:H/AR:X/MAV:A/MAC:X/MPR:L/MUI:R/MS:X/MC:L/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "fbd95411 2.5", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:R/S:U/C:H/I:L/A:N/E:P/RL:W/RC:C/CR:M/IR:L/AR:X/MAV:X/MAC:X/MPR:L/MUI:N/MS:X/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(2.5)), // exp environmental score
        }, // exp
      ), (
        "565dfceb 4.3", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:L/E:X/RL:O/RC:R/CR:H/IR:X/AR:L/MAV:A/MAC:X/MPR:N/MUI:N/MS:U/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "66a75517 2.2", // test name
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:N/E:U/RL:X/RC:U/CR:L/IR:M/AR:X/MAV:N/MAC:H/MPR:L/MUI:X/MS:U/MC:X/MI:X/MA:X", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.5)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "9e3a9c2f 5.7", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:H/E:U/RL:X/RC:X/CR:H/IR:L/AR:M/MAV:A/MAC:H/MPR:H/MUI:N/MS:U/MC:H/MI:N/MA:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "8094352b 7.2", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H/E:P/RL:U/RC:C/CR:H/IR:L/AR:L/MAV:X/MAC:X/MPR:N/MUI:N/MS:C/MC:X/MI:L/MA:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "e0a782a6 8.2", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N/E:X/RL:O/RC:U/CR:X/IR:H/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:X/MC:X/MI:N/MA:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(8.2)), // exp environmental score
        }, // exp
      ), (
        "2896cfb6 3.2", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N/E:U/RL:U/RC:R/CR:X/IR:X/AR:H/MAV:P/MAC:H/MPR:N/MUI:N/MS:X/MC:X/MI:L/MA:N", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "cab76651 2.2", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:L/E:H/RL:U/RC:U/CR:M/IR:M/AR:L/MAV:X/MAC:X/MPR:H/MUI:N/MS:U/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "8928adc4 8.9", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:H/RL:T/RC:U/CR:X/IR:M/AR:H/MAV:N/MAC:L/MPR:L/MUI:N/MS:C/MC:N/MI:X/MA:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(8.9)), // exp environmental score
        }, // exp
      ), (
        "4d4184ac 0.0", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:U/CR:X/IR:X/AR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:C/MC:N/MI:N/MA:N", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "0e4ea570 6.4", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H/E:F/RL:W/RC:U/CR:X/IR:L/AR:H/MAV:L/MAC:L/MPR:L/MUI:R/MS:X/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "7cd843b7 4.7", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H/E:H/RL:O/RC:R/CR:H/IR:L/AR:X/MAV:A/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:X", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "250ff7b2 5.7", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H/E:H/RL:O/RC:R/CR:H/IR:H/AR:X/MAV:X/MAC:L/MPR:H/MUI:X/MS:U/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "ee7c1e15 3.6", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L/E:U/RL:O/RC:C/CR:L/IR:L/AR:L/MAV:L/MAC:L/MPR:L/MUI:R/MS:X/MC:H/MI:X/MA:L", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "63e7f919 5.6", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L/E:P/RL:T/RC:X/CR:X/IR:L/AR:X/MAV:L/MAC:X/MPR:X/MUI:N/MS:X/MC:H/MI:X/MA:X", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "730a1306 6.8", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H/E:P/RL:X/RC:C/CR:M/IR:H/AR:H/MAV:N/MAC:X/MPR:H/MUI:N/MS:X/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "50dfb443 3.3", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L/E:H/RL:W/RC:R/CR:H/IR:L/AR:H/MAV:N/MAC:L/MPR:H/MUI:R/MS:U/MC:N/MI:L/MA:L", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "57d27ca9 6.4", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L/E:P/RL:W/RC:R/CR:L/IR:X/AR:X/MAV:N/MAC:L/MPR:H/MUI:R/MS:X/MC:X/MI:X/MA:N", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "acb4565f 7.7", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N/E:P/RL:T/RC:R/CR:M/IR:H/AR:L/MAV:N/MAC:X/MPR:N/MUI:R/MS:U/MC:H/MI:H/MA:X", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "94022a33 7.3", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N/E:F/RL:X/RC:U/CR:M/IR:M/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:X/MI:N/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "652a8fc4 6.3", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:N/E:X/RL:W/RC:X/CR:H/IR:X/AR:X/MAV:X/MAC:X/MPR:L/MUI:R/MS:U/MC:H/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "bd9f29db 7.2", // test name
        "CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:H/E:U/RL:X/RC:U/CR:X/IR:L/AR:H/MAV:N/MAC:X/MPR:L/MUI:N/MS:U/MC:X/MI:X/MA:H", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "6d000fd9 6.1", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H/E:F/RL:T/RC:X/CR:M/IR:L/AR:X/MAV:P/MAC:H/MPR:X/MUI:N/MS:X/MC:X/MI:H/MA:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "7b688398 7.3", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:H/E:H/RL:U/RC:U/CR:X/IR:H/AR:X/MAV:A/MAC:H/MPR:N/MUI:R/MS:X/MC:X/MI:H/MA:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "a5d51ee2 8.0", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L/E:H/RL:W/RC:U/CR:H/IR:H/AR:L/MAV:N/MAC:H/MPR:X/MUI:N/MS:C/MC:H/MI:N/MA:X", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(8.0)), // exp environmental score
        }, // exp
      ), (
        "295ace5b 4.7", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L/E:P/RL:T/RC:U/CR:L/IR:X/AR:M/MAV:X/MAC:L/MPR:X/MUI:R/MS:U/MC:H/MI:H/MA:L", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "20b69338 5.9", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P/RL:U/RC:C/CR:L/IR:X/AR:M/MAV:N/MAC:H/MPR:X/MUI:X/MS:U/MC:L/MI:N/MA:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "0dd93f14 4.6", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:U/RL:W/RC:X/CR:X/IR:L/AR:X/MAV:P/MAC:L/MPR:L/MUI:X/MS:X/MC:H/MI:L/MA:L", // vec
        Scores {
          base: Score::from(2.4), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "cfaba3ea 4.6", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H/E:H/RL:T/RC:C/CR:M/IR:M/AR:X/MAV:N/MAC:H/MPR:X/MUI:X/MS:X/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "15178b76 4.7", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H/E:U/RL:O/RC:X/CR:M/IR:X/AR:L/MAV:A/MAC:H/MPR:L/MUI:X/MS:U/MC:X/MI:L/MA:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "a517df88 3.3", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H/E:H/RL:W/RC:X/CR:X/IR:X/AR:L/MAV:X/MAC:H/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "ee33a2b9 5.2", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H/E:P/RL:O/RC:U/CR:L/IR:X/AR:H/MAV:L/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:X/MA:H", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "80537d5d 1.9", // test name
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N/E:P/RL:O/RC:U/CR:M/IR:L/AR:M/MAV:P/MAC:L/MPR:X/MUI:X/MS:C/MC:X/MI:N/MA:N", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(1.8)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
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
