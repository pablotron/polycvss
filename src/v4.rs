//! [CVSS v4][doc] parsing and scoring.
//!
//! # Examples
//!
//! Parse [CVSS v4][doc] [vector string][vector-string], then get a
//! [`Metric`][] by [`Name`][]:
//!
//! ```
//! # use polycvss::{Err, v4::{AttackVector, Vector, Metric, Name}};
//! # fn main() -> Result<(), Err> {
//! // parse vector string
//! let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
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
//! # use polycvss::{Err, v4::{Name, Vector}};
//! # fn main() -> Result<(), Err> {
//! // parse vector string
//! let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
//!
//! // get metric names
//! let names: Vec<Name> = v.into_iter().map(Name::from).collect();
//!
//! // check result
//! assert_eq!(names, vec!(
//!   Name::AttackVector,
//!   Name::AttackComplexity,
//!   Name::AttackRequirements,
//!   Name::PrivilegesRequired,
//!   Name::UserInteraction,
//!   Name::VulnerableSystemConfidentialityImpact,
//!   Name::VulnerableSystemIntegrityImpact,
//!   Name::VulnerableSystemAvailabilityImpact,
//!   Name::SubsequentSystemConfidentialityImpact,
//!   Name::SubsequentSystemIntegrityImpact,
//!   Name::SubsequentSystemAvailabilityImpact,
//! ));
//! # Ok(())
//! # }
//! ```
//!
//! Get score for [CVSS v4][doc] vector string:
//!
//! ```
//! # use polycvss::{Err, Score, v4::Vector};
//! # fn main() -> Result<(), Err> {
//! // parse vector string
//! let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N".parse()?;
//!
//! // get score
//! let score = Score::from(v);
//!
//! // check result
//! assert_eq!(score, Score::from(6.9));
//! # Ok(())
//! # }
//! ```
//!
//! [doc]: https://www.first.org/cvss/v4-0/specification-document
//!   "Common Vulnerability Scoring System (CVSS) version 4.0 Specification"
//! [vector-string]: https://www.first.org/cvss/v4-0/specification-document#Vector-String
//!   "CVSS v4.0 Specification, Section 7: Vector String"

#[cfg(feature="serde")]
use serde::{self,Deserialize,Serialize};
use super::{Err, Score, VAL_MASK, Version, encode::{EncodedVal, EncodedMetric}};

/// [`Metric::AttackVector`][] (`AV`) values.
///
/// # Description
///
/// This metric reflects the context by which vulnerability exploitation
/// is possible. This metric value (and consequently the resulting
/// severity) will be larger the more remote (logically, and physically)
/// an attacker can be in order to exploit the vulnerable system. The
/// assumption is that the number of potential attackers for a
/// vulnerability that could be exploited from across a network is larger
/// than the number of potential attackers that could exploit a
/// vulnerability requiring physical access to a device, and therefore
/// warrants a greater severity.
///
/// # Properties
///
/// - Metric Group: [Base Metrics][Group::Base]
/// - Documentation: [CVSS v4.0 Specification, Section 2.1.1: Attack Vector (`AV`)][doc]
///
/// # Examples
///
/// Parse string as metric and check it:
///
/// ```
/// # use polycvss::{Err, v4::{AttackVector, Metric}};
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
/// # use polycvss::v4::{AttackVector, Metric};
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
/// # use polycvss::v4::{AttackVector, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AttackVector(AttackVector::Local));
///
/// // check result
/// assert_eq!(name, Name::AttackVector);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Attack-Vector-AV
///   "CVSS v4.0 Specification, Section 2.1.1: Attack Vector (AV)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
#[repr(u8)]
pub enum AttackVector {
  /// Network (`N`)
  ///
  /// The vulnerable system is bound to the network stack and the set of
  /// possible attackers extends beyond the other options listed below, up
  /// to and including the entire Internet. Such a vulnerability is often
  /// termed “remotely exploitable” and can be thought of as an attack
  /// being exploitable at the protocol level one or more network hops
  /// away (e.g., across one or more routers). An example of a network
  /// attack is an attacker causing a denial of service (DoS) by sending a
  /// specially crafted TCP packet across a wide area network (e.g.,
  /// CVE-2004-0230).
  Network = 0,

  /// Adjacent (`A`)
  ///
  /// The vulnerable system is bound to a protocol stack, but the attack
  /// is limited at the protocol level to a logically adjacent topology.
  /// This can mean an attack must be launched from the same shared
  /// proximity (e.g., Bluetooth, NFC, or IEEE 802.11) or logical network
  /// (e.g., local IP subnet), or from within a secure or otherwise
  /// limited administrative domain (e.g., MPLS, secure VPN within an
  /// administrative network zone). One example of an Adjacent attack
  /// would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to
  /// a denial of service on the local LAN segment (e.g., CVE-2013-6014).
  Adjacent = 1,

  /// Local (`L`)
  ///
  /// The vulnerable system is not bound to the network stack and the
  /// attacker’s path is via read/write/execute capabilities. Either:
  ///
  /// - the attacker exploits the vulnerability by accessing the target
  ///   system locally (e.g., keyboard, console), or through terminal
  ///   emulation (e.g., SSH); or
  /// - the attacker relies on User Interaction by another person to
  ///   perform actions required to exploit the vulnerability (e.g.,
  ///   using social engineering techniques to trick a legitimate user
  ///   into opening a malicious document).
  Local = 2,

  /// Physical (`P`)
  ///
  /// The attack requires the attacker to physically touch or manipulate
  /// the vulnerable system. Physical interaction may be brief (e.g., evil
  /// maid attack) or persistent. An example of such an attack is a cold
  /// boot attack in which an attacker gains access to disk encryption
  /// keys after physically accessing the target system. Other examples
  /// include peripheral attacks via FireWire/USB Direct Memory Access
  /// (DMA).
  Physical = 3,
}

impl AttackVector {
  // Distance between this value and another one.
  //
  // Used in `Scores::from`.
  fn diff(self, other: Self) -> u8 {
    (self as u8).abs_diff(other as u8)
  }
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
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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
/// This metric captures measurable actions that must be taken by the
/// attacker to actively evade or circumvent existing built-in
/// security-enhancing conditions in order to obtain a working exploit.
/// These are conditions whose primary purpose is to increase security
/// and/or increase exploit engineering complexity. A vulnerability
/// exploitable without a target-specific variable has a lower complexity
/// than a vulnerability that would require non-trivial customization.
/// This metric is meant to capture security mechanisms utilized by the
/// vulnerable system, and does not relate to the amount of time or
/// attempts it would take for an attacker to succeed, e.g. a race
/// condition. If the attacker does not take action to overcome these
/// conditions, the attack will always fail.
///
/// The evasion or satisfaction of authentication mechanisms or
/// requisites is included in the Privileges Required assessment and is
/// not considered here as a factor of relevance for Attack Complexity.
///
/// # Properties
///
/// - Metric Group: [Base Metrics][Group::Base]
/// - Documentation: [CVSS v4.0 Specification, Section 2.1.2: Attack Complexity (`AC`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v4::{AttackComplexity, Metric}};
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
/// # use polycvss::v4::{AttackComplexity, Metric};
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
/// # use polycvss::v4::{AttackComplexity, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AttackComplexity(AttackComplexity::High));
///
/// // check result
/// assert_eq!(name, Name::AttackComplexity);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Attack-Complexity-AC
///   "CVSS v4.0 Specification, Section 2.1.2: Attack Complexity (AC)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
#[repr(u8)]
pub enum AttackComplexity {
  /// Low (`L`)
  ///
  ///The attacker must take no measurable action to exploit the
  /// vulnerability. The attack requires no target-specific circumvention
  /// to exploit the vulnerability. An attacker can expect repeatable
  /// success against the vulnerable system.
  Low = 0,

  /// High (`H`)
  ///
  /// The successful attack depends on the evasion or circumvention of
  /// security-enhancing techniques in place that would otherwise hinder
  /// the attack. These include:
  ///
  /// Evasion of exploit mitigation techniques. The attacker must have
  /// additional methods available to bypass security measures in place. For
  /// example, circumvention of address space randomization (ASLR) or data
  /// execution prevention (DEP) must be performed for the attack to be
  /// successful.
  ///
  /// Obtaining target-specific secrets. The attacker must gather some
  /// target-specific secret before the attack can be successful. A secret
  /// is any piece of information that cannot be obtained through any amount
  /// of reconnaissance. To obtain the secret the attacker must perform
  /// additional attacks or break otherwise secure measures (e.g. knowledge
  /// of a secret key may be needed to break a crypto channel). This
  /// operation must be performed for each attacked target.
  High = 1,
}

impl AttackComplexity {
  // Distance between this value and another one.
  //
  // Used in `Scores::from`.
  fn diff(self, other: Self) -> u8 {
    (self as u8).abs_diff(other as u8)
  }
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
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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

/// [`Metric::AttackRequirements`][] (`AT`) values.
///
/// # Description
///
/// This metric captures the prerequisite deployment and execution
/// conditions or variables of the vulnerable system that enable the
/// attack. These differ from security-enhancing techniques/technologies
/// (ref Attack Complexity) as the primary purpose of these conditions is
/// not to explicitly mitigate attacks, but rather, emerge naturally as a
/// consequence of the deployment and execution of the vulnerable system.
/// If the attacker does not take action to overcome these conditions, the
/// attack may succeed only occasionally or not succeed at all.
///
/// # Properties
///
/// - Metric Group: [Base Metrics][Group::Base]
/// - Base Metric Set: Exploitability Metrics
/// - Documentation: [CVSS v4.0 Specification, Section 2.1.3: Attack Requirements (`AT`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v4::{AttackRequirements, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "AT:N".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::AttackRequirements(AttackRequirements::None));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v4::{AttackRequirements, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::AttackRequirements(AttackRequirements::Present).to_string();
///
/// // check result
/// assert_eq!(s, "AT:P");
/// # }
/// ```
///
/// Get metric name
///
/// ```
/// # use polycvss::v4::{AttackRequirements, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AttackRequirements(AttackRequirements::None));
///
/// // check result
/// assert_eq!(name, Name::AttackRequirements);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Attack-Requirements-AT
///   "CVSS v4.0 Specification, Section 2.1.3: Attack Requirements (AT)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
#[repr(u8)]
pub enum AttackRequirements {
  /// None (`N`)
  ///
  /// The successful attack does not depend on the deployment and
  /// execution conditions of the vulnerable system. The attacker can
  /// expect to be able to reach the vulnerability and execute the exploit
  /// under all or most instances of the vulnerability.
  None = 0,

  /// Present (`P`)
  ///
  /// The successful attack depends on the presence of specific
  /// deployment and execution conditions of the vulnerable system that
  /// enable the attack. These include:
  ///
  /// A race condition must be won to successfully exploit the
  /// vulnerability. The successfulness of the attack is conditioned on
  /// execution conditions that are not under full control of the attacker.
  /// The attack may need to be launched multiple times against a single
  /// target before being successful.
  ///
  /// Network injection. The attacker must inject themselves into the
  /// logical network path between the target and the resource requested by
  /// the victim (e.g. vulnerabilities requiring an on-path attacker).
  Present = 1,
}

impl AttackRequirements {
  // Distance between this value and another one.
  //
  // Used in `Scores::from`.
  fn diff(self, other: Self) -> u8 {
    (self as u8).abs_diff(other as u8)
  }
}

/// [`Metric::ModifiedAttackRequirements`][] (`MAT`) values.
///
/// # Description
///
/// Metric value which overrides the base [`Metric::AttackRequirements`][]
/// (`AT`) metric value.
///
/// # Properties
///
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedAttackRequirements {
  /// Not Defined (`X`)
  NotDefined,

  /// None (`N`)
  ///
  /// See [`AttackRequirements::None`][].
  None,

  /// Present (`P`)
  ///
  /// See [`AttackRequirements::Present`][].
  Present,
}

/// [`Metric::PrivilegesRequired`][] (`PR`) values.
///
/// # Description
///
/// This metric describes the level of privileges an attacker must
/// possess prior to successfully exploiting the vulnerability. The method
/// by which the attacker obtains privileged credentials prior to the
/// attack (e.g., free trial accounts), is outside the scope of this
/// metric. Generally, self-service provisioned accounts do not constitute
/// a privilege requirement if the attacker can grant themselves
/// privileges as part of the attack.
///
/// The resulting score is greatest if no privileges are required.
///
/// # Properties
///
/// - Metric Group: [Base Metrics][Group::Base]
/// - Base Metric Set: Exploitability Metrics
/// - Documentation: [CVSS v4.0 Specification, Section 2.1.4: Privileges Required (`PR`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v4::{PrivilegesRequired, Metric}};
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
/// # use polycvss::v4::{PrivilegesRequired, Metric};
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
/// # use polycvss::v4::{PrivilegesRequired, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::PrivilegesRequired(PrivilegesRequired::High));
///
/// // check result
/// assert_eq!(name, Name::PrivilegesRequired);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Privileges-Required-PR
///   "CVSS v4.0 Specification, Section 2.1.4: Privileges Required (PR)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum PrivilegesRequired {
  /// None (`N`)
  ///
  /// The attacker is unauthenticated prior to attack, and therefore
  /// does not require any access to settings or files of the vulnerable
  /// system to carry out an attack.
  None = 0,

  /// Low (`L`)
  ///
  /// The attacker requires privileges that provide basic capabilities
  /// that are typically limited to settings and resources owned by a
  /// single low-privileged user. Alternatively, an attacker with Low
  /// privileges has the ability to access only non-sensitive resources.
  Low = 1,

  /// High (`H`)
  ///
  /// The attacker requires privileges that provide significant (e.g.,
  /// administrative) control over the vulnerable system allowing full
  /// access to the vulnerable system’s settings and files.
  High = 2,
}

impl PrivilegesRequired {
  // Distance between this value and another one.
  //
  // Used in `Scores::from`.
  fn diff(self, other: Self) -> u8 {
    (self as u8).abs_diff(other as u8)
  }
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
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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
/// vulnerable system. This metric determines whether the vulnerability
/// can be exploited solely at the will of the attacker, or whether a
/// separate user (or user-initiated process) must participate in some
/// manner. The resulting score is greatest when no user interaction is
/// required.
///
/// # Properties
///
/// - Metric Group: [Base Metrics][Group::Base]
/// - Base Metric Set: Exploitability Metrics
/// - Documentation: [CVSS v4.0 Specification, Section 2.1.5: User Interaction (`UI`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v4::{UserInteraction, Metric}};
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
/// # use polycvss::v4::{UserInteraction, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::UserInteraction(UserInteraction::Passive).to_string();
///
/// // check result
/// assert_eq!(s, "UI:P");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v4::{UserInteraction, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::UserInteraction(UserInteraction::Active));
///
/// // check result
/// assert_eq!(name, Name::UserInteraction);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#User-Interaction-UI
///   "CVSS v4.0 Specification, Section 2.1.5: User Interaction (UI)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
#[repr(u8)]
pub enum UserInteraction {
  /// None (`N`)
  ///
  /// The vulnerable system can be exploited without interaction from any human
  /// user, other than the attacker. Examples include: a remote attacker is able to
  /// send packets to a target system a locally authenticated attacker executes code
  /// to elevate privileges
  None = 0,

  /// Passive (`P`)
  ///
  /// Successful exploitation of this vulnerability requires limited
  /// interaction by the targeted user with the vulnerable system and the
  /// attacker’s payload. These interactions would be considered
  /// involuntary and do not require that the user actively subvert
  /// protections built into the vulnerable system. Examples include:
  ///
  /// utilizing a website that has been modified to display malicious
  /// content when the page is rendered (most stored XSS or CSRF)
  ///
  /// running an application that calls a malicious binary that has been
  /// planted on the system
  ///
  /// using an application which generates traffic over an untrusted or
  /// compromised network (vulnerabilities requiring an on-path attacker)
  Passive = 1,

  /// Active (`A`)
  ///
  /// Successful exploitation of this vulnerability requires a targeted
  /// user to perform specific, conscious interactions with the vulnerable
  /// system and the attacker’s payload, or the user’s interactions would
  /// actively subvert protection mechanisms which would lead to
  /// exploitation of the vulnerability. Examples include:
  ///
  /// importing a file into a vulnerable system in a specific manner
  ///
  /// placing files into a specific directory prior to executing code
  ///
  /// submitting a specific string into a web application (e.g. reflected
  /// or self XSS) dismiss or accept prompts or security warnings prior to
  /// taking an action (e.g. opening/editing a file, connecting a device).
  Active = 2,
}

impl UserInteraction {
  // Distance between this value and another one.
  //
  // Used in `Scores::from`.
  fn diff(self, other: Self) -> u8 {
    (self as u8).abs_diff(other as u8)
  }
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
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedUserInteraction {
  /// Not Defined (`X`)
  NotDefined,

  /// None (`N`)
  ///
  /// See [`UserInteraction::None`][].
  None,

  /// Passive (`P`)
  ///
  /// See [`UserInteraction::Passive`][].
  Passive,

  /// Active (`A`)
  ///
  /// See [`UserInteraction::Active`][].
  Active,
}

/// Impact metric (`VC`, `VI`, `VA`, `SC`, `SI`, `SA`) values.
///
/// # Description
///
/// Impact metrics:
///
/// - `VC`: [`Metric::VulnerableSystemConfidentialityImpact`][]
/// - `VI`: [`Metric::VulnerableSystemIntegrityImpact`][]
/// - `VA`: [`Metric::VulnerableSystemAvailabilityImpact`][]
/// - `SC`: [`Metric::SubsequentSystemConfidentialityImpact`][]
/// - `SI`: [`Metric::SubsequentSystemIntegrityImpact`][]
/// - `SA`: [`Metric::SubsequentSystemAvailabilityImpact`][]
///
/// # Properties
///
/// - Metric Group: [Base Metrics][Group::Base]
/// - Base Metric Set: Impact Metrics
/// - Documentation: [CVSS v4.0 Specification, Section 2.2: Impact Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Impact-Metrics
///   "CVSS v4.0 Specification, Section 2.2: Impact Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
#[repr(u8)]
pub enum Impact {
  /// High (`H`)
  ///
  /// | Metric | System | Effect | Description |
  /// | ------ | ------ | ------ | ----------- |
  /// | [`VC`][Metric::VulnerableSystemConfidentialityImpact] | Vulnerable | Confidentiality | There is a total loss of confidentiality, resulting in all information within the Vulnerable System being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server. |
  /// | [`SC`][Metric::SubsequentSystemConfidentialityImpact] | Subsequent | Confidentiality | There is a total loss of confidentiality, resulting in all resources within the Subsequent System being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server. |
  /// | [`VI`][Metric::VulnerableSystemIntegrityImpact] | Vulnerable | Integrity | There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the Vulnerable System. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the Vulnerable System. |
  /// | [`SI`][Metric::SubsequentSystemIntegrityImpact] | Subsequent | Integrity | There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the Subsequent System. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the Subsequent System. |
  /// | [`VA`][Metric::VulnerableSystemAvailabilityImpact] | Vulnerable | Availability | There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Vulnerable System; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Vulnerable System (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable). |
  /// | [`SA`][Metric::SubsequentSystemAvailabilityImpact] | Subsequent | Availability | There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Subsequent System; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Subsequent System (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable). |
  High = 0,

  /// Low (`L`)
  ///
  /// | Metric | System | Effect | Description |
  /// | ------ | ------ | ------ | ----------- |
  /// | [`VC`][Metric::VulnerableSystemConfidentialityImpact] | Vulnerable | Confidentiality | There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the Vulnerable System. |
  /// | [`SC`][Metric::SubsequentSystemConfidentialityImpact] | Subsequent | Confidentiality | There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the Subsequent System. |
  /// | [`VI`][Metric::VulnerableSystemIntegrityImpact] | Vulnerable | Integrity | Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Vulnerable System. |
  /// | [`SI`][Metric::SubsequentSystemIntegrityImpact] | Subsequent | Integrity | Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Subsequent System. |
  /// | [`VA`][Metric::VulnerableSystemAvailabilityImpact] | Vulnerable | Availability | Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the Vulnerable System are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Vulnerable System. |
  /// | [`SA`][Metric::SubsequentSystemAvailabilityImpact] | Subsequent | Availability | Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the Subsequent System are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Subsequent System. |
  Low = 1,

  /// None (`N`)
  ///
  /// | Metric | System | Effect | Description |
  /// | ------ | ------ | ------ | ----------- |
  /// | [`VC`][Metric::VulnerableSystemConfidentialityImpact] | Vulnerable | Confidentiality | There is no loss of confidentiality within the Vulnerable System. |
  /// | [`SC`][Metric::SubsequentSystemConfidentialityImpact] | Subsequent | Confidentiality | There is no loss of confidentiality within the Subsequent System or all confidentiality impact is constrained to the Vulnerable System. |
  /// | [`VI`][Metric::VulnerableSystemIntegrityImpact] | Vulnerable | Integrity | There is no loss of integrity within the Vulnerable System. |
  /// | [`SI`][Metric::SubsequentSystemIntegrityImpact] | Subsequent | Integrity | There is no loss of integrity within the Subsequent System or all integrity impact is constrained to the Vulnerable System. |
  /// | [`VA`][Metric::VulnerableSystemAvailabilityImpact] | Vulnerable | Availability | There is no impact to availability within the Vulnerable System. |
  /// | [`SA`][Metric::SubsequentSystemAvailabilityImpact] | Subsequent | Availability | There is no impact to availability within the Subsequent System or all availability impact is constrained to the Vulnerable System. |
  None = 2,
}

impl Impact {
  // Distance between this value and another one.
  //
  // Used in `Scores::from`.
  fn diff(self, other: Self) -> u8 {
    (self as u8).abs_diff(other as u8)
  }
}

/// Modified Impact metric (`MVC`, `MVI`, `MVA`, `MSC`) values.
///
/// # Description
///
/// Modified Impact metrics:
///
/// - `MVC`: [`Metric::ModifiedVulnerableSystemConfidentiality`][]
/// - `MVI`: [`Metric::ModifiedVulnerableSystemIntegrity`][]
/// - `MVA`: [`Metric::ModifiedVulnerableSystemAvailability`][]
/// - `MSC`: [`Metric::ModifiedSubsequentSystemConfidentiality`][]
///
/// # Properties
///
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedImpact {
  /// Not Defined (`X`)
  NotDefined,

  /// High (`H`)
  ///
  /// See [`Impact::High`][].
  High,

  /// Low (`L`)
  ///
  /// See [`Impact::Low`][].
  Low,

  /// None (`N`)
  ///
  /// See [`Impact::None`][].
  None,
}

/// Subsequent Impact values.
///
/// # Description
///
/// Used for `si` and `sa` fields of [`Values`][] struct.  Excludes `Not
/// Defined (X)` and includes `Safety (S)`.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u8)]
enum SubsequentImpact {
  /// None (`N`)
  ///
  /// See [`Impact::None`][].
  None = 0,

  /// Low (`L`)
  ///
  /// See [`Impact::Low`][].
  Low = 1,

  /// High (`H`)
  ///
  /// See [`Impact::High`][].
  High = 2,

  /// Safety (`S`)
  Safety = 3,
}

impl SubsequentImpact {
  // Distance between this value and another one.
  //
  // Used in `Scores::from`.
  fn diff(self, other: Self) -> u8 {
    (self as u8).abs_diff(other as u8)
  }
}

/// Modified Subsequent Impact metric (`MSI`, `MSA`) values.
///
/// # Description
///
/// Modified Subsequent Impact metrics:
///
/// - `MSI`: [`Metric::ModifiedSubsequentSystemIntegrity`][]
/// - `MSA`: [`Metric::ModifiedSubsequentSystemAvailability`][]
///
/// # Properties
///
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ModifiedSubsequentImpact {
  /// Not Defined (`X`)
  NotDefined,

  /// High (`H`)
  ///
  /// See [`Impact::High`][].
  High,

  /// Low (`L`)
  ///
  /// See [`Impact::Low`][].
  Low,

  /// None (`N`)
  ///
  /// See [`Impact::None`][].
  None,

  /// Safety (`S`)
  ///
  /// The Safety metric value measures the impact regarding the Safety
  /// of a human actor or participant that can be predictably injured as a
  /// result of the vulnerability being exploited. Unlike other impact
  /// metric values, Safety can only be associated with the Subsequent
  /// System impact set and should be considered in addition to the N/L/H
  /// impact values for Availability and Integrity metrics.
  Safety,
}

/// [`Metric::ExploitMaturity`][] (`E`) values.
///
/// # Description
///
/// This metric measures the likelihood of the vulnerability being
/// attacked, and is based on the current state of exploit techniques,
/// exploit code availability, or active, “in-the-wild” exploitation.
/// Public availability of easy-to-use exploit code or exploitation
/// instructions increases the number of potential attackers by including
/// those who are unskilled. Initially, real-world exploitation may only
/// be theoretical. Publication of proof-of-concept exploit code,
/// functional exploit code, or sufficient technical details necessary to
/// exploit the vulnerability may follow. Furthermore, the available
/// exploit code or instructions may progress from a proof-of-concept
/// demonstration to exploit code that is successful in exploiting the
/// vulnerability consistently. In severe cases, it may be delivered as
/// the payload of a network-based worm or virus or other automated attack
/// tools.
///
/// It is the responsibility of the CVSS consumer to populate the values
/// of Exploit Maturity (`E`) based on information regarding the
/// availability of exploitation code/processes and the state of
/// exploitation techniques. This information will be referred to as
/// “threat intelligence” throughout this document.
///
/// Operational Recommendation: Threat intelligence sources that provide
/// Exploit Maturity information for all vulnerabilities should be
/// preferred over those with only partial coverage. Also, it is
/// recommended to use multiple sources of threat intelligence as many are
/// not comprehensive. This information should be updated as frequently as
/// possible and its application to CVSS assessment should be automated.
///
/// # Properties
///
/// - Metric Group: [Threat Metrics][Group::Threat]
/// - Documentation: [CVSS v4.0 Specification, Section 3.1: Exploit Maturity (`E`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v4::{ExploitMaturity, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "E:A".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::ExploitMaturity(ExploitMaturity::Attacked));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v4::{ExploitMaturity, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::ExploitMaturity(ExploitMaturity::ProofOfConcept).to_string();
///
/// // check result
/// assert_eq!(s, "E:P");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v4::{ExploitMaturity, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::ExploitMaturity(ExploitMaturity::Unreported));
///
/// // check result
/// assert_eq!(name, Name::ExploitMaturity);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Exploit-Maturity-E
///   "CVSS v4.0 Specification, Section 3.1: Exploit Maturity (E)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
#[repr(u8)]
pub enum ExploitMaturity {
  /// Not Defined (`X`)
  ///
  /// Reliable threat intelligence is not available to determine Exploit
  /// Maturity characteristics. This is the default value and is
  /// equivalent to Attacked (`A`) for the purposes of the calculation of
  /// the score by assuming the worst case.
  NotDefined = 0,

  /// Attacked (`A`)
  ///
  /// Based on available threat intelligence either of the following must apply:
  ///
  /// - Attacks targeting this vulnerability (attempted or successful)
  ///   have been reported
  /// - Solutions to simplify attempts to exploit the vulnerability are
  ///   publicly or privately available (such as exploit toolkits)
  Attacked = 1,

  /// Proof-of-Concept (`P`)
  ///
  /// Based on available threat intelligence each of the following must apply:
  ///
  /// - Proof-of-concept exploit code is publicly available
  /// - No knowledge of reported attempts to exploit this vulnerability
  /// - No knowledge of publicly available solutions used to simplify
  ///   attempts to exploit the vulnerability (i.e., the “Attacked” value
  ///   does not apply)
  ProofOfConcept = 2,

  /// Unreported (`U`)
  ///
  /// Based on available threat intelligence each of the following must apply:
  ///
  /// - No knowledge of publicly available proof-of-concept exploit code
  /// - No knowledge of reported attempts to exploit this vulnerability
  /// - No knowledge of publicly available solutions used to simplify
  ///   attempts to exploit the vulnerability (i.e., neither the “POC” nor
  ///   “Attacked” values apply)
  Unreported = 3,
}

impl ExploitMaturity {
  // Get ordinal value.
  //
  // Used because E=X is treated as E=A for severity distance
  // calculation.
  fn ordinal(self) -> u8 {
    (match self {
      ExploitMaturity::NotDefined => ExploitMaturity::Attacked,
      _ => self,
    }) as u8
  }

  // Distance between this value and another one.
  //
  // Used in `Scores::from`.
  fn diff(self, other: Self) -> u8 {
    self.ordinal().abs_diff(other.ordinal())
  }
}

/// Requirement metric (`CR`, `IR`, `AR`) values.
///
/// # Description
///
/// These metrics enable the consumer to customize the assessment
/// depending on the importance of the affected IT asset to the analyst’s
/// organization, measured in terms of Confidentiality, Integrity, and
/// Availability. That is, if an IT asset supports a business function for
/// which Availability is most important, the analyst can assign a greater
/// value to Availability metrics relative to Confidentiality and
/// Integrity. Each Security Requirement has three possible values: Low,
/// Medium, or High, or the default value of Not Defined (`X`).
///
/// The full effect on the environmental score is determined by the
/// corresponding Modified Base Impact metrics. Following the concept of
/// assuming “reasonable worst case”, in absence of explicit values, these
/// metrics are set to the default value of Not Defined (`X`), which is
/// equivalent to the metric value of High (`H`).
///
/// # Metrics
///
/// - `CR`: [`Metric::ConfidentialityRequirement`][]
/// - `IR`: [`Metric::IntegrityRequirement`][]
/// - `AR`: [`Metric::AvailabilityRequirement`][]
///
/// # Properties
///
/// - Metric Group: [Environmental Metrics][Group::Environmental]
/// - Documentation: [CVSS v4.0 Specification, Section 4.1: Confidentiality, Integrity, and Availability Requirements (CR, IR, AR)][doc]
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Confidentiality-Integrity-and-Availability-Requirements-CR-IR-AR
///   "CVSS v4.0 Specification, Section 4.1: Confidentiality, Integrity, and Availability Requirements (CR, IR, AR)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
#[repr(u8)]
pub enum Requirement {
  /// Not Defined (`X`)
  ///
  /// This is the default value. Assigning this value indicates there is
  /// insufficient information to choose one of the other values. This has
  /// the same effect as assigning High as the worst case.
  NotDefined = 0,

  /// High (`H`)
  ///
  /// Loss of [Confidentiality | Integrity | Availability] is likely to
  /// have a catastrophic adverse effect on the organization or
  /// individuals associated with the organization (e.g., employees,
  /// customers).
  High = 1,

  /// Medium (`M`)
  ///
  /// Loss of [Confidentiality | Integrity | Availability] is likely to
  /// have a serious adverse effect on the organization or individuals
  /// associated with the organization (e.g., employees, customers).
  Medium = 2,

  /// Low (`L`)
  ///
  /// Loss of [Confidentiality | Integrity | Availability] is likely to
  /// have only a limited adverse effect on the organization or
  /// individuals associated with the organization (e.g., employees,
  /// customers).
  Low = 3,
}

impl Requirement {
  // Get ordinal position.
  //
  // Used because NotDefined is treated as High for severity distance
  // calculation.
  fn ordinal(self) -> u8 {
    (match self {
      Requirement::NotDefined => Requirement::High,
      _ => self,
    }) as u8
  }

  // Distance between this value and another one.
  //
  // Used in `Scores::from`.
  fn diff(self, other: Self) -> u8 {
    self.ordinal().abs_diff(other.ordinal())
  }
}

/// [`Metric::Safety`][] (`S`) values.
///
/// # Description
///
/// The Safety supplemental metric value indicates the degree of impact
/// to the Safety of a human actor or participant that can be predictably
/// injured as a result of the vulnerability being exploited.
///
/// Note that Safety metrics are defined in both Environmental and
/// Supplemental contexts, although the vector string values differ. As a
/// Supplemental metric, and consistent with the IEC 61508 Definitions
/// table below, Safety can be described with metric values of `S:X`,
/// `S:P`, or `S:N`.
///
/// # Properties
///
/// - Metric Group: [Supplemental Metrics][Group::Supplemental]
/// - Documentation: [CVSS v4.0 Specification, Section 5.1: Safety (`S`)][doc]
///
/// ## IEC 61508 Definitions
///
/// | Category     | Definition                            |
/// |--------------|---------------------------------------|
/// | Catastrophic | Multiple loss of life                 |
/// | Critical     | Loss of a single life                 |
/// | Marginal     | Major injuries to one or more persons |
/// | Negligible   | Minor injuries at worst               |
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v4::{Safety, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "S:P".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::Safety(Safety::Present));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v4::{Safety, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::Safety(Safety::Negligible).to_string();
///
/// // check result
/// assert_eq!(s, "S:N");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v4::{Safety, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::Safety(Safety::NotDefined));
///
/// // check result
/// assert_eq!(name, Name::Safety);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Safety-S
///   "CVSS v4.0 Specification, Section 5.1: Safety (S)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum Safety {
  /// Not Defined (`X`)
  ///
  /// The metric has not been evaluated.
  NotDefined,

  /// Present (`P`)
  ///
  /// Consequences of the vulnerability meet definition of IEC 61508
  /// consequence categories of "marginal," "critical," or "catastrophic."
  Present,

  /// Negligible (`N`)
  ///
  /// Consequences of the vulnerability meet definition of IEC 61508
  /// consequence category "negligible."
  Negligible,
}

/// [`Metric::Automatable`][] (`AU`) values.
///
/// # Description
///
/// The “Automatable” metric captures the answer to the question ”Can an
/// attacker automate exploitation events for this vulnerability across
/// multiple targets?” based on steps 1-4 of the kill chain2 [Hutchins et
/// al., 2011]. These steps are reconnaissance, weaponization, delivery,
/// and exploitation. If evaluated, the metric can take the values no or
/// yes.
///
/// # Properties
///
/// - Metric Group: [Supplemental Metrics][Group::Supplemental]
/// - Documentation: [CVSS v4.0 Specification, Section 5.2: Automatable (`AU`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v4::{Automatable, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "AU:N".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::Automatable(Automatable::No));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v4::{Automatable, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::Automatable(Automatable::Yes).to_string();
///
/// // check result
/// assert_eq!(s, "AU:Y");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v4::{Automatable, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::Automatable(Automatable::NotDefined));
///
/// // check result
/// assert_eq!(name, Name::Automatable);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Automatable-AU
///   "CVSS v4.0 Specification, Section 5.2: Automatable (AU)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum Automatable {
  /// Not Defined (`X`)
  ///
  /// The metric has not been evaluated.
  NotDefined,

  /// No (`N`)
  ///
  /// Attackers cannot reliably automate all 4 steps of the kill chain
  /// for this vulnerability for some reason. These steps are
  /// reconnaissance, weaponization, delivery, and exploitation.
  No,

  /// Yes (`Y`)
  ///
  /// Attackers can reliably automate all 4 steps of the kill chain.
  /// These steps are reconnaissance, weaponization, delivery, and
  /// exploitation (e.g., the vulnerability is “wormable”).
  Yes,
}

/// [`Metric::Recovery`][] (`R`) values.
///
/// # Description
///
/// Recovery describes the resilience of a system to recover services,
/// in terms of performance and availability, after an attack has been
/// performed.
///
/// # Properties
///
/// - Metric Group: [Supplemental Metrics][Group::Supplemental]
/// - Documentation: [CVSS v4.0 Specification, Section 5.4: Recovery (`R`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v4::{Recovery, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "R:A".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::Recovery(Recovery::Automatic));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v4::{Recovery, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::Recovery(Recovery::User).to_string();
///
/// // check result
/// assert_eq!(s, "R:U");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v4::{Recovery, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::Recovery(Recovery::Irrecoverable));
///
/// // check result
/// assert_eq!(name, Name::Recovery);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Recovery-R
///   "CVSS v4.0 Specification, Section 5.4: Recovery (R)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum Recovery {
  /// Not Defined (`X`)
  ///
  /// The metric has not been evaluated.
  NotDefined,

  /// Automatic (`A`)
  ///
  /// The system recovers services automatically after an attack has been performed.
  Automatic,

  /// User (`U`)
  ///
  /// The system requires manual intervention by the user to recover
  /// services, after an attack has been performed.
  User,

  /// Irrecoverable (`I`)
  ///
  /// The system services are irrecoverable by the user, after an attack
  /// has been performed.
  Irrecoverable,
}

/// [`Metric::ValueDensity`][] (`V`) values.
///
/// # Description
///
/// Value Density describes the resources that the attacker will gain
/// control over with a single exploitation event. It has two possible
/// values, diffuse and concentrated:
///
/// # Properties
///
/// - Metric Group: [Supplemental Metrics][Group::Supplemental]
/// - Documentation: [CVSS v4.0 Specification, Section 5.5: Value Density (`V`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v4::{ValueDensity, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "V:D".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::ValueDensity(ValueDensity::Diffuse));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v4::{ValueDensity, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::ValueDensity(ValueDensity::Concentrated).to_string();
///
/// // check result
/// assert_eq!(s, "V:C");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v4::{ValueDensity, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::ValueDensity(ValueDensity::NotDefined));
///
/// // check result
/// assert_eq!(name, Name::ValueDensity);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Value-Density-V
///   "CVSS v4.0 Specification, Section 5.5: Value Density (V)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ValueDensity {
  /// Not Defined (`X`)
  ///
  /// The metric has not been evaluated.
  NotDefined,

  /// Diffuse (`D`)
  ///
  /// The vulnerable system has limited resources. That is, the
  /// resources that the attacker will gain control over with a single
  /// exploitation event are relatively small. An example of Diffuse
  /// (think: limited) Value Density would be an attack on a single email
  /// client vulnerability.
  Diffuse,

  /// Concentrated (`C`)
  ///
  /// The vulnerable system is rich in resources. Heuristically, such
  /// systems are often the direct responsibility of “system operators”
  /// rather than users. An example of Concentrated (think: broad) Value
  /// Density would be an attack on a central email server.
  Concentrated,
}

/// [`Metric::VulnerabilityResponseEffort`][] (`RE`) values.
///
/// # Description
///
/// The intention of the Vulnerability Response Effort metric is to
/// provide supplemental information on how difficult it is for consumers
/// to provide an initial response to the impact of vulnerabilities for
/// deployed products and services in their infrastructure. The consumer
/// can then take this additional information on effort required into
/// consideration when applying mitigations and/or scheduling remediation.
///
/// When calculating Vulnerability Response Effort, the effort required
/// to deploy the quickest available response should be considered.
///
/// # Properties
///
/// - Metric Group: [Supplemental Metrics][Group::Supplemental]
/// - Documentation: [CVSS v4.0 Specification, Section 5.6: Vulnerability Response Effort (`RE`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v4::{VulnerabilityResponseEffort, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "RE:L".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Low));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v4::{VulnerabilityResponseEffort, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Moderate).to_string();
///
/// // check result
/// assert_eq!(s, "RE:M");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v4::{VulnerabilityResponseEffort, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::NotDefined));
///
/// // check result
/// assert_eq!(name, Name::VulnerabilityResponseEffort);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Vulnerability-Response-Effort-RE
///   "CVSS v4.0 Specification, Section 5.6: Vulnerability Response Effort (RE)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum VulnerabilityResponseEffort {
  /// Not Defined (`X`)
  ///
  /// The metric has not been evaluated.
  NotDefined,

  /// Low (`L`)
  ///
  /// The effort required to respond to a vulnerability is low/trivial.
  /// Examples include: communication on better documentation,
  /// configuration workarounds, or guidance from the vendor that does not
  /// require an immediate update, upgrade, or replacement by the
  /// consuming entity, such as firewall filter configuration.
  Low,

  /// Moderate (`M`)
  ///
  /// The actions required to respond to a vulnerability require some
  /// effort on behalf of the consumer and could cause minimal service
  /// impact to implement. Examples include: simple remote update,
  /// disabling of a subsystem, or a low-touch software upgrade such as a
  /// driver update.
  Moderate,

  /// High (`H`)
  ///
  /// The actions required to respond to a vulnerability are significant
  /// and/or difficult, and may possibly lead to an extended, scheduled
  /// service impact. This would need to be considered for scheduling
  /// purposes including honoring any embargo on deployment of the
  /// selected response. Alternatively, response to the vulnerability in
  /// the field is not possible remotely. The only resolution to the
  /// vulnerability involves physical replacement (e.g. units deployed
  /// would have to be recalled for a depot level repair or replacement).
  /// Examples include: a highly privileged driver update, microcode or
  /// UEFI BIOS updates, or software upgrades requiring careful analysis
  /// and understanding of any potential infrastructure impact before
  /// implementation. A UEFI BIOS update that impacts Trusted Platform
  /// Module (TPM) attestation without impacting disk encryption software
  /// such as Bit locker is a good recent example. Irreparable failures
  /// such as non-bootable flash subsystems, failed disks or solid-state
  /// drives (SSD), bad memory modules, network devices, or other
  /// non-recoverable under warranty hardware, should also be scored as
  /// having a High effort.
  High,
}

/// [`Metric::ProviderUrgency`][] (`U`) values.
///
/// # Description
///
/// Many vendors currently provide supplemental severity ratings to
/// consumers via product security advisories. Other vendors publish
/// Qualitative Severity Ratings from the CVSS Specification Document in
/// their advisories.
///
/// To facilitate a standardized method to incorporate additional
/// provider-supplied assessment, an optional “pass-through” Supplemental
/// Metric called Provider Urgency is available.
///
/// Note: While any assessment provider along the product supply chain
/// may provide a Provider Urgency rating:
///
/// Library Maintainer → OS/Distro Maintainer → Provider 1 … Provider n
/// (PPP) → Consumer
///
/// The Penultimate Product Provider (PPP) is best positioned to provide
/// a direct assessment of Provider Urgency.
///
/// # Properties
///
/// - Metric Group: [Supplemental Metrics][Group::Supplemental]
/// - Documentation: [CVSS v4.0 Specification, Section 5.3: Provider Urgency (`U`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v4::{ProviderUrgency, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "U:Red".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::ProviderUrgency(ProviderUrgency::Red));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v4::{ProviderUrgency, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::ProviderUrgency(ProviderUrgency::Amber).to_string();
///
/// // check result
/// assert_eq!(s, "U:Amber");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v4::{ProviderUrgency, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::ProviderUrgency(ProviderUrgency::NotDefined));
///
/// // check result
/// assert_eq!(name, Name::ProviderUrgency);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Provider-Urgency-U
///   "CVSS v4.0 Specification, Section 5.3: Provider Urgency (U)"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ProviderUrgency {
  /// Not Defined (`X`)
  ///
  /// The metric has not been evaluated.
  NotDefined,

  /// Red
  ///
  /// Provider has assessed the impact of this vulnerability as having
  /// the highest urgency.
  Red,

  /// Amber
  ///
  /// Provider has assessed the impact of this vulnerability as having a
  /// moderate urgency.
  Amber,

  /// Green
  ///
  /// Provider has assessed the impact of this vulnerability as having a
  /// reduced urgency.
  Green,

  /// Clear
  ///
  /// Provider has assessed the impact of this vulnerability as having
  /// no urgency (Informational).
  Clear,
}

/// [`Metric`][] group.
///
/// See [CVSS v4.0 Specification, Section 1.1: Metrics][doc].
///
/// # Example
///
/// Get metric group:
///
/// ```
/// # use polycvss::v4::{Group, Name};
/// # fn main() {
/// // get group
/// let group = Group::from(Name::AttackVector);
///
/// // check result
/// assert_eq!(group, Group::Base);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Metrics
///   "CVSS v4.0 Specification, Section 1.1: Metrics"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
pub enum Group {
  /// Base metrics.
  ///
  /// # Metrics
  ///
  /// - [`Metric::AttackVector`] (`AV`)
  /// - [`Metric::AttackComplexity`] (`AC`)
  /// - [`Metric::AttackRequirements`] (`AT`)
  /// - [`Metric::PrivilegesRequired`] (`PR`)
  /// - [`Metric::UserInteraction`] (`UI`)
  /// - [`Metric::VulnerableSystemConfidentialityImpact`] (`VC`)
  /// - [`Metric::VulnerableSystemIntegrityImpact`] (`VI`)
  /// - [`Metric::VulnerableSystemAvailabilityImpact`] (`VA`)
  /// - [`Metric::SubsequentSystemConfidentialityImpact`] (`SC`)
  /// - [`Metric::SubsequentSystemIntegrityImpact`] (`SI`)
  /// - [`Metric::SubsequentSystemAvailabilityImpact`] (`SA`)
  Base,

  /// Threat metrics.
  ///
  /// # Description
  ///
  /// The Threat metrics measure the current state of exploit techniques
  /// or code availability for a vulnerability.
  ///
  /// # Metrics
  ///
  /// - [`Metric::ExploitMaturity`] (`E`)
  Threat,

  /// Environmental metrics.
  ///
  /// # Description
  ///
  /// These metrics enable the consumer analyst to customize the
  /// resulting score depending on the importance of the affected IT asset
  /// to a user’s organization, measured in terms of
  /// complementary/alternative security controls in place,
  /// Confidentiality, Integrity, and Availability. The metrics are the
  /// modified equivalent of Base metrics and are assigned values based on
  /// the system placement within organizational infrastructure.
  ///
  /// # Metrics
  ///
  /// - [`Metric::ConfidentialityRequirement`] (`CR`)
  /// - [`Metric::IntegrityRequirement`] (`IR`)
  /// - [`Metric::AvailabilityRequirement`] (`AR`)
  /// - [`Metric::ModifiedAttackVector`] (`MAV`)
  /// - [`Metric::ModifiedAttackComplexity`] (`MAC`)
  /// - [`Metric::ModifiedAttackRequirements`] (`MAT`)
  /// - [`Metric::ModifiedPrivilegesRequired`] (`MPR`)
  /// - [`Metric::ModifiedUserInteraction`] (`MUI`)
  /// - [`Metric::ModifiedVulnerableSystemConfidentiality`] (`MVC`)
  /// - [`Metric::ModifiedVulnerableSystemIntegrity`] (`MVI`)
  /// - [`Metric::ModifiedVulnerableSystemAvailability`] (`MVA`)
  /// - [`Metric::ModifiedSubsequentSystemConfidentiality`] (`MSC`)
  /// - [`Metric::ModifiedSubsequentSystemIntegrity`] (`MSI`)
  /// - [`Metric::ModifiedSubsequentSystemAvailability`] (`MSA`)
  Environmental,

  /// Supplemental metrics.
  ///
  /// # Description
  ///
  /// A new, optional metric group called the Supplemental metric group
  /// provides new metrics that describe and measure additional extrinsic
  /// attributes of a vulnerability. While the assessment of Supplemental
  /// metrics is provisioned by the provider, the usage and response plan
  /// of each metric within the Supplemental metric group is determined by
  /// the consumer. This contextual information may be employed
  /// differently in each consumer’s environment. No metric will have any
  /// impact on the final calculated CVSS score (e.g. CVSS-BTE).
  /// Organizations may then assign importance and/or effective impact of
  /// each metric, or set/combination of metrics, giving them more, less,
  /// or absolutely no effect on the final risk analysis. Metrics and
  /// values will simply convey additional extrinsic characteristics of
  /// the vulnerability itself.
  ///
  /// # Metrics
  ///
  /// - [`Metric::Safety`] (`S`)
  /// - [`Metric::Automatable`] (`AU`)
  /// - [`Metric::Recovery`] (`R`)
  /// - [`Metric::ValueDensity`] (`V`)
  /// - [`Metric::VulnerabilityResponseEffort`] (`RE`)
  /// - [`Metric::ProviderUrgency`] (`U`)
  Supplemental,
}

impl From<Name> for Group {
  fn from(name: Name) -> Group {
    match name {
      Name::AttackVector => Group::Base,
      Name::AttackComplexity => Group::Base,
      Name::AttackRequirements => Group::Base,
      Name::PrivilegesRequired => Group::Base,
      Name::UserInteraction => Group::Base,
      Name::VulnerableSystemConfidentialityImpact => Group::Base,
      Name::VulnerableSystemIntegrityImpact => Group::Base,
      Name::VulnerableSystemAvailabilityImpact => Group::Base,
      Name::SubsequentSystemConfidentialityImpact => Group::Base,
      Name::SubsequentSystemIntegrityImpact => Group::Base,
      Name::SubsequentSystemAvailabilityImpact => Group::Base,

      Name::ExploitMaturity => Group::Threat,

      Name::ConfidentialityRequirement => Group::Environmental,
      Name::IntegrityRequirement => Group::Environmental,
      Name::AvailabilityRequirement => Group::Environmental,
      Name::ModifiedAttackVector => Group::Environmental,
      Name::ModifiedAttackComplexity => Group::Environmental,
      Name::ModifiedAttackRequirements => Group::Environmental,
      Name::ModifiedPrivilegesRequired => Group::Environmental,
      Name::ModifiedUserInteraction => Group::Environmental,
      Name::ModifiedVulnerableSystemConfidentiality => Group::Environmental,
      Name::ModifiedVulnerableSystemIntegrity => Group::Environmental,
      Name::ModifiedVulnerableSystemAvailability => Group::Environmental,
      Name::ModifiedSubsequentSystemConfidentiality => Group::Environmental,
      Name::ModifiedSubsequentSystemIntegrity => Group::Environmental,
      Name::ModifiedSubsequentSystemAvailability => Group::Environmental,

      Name::Safety => Group::Supplemental,
      Name::Automatable => Group::Supplemental,
      Name::Recovery => Group::Supplemental,
      Name::ValueDensity => Group::Supplemental,
      Name::VulnerabilityResponseEffort => Group::Supplemental,
      Name::ProviderUrgency => Group::Supplemental,
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
/// # use polycvss::v4::{AttackVector, Metric, Name};
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
/// # use polycvss::v4::{AttackVector, Name};
/// # fn main() {
/// // check if metric is mandatory
/// assert_eq!(true, Name::AttackVector.is_mandatory());
/// # }
/// ```
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
pub enum Name {
  /// Attack Vector (`AV`) metric name.  See [`Metric::AttackVector`][].
  AttackVector,
  /// Attack Complexity (`AC`) metric name.  See [`Metric::AttackComplexity`][].
  AttackComplexity,
  /// Attack Requirements (`AT`) metric name.  See [`Metric::AttackRequirements`][].
  AttackRequirements,
  /// Privileges Required (`PR`) metric name.  See [`Metric::PrivilegesRequired`][].
  PrivilegesRequired,
  /// User Interaction (`UI`) metric name.  See [`Metric::UserInteraction`][].
  UserInteraction,
  /// Vulnerable System Confidentiality Impact (`VC`) metric name.  See [`Metric::VulnerableSystemConfidentialityImpact`][].
  VulnerableSystemConfidentialityImpact,
  /// Vulnerable System Integrity Impact (`VI`) metric name.  See [`Metric::VulnerableSystemIntegrityImpact`][].
  VulnerableSystemIntegrityImpact,
  /// Vulnerable System Availability Impact (`VA`) metric name.  See [`Metric::VulnerableSystemAvailabilityImpact`][].
  VulnerableSystemAvailabilityImpact,
  /// Subsequent System Confidentiality Impact (`SC`) metric name.  See [`Metric::SubsequentSystemConfidentialityImpact`][].
  SubsequentSystemConfidentialityImpact,
  /// Subsequent System Integrity Impact (`SI`) metric name.  See [`Metric::SubsequentSystemIntegrityImpact`][].
  SubsequentSystemIntegrityImpact,
  /// Subsequent System Availability Impact (`SA`) metric name.  See [`Metric::SubsequentSystemAvailabilityImpact`][].
  SubsequentSystemAvailabilityImpact,
  /// Exploit Maturity (`E`) metric name.  See [`Metric::ExploitMaturity`][].
  ExploitMaturity,
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
  /// Modified Attack Requirements (`MAT`) metric name.  See [`Metric::ModifiedAttackRequirements`][].
  ModifiedAttackRequirements,
  /// Modified Privileges Required (`MPR`) metric name.  See [`Metric::ModifiedPrivilegesRequired`][].
  ModifiedPrivilegesRequired,
  /// Modified User Interaction (`MUI`) metric name.  See [`Metric::ModifiedUserInteraction`][].
  ModifiedUserInteraction,
  /// Modified Vulnerable System Confidentiality (`MVC`) metric name.  See [`Metric::ModifiedVulnerableSystemConfidentiality`][].
  ModifiedVulnerableSystemConfidentiality,
  /// Modified Vulnerable System Integrity (`MVI`) metric name.  See [`Metric::ModifiedVulnerableSystemIntegrity`][].
  ModifiedVulnerableSystemIntegrity,
  /// Modified Vulnerable System Availability (`MVA`) metric name.  See [`Metric::ModifiedVulnerableSystemAvailability`][].
  ModifiedVulnerableSystemAvailability,
  /// Modified Subsequent System Confidentiality (`MSC`) metric name.  See [`Metric::ModifiedSubsequentSystemConfidentiality`][].
  ModifiedSubsequentSystemConfidentiality,
  /// Modified Subsequent System Integrity (`MSI`) metric name.  See [`Metric::ModifiedSubsequentSystemIntegrity`][].
  ModifiedSubsequentSystemIntegrity,
  /// Modified Subsequent System Availability (`MSA`) metric name.  See [`Metric::ModifiedSubsequentSystemAvailability`][].
  ModifiedSubsequentSystemAvailability,
  /// Safety (`S`) metric name.  See [`Metric::Safety`][].
  Safety,
  /// Automatable (`AU`) metric name.  See [`Metric::Automatable`][].
  Automatable,
  /// Recovery (`R`) metric name.  See [`Metric::Recovery`][].
  Recovery,
  /// Value Density (`V`) metric name.  See [`Metric::ValueDensity`][].
  ValueDensity,
  /// Vulnerability Response Effort (`RE`) metric name.  See [`Metric::VulnerabilityResponseEffort`][].
  VulnerabilityResponseEffort,
  /// Provider Urgency (`U`) metric name.  See [`Metric::ProviderUrgency`][].
  ProviderUrgency,
}

impl Name {
  /// Is this metric mandatory?
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::v4::{AttackVector, Name};
  /// # fn main() {
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
      Metric::AttackVector(_) => Name::AttackVector, // Attack Vector (AV)
      Metric::AttackComplexity(_) => Name::AttackComplexity, // Attack Complexity (AC)
      Metric::AttackRequirements(_) => Name::AttackRequirements, // Attack Requirements (AT)
      Metric::PrivilegesRequired(_) => Name::PrivilegesRequired, // Privileges Required (PR)
      Metric::UserInteraction(_) => Name::UserInteraction, // User Interaction (UI)
      Metric::VulnerableSystemConfidentialityImpact(_) => Name::VulnerableSystemConfidentialityImpact, // Vulnerable System Confidentiality Impact (VC)
      Metric::VulnerableSystemIntegrityImpact(_) => Name::VulnerableSystemIntegrityImpact, // Vulnerable System Integrity Impact (VI)
      Metric::VulnerableSystemAvailabilityImpact(_) => Name::VulnerableSystemAvailabilityImpact, // Vulnerable System Availability Impact (VA)
      Metric::SubsequentSystemConfidentialityImpact(_) => Name::SubsequentSystemConfidentialityImpact, // Subsequent System Confidentiality Impact (SC)
      Metric::SubsequentSystemIntegrityImpact(_) => Name::SubsequentSystemIntegrityImpact, // Subsequent System Integrity Impact (SI)
      Metric::SubsequentSystemAvailabilityImpact(_) => Name::SubsequentSystemAvailabilityImpact, // Subsequent System Availability Impact (SA)
      Metric::ExploitMaturity(_) => Name::ExploitMaturity, // Exploit Maturity (E)
      Metric::ConfidentialityRequirement(_) => Name::ConfidentialityRequirement, // Confidentiality Requirement (CR)
      Metric::IntegrityRequirement(_) => Name::IntegrityRequirement, // Integrity Requirement (IR)
      Metric::AvailabilityRequirement(_) => Name::AvailabilityRequirement, // Availability Requirement (AR)
      Metric::ModifiedAttackVector(_) => Name::ModifiedAttackVector, // Modified Attack Vector (MAV)
      Metric::ModifiedAttackComplexity(_) => Name::ModifiedAttackComplexity, // Modified Attack Complexity (MAC)
      Metric::ModifiedAttackRequirements(_) => Name::ModifiedAttackRequirements, // Modified Attack Requirements (MAT)
      Metric::ModifiedPrivilegesRequired(_) => Name::ModifiedPrivilegesRequired, // Modified Privileges Required (MPR)
      Metric::ModifiedUserInteraction(_) => Name::ModifiedUserInteraction, // Modified User Interaction (MUI)
      Metric::ModifiedVulnerableSystemConfidentiality(_) => Name::ModifiedVulnerableSystemConfidentiality, // Modified Vulnerable System Confidentiality (MVC)
      Metric::ModifiedVulnerableSystemIntegrity(_) => Name::ModifiedVulnerableSystemIntegrity, // Modified Vulnerable System Integrity (MVI)
      Metric::ModifiedVulnerableSystemAvailability(_) => Name::ModifiedVulnerableSystemAvailability, // Modified Vulnerable System Availability (MVA)
      Metric::ModifiedSubsequentSystemConfidentiality(_) => Name::ModifiedSubsequentSystemConfidentiality, // Modified Subsequent System Confidentiality (MSC)
      Metric::ModifiedSubsequentSystemIntegrity(_) => Name::ModifiedSubsequentSystemIntegrity, // Modified Subsequent System Integrity (MSI)
      Metric::ModifiedSubsequentSystemAvailability(_) => Name::ModifiedSubsequentSystemAvailability, // Modified Subsequent System Availability (MSA)
      Metric::Safety(_) => Name::Safety, // Safety (S)
      Metric::Automatable(_) => Name::Automatable, // Automatable (AU)
      Metric::Recovery(_) => Name::Recovery, // Recovery (R)
      Metric::ValueDensity(_) => Name::ValueDensity, // Value Density (V)
      Metric::VulnerabilityResponseEffort(_) => Name::VulnerabilityResponseEffort, // Vulnerability Response Effort (RE)
      Metric::ProviderUrgency(_) => Name::ProviderUrgency, // Provider Urgency (U)
    }
  }
}

impl std::str::FromStr for Name {
  type Err = super::Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "AV" => Ok(Name::AttackVector),
      "AC" => Ok(Name::AttackComplexity),
      "AT" => Ok(Name::AttackRequirements),
      "PR" => Ok(Name::PrivilegesRequired),
      "UI" => Ok(Name::UserInteraction),
      "VC" => Ok(Name::VulnerableSystemConfidentialityImpact),
      "VI" => Ok(Name::VulnerableSystemIntegrityImpact),
      "VA" => Ok(Name::VulnerableSystemAvailabilityImpact),
      "SC" => Ok(Name::SubsequentSystemConfidentialityImpact),
      "SI" => Ok(Name::SubsequentSystemIntegrityImpact),
      "SA" => Ok(Name::SubsequentSystemAvailabilityImpact),
      "E" => Ok(Name::ExploitMaturity),
      "CR" => Ok(Name::ConfidentialityRequirement),
      "IR" => Ok(Name::IntegrityRequirement),
      "AR" => Ok(Name::AvailabilityRequirement),
      "MAV" => Ok(Name::ModifiedAttackVector),
      "MAC" => Ok(Name::ModifiedAttackComplexity),
      "MAT" => Ok(Name::ModifiedAttackRequirements),
      "MPR" => Ok(Name::ModifiedPrivilegesRequired),
      "MUI" => Ok(Name::ModifiedUserInteraction),
      "MVC" => Ok(Name::ModifiedVulnerableSystemConfidentiality),
      "MVI" => Ok(Name::ModifiedVulnerableSystemIntegrity),
      "MVA" => Ok(Name::ModifiedVulnerableSystemAvailability),
      "MSC" => Ok(Name::ModifiedSubsequentSystemConfidentiality),
      "MSI" => Ok(Name::ModifiedSubsequentSystemIntegrity),
      "MSA" => Ok(Name::ModifiedSubsequentSystemAvailability),
      "S" => Ok(Name::Safety),
      "AU" => Ok(Name::Automatable),
      "R" => Ok(Name::Recovery),
      "V" => Ok(Name::ValueDensity),
      "RE" => Ok(Name::VulnerabilityResponseEffort),
      "U" => Ok(Name::ProviderUrgency),
      _ => Err(Err::UnknownName),
    }
  }
}

impl std::fmt::Display for Name {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{}", match self {
      Name::AttackVector => "AV",
      Name::AttackComplexity => "AC",
      Name::AttackRequirements => "AT",
      Name::PrivilegesRequired => "PR",
      Name::UserInteraction => "UI",
      Name::VulnerableSystemConfidentialityImpact => "VC",
      Name::VulnerableSystemIntegrityImpact => "VI",
      Name::VulnerableSystemAvailabilityImpact => "VA",
      Name::SubsequentSystemConfidentialityImpact => "SC",
      Name::SubsequentSystemIntegrityImpact => "SI",
      Name::SubsequentSystemAvailabilityImpact => "SA",
      Name::ExploitMaturity => "E",
      Name::ConfidentialityRequirement => "CR",
      Name::IntegrityRequirement => "IR",
      Name::AvailabilityRequirement => "AR",
      Name::ModifiedAttackVector => "MAV",
      Name::ModifiedAttackComplexity => "MAC",
      Name::ModifiedAttackRequirements => "MAT",
      Name::ModifiedPrivilegesRequired => "MPR",
      Name::ModifiedUserInteraction => "MUI",
      Name::ModifiedVulnerableSystemConfidentiality => "MVC",
      Name::ModifiedVulnerableSystemIntegrity => "MVI",
      Name::ModifiedVulnerableSystemAvailability => "MVA",
      Name::ModifiedSubsequentSystemConfidentiality => "MSC",
      Name::ModifiedSubsequentSystemIntegrity => "MSI",
      Name::ModifiedSubsequentSystemAvailability => "MSA",
      Name::Safety => "S",
      Name::Automatable => "AU",
      Name::Recovery => "R",
      Name::ValueDensity => "V",
      Name::VulnerabilityResponseEffort => "RE",
      Name::ProviderUrgency => "U",
    })
  }
}

/// [`Vector`] nomenclature.
///
/// # Description
///
/// Numerical CVSS Scores have very different meanings based on the
/// metrics used to calculate them. Regarding prioritization, the
/// usefulness of a numerical CVSS score is directly proportional to the
/// CVSS metrics leveraged to generate that score. Therefore, numerical
/// CVSS scores should be labeled using nomenclature that communicates the
/// metrics used in its generation.
///
/// | CVSS Nomenclature | CVSS Metrics Used |
/// | ----------------- | ----------------- |
/// | `CVSS-B` | Base metrics. |
/// | `CVSS-BE` | Base and Environmental metrics. |
/// | `CVSS-BT` | Base and Threat metrics. |
/// | `CVSS-BTE` | Base, Threat, Environmental metrics. |
///
/// Additional Notes:
///
/// - This nomenclature should be used wherever a numerical CVSS value is displayed or communicated.
/// - The application of Environmental and Threat metrics is the responsibility of the CVSS consumer. Assessment providers such as product maintainers and other public/private entities such as the National Vulnerability Database (NVD) typically provide only the Base Scores enumerated as CVSS-B.
/// - The inclusion of the “E” in the nomenclature is appropriate if any Environmental metrics are used to generate the resulting score.
/// - The inclusion of the “T” in the nomenclature is appropriate if any Threat metrics are used to generate the resulting score.
/// - In CVSS v4.0, Base, Threat, and Environmental metric values are always considered in the calculation of the final score. The absence of explicit Threat and/or Environmental metric selections will still result in a complete score using default (“Not Defined”) values. This nomenclature makes it explicit and clear about which metric groups were considered in the numerical CVSS score provided.
///
/// See [CVSS v4.0 Specification, Section 1.3: Nomenclature][doc].
///
/// # Examples
///
/// Convert nomenclatures to strings:
///
/// ```
/// # use polycvss::v4::Nomenclature;
/// # fn main() {
/// assert_eq!(Nomenclature::CvssB.to_string(), "CVSS-B");
/// assert_eq!(Nomenclature::CvssBe.to_string(), "CVSS-BE");
/// assert_eq!(Nomenclature::CvssBt.to_string(), "CVSS-BT");
/// assert_eq!(Nomenclature::CvssBte.to_string(), "CVSS-BTE");
/// # }
/// ```
///
/// Get nomenclature from string:
///
/// ```
/// # use polycvss::{Err, v4::Nomenclature};
/// # fn main() -> Result<(), Err> {
/// let n: Nomenclature = "CVSS-BT".parse()?;
/// assert_eq!(n, Nomenclature::CvssBt);
/// # Ok(())
/// # }
/// ```
///
/// Get nomenclature for vector string with only base metrics:
///
/// ```
/// # use polycvss::{Err, v4::{Nomenclature, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string with only base metrics
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
///
/// // get nomenclature, check result
/// assert_eq!(Nomenclature::from(v), Nomenclature::CvssB);
/// # Ok(())
/// # }
/// ```
///
/// Get nomenclature for vector string with base and environmental metrics:
///
/// ```
/// # use polycvss::{Err, v4::{Nomenclature, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string with base and environmental metrics
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:N".parse()?;
///
/// // get nomenclature, check result
/// assert_eq!(Nomenclature::from(v), Nomenclature::CvssBe);
/// # Ok(())
/// # }
/// ```
///
/// Get nomenclature for vector string with base and threat metrics:
///
/// ```
/// # use polycvss::{Err, v4::{Nomenclature, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string with base and threat metrics
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A".parse()?;
///
/// // get nomenclature, check result
/// assert_eq!(Nomenclature::from(v), Nomenclature::CvssBt);
/// # Ok(())
/// # }
/// ```
///
/// Get nomenclature for vector string with base, threat, and environmental metrics:
///
/// ```
/// # use polycvss::{Err, v4::{Nomenclature, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string with base, threat, and environmental metrics
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/MAV:N".parse()?;
///
/// // get nomenclature, check result
/// assert_eq!(Nomenclature::from(v), Nomenclature::CvssBte);
/// # Ok(())
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document#Nomenclature
///   "CVSS v4.0 Specification, Section 1.3: Nomenclature"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Nomenclature {
  /// Base metrics.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Nomenclature, Vector}};
  /// # fn main() -> Result<(), Err> {
  /// // parse vector string with only base metrics
  /// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
  ///
  /// // get nomenclature, check result
  /// assert_eq!(Nomenclature::from(v), Nomenclature::CvssB);
  /// # Ok(())
  /// # }
  /// ```
  CvssB,

  /// Base and Environmental metrics.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Nomenclature, Vector}};
  /// # fn main() -> Result<(), Err> {
  /// // parse vector string with base and environmental metrics
  /// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:N".parse()?;
  ///
  /// // get nomenclature, check result
  /// assert_eq!(Nomenclature::from(v), Nomenclature::CvssBe);
  /// # Ok(())
  /// # }
  /// ```
  CvssBe,

  /// Base and Threat metrics.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Nomenclature, Vector}};
  /// # fn main() -> Result<(), Err> {
  /// // parse vector string with base and threat metrics
  /// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A".parse()?;
  ///
  /// // get nomenclature, check result
  /// assert_eq!(Nomenclature::from(v), Nomenclature::CvssBt);
  /// # Ok(())
  /// # }
  /// ```
  CvssBt,

  /// Base, Threat, Environmental metrics.
  ///
  /// # Example
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Nomenclature, Vector}};
  /// # fn main() -> Result<(), Err> {
  /// // parse vector string with base, threat, and environmental metrics
  /// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/MAV:N".parse()?;
  ///
  /// // get nomenclature, check result
  /// assert_eq!(Nomenclature::from(v), Nomenclature::CvssBte);
  /// # Ok(())
  /// # }
  /// ```
  CvssBte,
}

impl std::fmt::Display for Nomenclature {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{}", match self {
      Nomenclature::CvssB => "CVSS-B",
      Nomenclature::CvssBe => "CVSS-BE",
      Nomenclature::CvssBt => "CVSS-BT",
      Nomenclature::CvssBte => "CVSS-BTE",
    })
  }
}

impl std::str::FromStr for Nomenclature {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "CVSS-B" => Ok(Nomenclature::CvssB),
      "CVSS-BE" => Ok(Nomenclature::CvssBe),
      "CVSS-BT" => Ok(Nomenclature::CvssBt),
      "CVSS-BTE" => Ok(Nomenclature::CvssBte),
      _ => Err(Err::UnknownNomenclature),
    }
  }
}

impl From<Vector> for Nomenclature {
  fn from(vec: Vector) -> Nomenclature {
    let e = vec.into_iter().map(Name::from).map(Group::from).any(|g| g == Group::Environmental);
    let t = vec.into_iter().map(Name::from).map(Group::from).any(|g| g == Group::Threat);

    match (e, t) {
      (false, false) => Nomenclature::CvssB,
      (false, true) => Nomenclature::CvssBt,
      (true, false) => Nomenclature::CvssBe,
      (true, true) => Nomenclature::CvssBte,
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
/// # use polycvss::{Err, v4::{AttackVector, Metric}};
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
/// # use polycvss::v4::{AttackVector, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::AttackVector(AttackVector::Adjacent).to_string();
///
/// // check result
/// assert_eq!(s, "AV:A");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v4::{AttackVector, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AttackVector(AttackVector::Local));
///
/// // check result
/// assert_eq!(name, Name::AttackVector);
/// # }
/// ```
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
pub enum Metric {
  /// Attack Vector (`AV`) metric.
  ///
  /// # Description
  ///
  /// This metric reflects the context by which vulnerability exploitation
  /// is possible. This metric value (and consequently the resulting
  /// severity) will be larger the more remote (logically, and physically)
  /// an attacker can be in order to exploit the vulnerable system. The
  /// assumption is that the number of potential attackers for a
  /// vulnerability that could be exploited from across a network is larger
  /// than the number of potential attackers that could exploit a
  /// vulnerability requiring physical access to a device, and therefore
  /// warrants a greater severity.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
  /// - Documentation: [CVSS v4.0 Specification, Section 2.1.1: Attack Vector (`AV`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric and check it:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{AttackVector, Metric}};
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
  /// # use polycvss::v4::{AttackVector, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::AttackVector(AttackVector::Adjacent).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "AV:A");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{AttackVector, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::AttackVector(AttackVector::Local));
  ///
  /// // check result
  /// assert_eq!(name, Name::AttackVector);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Attack-Vector-AV
  ///   "CVSS v4.0 Specification, Section 2.1.1: Attack Vector (AV)"
  AttackVector(AttackVector), // Attack Vector (AV)

  /// Attack Complexity (`AC`) metric.
  ///
  /// # Description
  ///
  /// This metric captures measurable actions that must be taken by the
  /// attacker to actively evade or circumvent existing built-in
  /// security-enhancing conditions in order to obtain a working exploit.
  /// These are conditions whose primary purpose is to increase security
  /// and/or increase exploit engineering complexity. A vulnerability
  /// exploitable without a target-specific variable has a lower complexity
  /// than a vulnerability that would require non-trivial customization.
  /// This metric is meant to capture security mechanisms utilized by the
  /// vulnerable system, and does not relate to the amount of time or
  /// attempts it would take for an attacker to succeed, e.g. a race
  /// condition. If the attacker does not take action to overcome these
  /// conditions, the attack will always fail.
  ///
  /// The evasion or satisfaction of authentication mechanisms or
  /// requisites is included in the Privileges Required assessment and is
  /// not considered here as a factor of relevance for Attack Complexity.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
  /// - Documentation: [CVSS v4.0 Specification, Section 2.1.2: Attack Complexity (`AC`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{AttackComplexity, Metric}};
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
  /// # use polycvss::v4::{AttackComplexity, Metric};
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
  /// # use polycvss::v4::{AttackComplexity, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::AttackComplexity(AttackComplexity::High));
  ///
  /// // check result
  /// assert_eq!(name, Name::AttackComplexity);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Attack-Complexity-AC
  ///   "CVSS v4.0 Specification, Section 2.1.2: Attack Complexity (AC)"
  AttackComplexity(AttackComplexity), // Attack Complexity (AC)

  /// Attack Requirements (`AT`) metric.
  ///
  /// # Description
  ///
  /// This metric captures the prerequisite deployment and execution
  /// conditions or variables of the vulnerable system that enable the
  /// attack. These differ from security-enhancing techniques/technologies
  /// (ref Attack Complexity) as the primary purpose of these conditions is
  /// not to explicitly mitigate attacks, but rather, emerge naturally as a
  /// consequence of the deployment and execution of the vulnerable system.
  /// If the attacker does not take action to overcome these conditions, the
  /// attack may succeed only occasionally or not succeed at all.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
  /// - Base Metric Set: Exploitability Metrics
  /// - Documentation: [CVSS v4.0 Specification, Section 2.1.3: Attack Requirements (`AT`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{AttackRequirements, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "AT:N".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::AttackRequirements(AttackRequirements::None));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{AttackRequirements, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::AttackRequirements(AttackRequirements::Present).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "AT:P");
  /// # }
  /// ```
  ///
  /// Get metric name
  ///
  /// ```
  /// # use polycvss::v4::{AttackRequirements, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::AttackRequirements(AttackRequirements::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::AttackRequirements);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Attack-Requirements-AT
  ///   "CVSS v4.0 Specification, Section 2.1.3: Attack Requirements (AT)"
  AttackRequirements(AttackRequirements), // Attack Requirements (AT)

  /// Privileges Required (`PR`) metric.
  ///
  /// # Description
  ///
  /// This metric describes the level of privileges an attacker must
  /// possess prior to successfully exploiting the vulnerability. The method
  /// by which the attacker obtains privileged credentials prior to the
  /// attack (e.g., free trial accounts), is outside the scope of this
  /// metric. Generally, self-service provisioned accounts do not constitute
  /// a privilege requirement if the attacker can grant themselves
  /// privileges as part of the attack.
  ///
  /// The resulting score is greatest if no privileges are required.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
  /// - Base Metric Set: Exploitability Metrics
  /// - Documentation: [CVSS v4.0 Specification, Section 2.1.4: Privileges Required (`PR`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{PrivilegesRequired, Metric}};
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
  /// # use polycvss::v4::{PrivilegesRequired, Metric};
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
  /// # use polycvss::v4::{PrivilegesRequired, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::PrivilegesRequired(PrivilegesRequired::High));
  ///
  /// // check result
  /// assert_eq!(name, Name::PrivilegesRequired);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Privileges-Required-PR
  ///   "CVSS v4.0 Specification, Section 2.1.4: Privileges Required (PR)"
  PrivilegesRequired(PrivilegesRequired), // Privileges Required (PR)

  /// User Interaction (`UI`) metric.
  ///
  /// # Description
  ///
  /// This metric captures the requirement for a human user, other than
  /// the attacker, to participate in the successful compromise of the
  /// vulnerable system. This metric determines whether the vulnerability
  /// can be exploited solely at the will of the attacker, or whether a
  /// separate user (or user-initiated process) must participate in some
  /// manner. The resulting score is greatest when no user interaction is
  /// required.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
  /// - Base Metric Set: Exploitability Metrics
  /// - Documentation: [CVSS v4.0 Specification, Section 2.1.5: User Interaction (`UI`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{UserInteraction, Metric}};
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
  /// # use polycvss::v4::{UserInteraction, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::UserInteraction(UserInteraction::Passive).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "UI:P");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{UserInteraction, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::UserInteraction(UserInteraction::Active));
  ///
  /// // check result
  /// assert_eq!(name, Name::UserInteraction);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#User-Interaction-UI
  ///   "CVSS v4.0 Specification, Section 2.1.5: User Interaction (UI)"
  UserInteraction(UserInteraction), // User Interaction (UI)

  /// Vulnerable System Confidentiality Impact (`VC`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the impact to the confidentiality of the
  /// information managed by the system due to a successfully exploited
  /// vulnerability. Confidentiality refers to limiting information access
  /// and disclosure to only authorized users, as well as preventing
  /// access by, or disclosure to, unauthorized ones. The resulting score
  /// is greatest when the loss to the system is highest.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
  /// - Base Metric Set: Impact Metrics
  /// - Documentation: [CVSS v4.0 Specification, Section 2.2.1: Confidentiality (`VC`/`SC`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "VC:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::VulnerableSystemConfidentialityImpact(Impact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::VulnerableSystemConfidentialityImpact(Impact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "VC:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::VulnerableSystemConfidentialityImpact(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::VulnerableSystemConfidentialityImpact);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Confidentiality-VC-SC
  ///   "CVSS v4.0 Specification, Section 2.2.1: Confidentiality (VC/SC)"
  VulnerableSystemConfidentialityImpact(Impact), // Vulnerable System Confidentiality Impact (VC)

  /// Vulnerable System Integrity Impact (`VI`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the impact to integrity of a successfully
  /// exploited vulnerability. Integrity refers to the trustworthiness and
  /// veracity of information. Integrity of a system is impacted when an
  /// attacker causes unauthorized modification of system data. Integrity
  /// is also impacted when a system user can repudiate critical actions
  /// taken in the context of the system (e.g. due to insufficient
  /// logging).
  ///
  /// The resulting score is greatest when the consequence to the system is highest.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
  /// - Base Metric Set: Impact Metrics
  /// - Documentation: [CVSS v4.0 Specification, Section 2.2.4: Integrity (`VI`/`SI`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "VI:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::VulnerableSystemIntegrityImpact(Impact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::VulnerableSystemIntegrityImpact(Impact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "VI:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::VulnerableSystemIntegrityImpact(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::VulnerableSystemIntegrityImpact);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Integrity-VI-SI
  ///   "CVSS v4.0 Specification, Section 2.2.4: Integrity (VI/SI)"
  VulnerableSystemIntegrityImpact(Impact), // Vulnerable System Integrity Impact (VI)

  /// Vulnerable System Availability Impact (`VA`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the impact to the availability of the
  /// impacted system resulting from a successfully exploited
  /// vulnerability. While the Confidentiality and Integrity impact
  /// metrics apply to the loss of confidentiality or integrity of data
  /// (e.g., information, files) used by the system, this metric refers to
  /// the loss of availability of the impacted system itself, such as a
  /// networked service (e.g., web, database, email). Since availability
  /// refers to the accessibility of information resources, attacks that
  /// consume network bandwidth, processor cycles, or disk space all
  /// impact the availability of a system. The resulting score is greatest
  /// when the consequence to the system is highest.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
  /// - Base Metric Set: Impact Metrics
  /// - Documentation: [CVSS v4.0 Specification, Section 2.2.6: Availability (`VA`/`SA`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "VA:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::VulnerableSystemAvailabilityImpact(Impact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::VulnerableSystemAvailabilityImpact(Impact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "VA:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::VulnerableSystemAvailabilityImpact(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::VulnerableSystemAvailabilityImpact);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Availability-VA-SA
  ///   "CVSS v4.0 Specification, Section 2.2.6: Availability (VA/SA)"
  VulnerableSystemAvailabilityImpact(Impact), // Vulnerable System Availability Impact (VA)

  /// Subsequent System Confidentiality Impact (`SC`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the impact to the confidentiality of the
  /// information managed by the system due to a successfully exploited
  /// vulnerability. Confidentiality refers to limiting information access
  /// and disclosure to only authorized users, as well as preventing
  /// access by, or disclosure to, unauthorized ones. The resulting score
  /// is greatest when the loss to the system is highest.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
  /// - Base Metric Set: Impact Metrics
  /// - Documentation: [CVSS v4.0 Specification, Section 2.2.1: Confidentiality (`VC`/`SC`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "SC:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::SubsequentSystemConfidentialityImpact(Impact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::SubsequentSystemConfidentialityImpact(Impact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "SC:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::SubsequentSystemConfidentialityImpact(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::SubsequentSystemConfidentialityImpact);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Confidentiality-VC-SC
  ///   "CVSS v4.0 Specification, Section 2.2.1: Confidentiality (VC/SC)"
  SubsequentSystemConfidentialityImpact(Impact), // Subsequent System Confidentiality Impact (SC)

  /// Subsequent System Integrity Impact (`SI`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the impact to integrity of a successfully
  /// exploited vulnerability. Integrity refers to the trustworthiness and
  /// veracity of information. Integrity of a system is impacted when an
  /// attacker causes unauthorized modification of system data. Integrity
  /// is also impacted when a system user can repudiate critical actions
  /// taken in the context of the system (e.g. due to insufficient
  /// logging).
  ///
  /// The resulting score is greatest when the consequence to the system is highest.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
  /// - Base Metric Set: Impact Metrics
  /// - Documentation: [CVSS v4.0 Specification, Section 2.2.4: Integrity (`VI`/`SI`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "SI:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::SubsequentSystemIntegrityImpact(Impact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::SubsequentSystemIntegrityImpact(Impact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "SI:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::SubsequentSystemIntegrityImpact(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::SubsequentSystemIntegrityImpact);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Integrity-VI-SI
  ///   "CVSS v4.0 Specification, Section 2.2.4: Integrity (VI/SI)"
  SubsequentSystemIntegrityImpact(Impact), // Subsequent System Integrity Impact (SI)

  /// Subsequent System Availability Impact (`SA`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the impact to the availability of the
  /// impacted system resulting from a successfully exploited
  /// vulnerability. While the Confidentiality and Integrity impact
  /// metrics apply to the loss of confidentiality or integrity of data
  /// (e.g., information, files) used by the system, this metric refers to
  /// the loss of availability of the impacted system itself, such as a
  /// networked service (e.g., web, database, email). Since availability
  /// refers to the accessibility of information resources, attacks that
  /// consume network bandwidth, processor cycles, or disk space all
  /// impact the availability of a system. The resulting score is greatest
  /// when the consequence to the system is highest.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Base Metrics][Group::Base]
  /// - Base Metric Set: Impact Metrics
  /// - Documentation: [CVSS v4.0 Specification, Section 2.2.6: Availability (`VA`/`SA`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "SA:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::SubsequentSystemAvailabilityImpact(Impact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::SubsequentSystemAvailabilityImpact(Impact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "SA:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::SubsequentSystemAvailabilityImpact(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::SubsequentSystemAvailabilityImpact);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Availability-VA-SA
  ///   "CVSS v4.0 Specification, Section 2.2.6: Availability (VA/SA)"
  SubsequentSystemAvailabilityImpact(Impact), // Subsequent System Availability Impact (SA)

  /// Exploit Maturity (`E`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the likelihood of the vulnerability being
  /// attacked, and is based on the current state of exploit techniques,
  /// exploit code availability, or active, “in-the-wild” exploitation.
  /// Public availability of easy-to-use exploit code or exploitation
  /// instructions increases the number of potential attackers by including
  /// those who are unskilled. Initially, real-world exploitation may only
  /// be theoretical. Publication of proof-of-concept exploit code,
  /// functional exploit code, or sufficient technical details necessary to
  /// exploit the vulnerability may follow. Furthermore, the available
  /// exploit code or instructions may progress from a proof-of-concept
  /// demonstration to exploit code that is successful in exploiting the
  /// vulnerability consistently. In severe cases, it may be delivered as
  /// the payload of a network-based worm or virus or other automated attack
  /// tools.
  ///
  /// It is the responsibility of the CVSS consumer to populate the values
  /// of Exploit Maturity (`E`) based on information regarding the
  /// availability of exploitation code/processes and the state of
  /// exploitation techniques. This information will be referred to as
  /// “threat intelligence” throughout this document.
  ///
  /// Operational Recommendation: Threat intelligence sources that provide
  /// Exploit Maturity information for all vulnerabilities should be
  /// preferred over those with only partial coverage. Also, it is
  /// recommended to use multiple sources of threat intelligence as many are
  /// not comprehensive. This information should be updated as frequently as
  /// possible and its application to CVSS assessment should be automated.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Threat Metrics][Group::Threat]
  /// - Documentation: [CVSS v4.0 Specification, Section 3.1: Exploit Maturity (`E`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ExploitMaturity, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "E:A".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ExploitMaturity(ExploitMaturity::Attacked));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ExploitMaturity, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ExploitMaturity(ExploitMaturity::ProofOfConcept).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "E:P");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{ExploitMaturity, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ExploitMaturity(ExploitMaturity::Unreported));
  ///
  /// // check result
  /// assert_eq!(name, Name::ExploitMaturity);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Exploit-Maturity-E
  ///   "CVSS v4.0 Specification, Section 3.1: Exploit Maturity (E)"
  ExploitMaturity(ExploitMaturity), // Exploit Maturity (E)

  /// Confidentiality Requirement (`CR`) metric.
  ///
  /// # Description
  ///
  /// These metrics enable the consumer to customize the assessment
  /// depending on the importance of the affected IT asset to the analyst’s
  /// organization, measured in terms of Confidentiality, Integrity, and
  /// Availability. That is, if an IT asset supports a business function for
  /// which Availability is most important, the analyst can assign a greater
  /// value to Availability metrics relative to Confidentiality and
  /// Integrity. Each Security Requirement has three possible values: Low,
  /// Medium, or High, or the default value of Not Defined (`X`).
  ///
  /// The full effect on the environmental score is determined by the
  /// corresponding Modified Base Impact metrics. Following the concept of
  /// assuming “reasonable worst case”, in absence of explicit values, these
  /// metrics are set to the default value of Not Defined (`X`), which is
  /// equivalent to the metric value of High (`H`).
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.1: Confidentiality, Integrity, and Availability Requirements (CR, IR, AR)][doc]
  ///
  /// # Examples
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Requirement, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "CR:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ConfidentialityRequirement(Requirement::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Requirement, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ConfidentialityRequirement(Requirement::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "CR:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Requirement, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ConfidentialityRequirement(Requirement::Medium));
  ///
  /// // check result
  /// assert_eq!(name, Name::ConfidentialityRequirement);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Confidentiality-Integrity-and-Availability-Requirements-CR-IR-AR
  ///   "CVSS v4.0 Specification, Section 4.1: Confidentiality, Integrity, and Availability Requirements (CR, IR, AR)"
  ConfidentialityRequirement(Requirement), // Confidentiality Requirement (CR)

  /// Integrity Requirement (`IR`) metric.
  ///
  /// # Description
  ///
  /// These metrics enable the consumer to customize the assessment
  /// depending on the importance of the affected IT asset to the analyst’s
  /// organization, measured in terms of Confidentiality, Integrity, and
  /// Availability. That is, if an IT asset supports a business function for
  /// which Availability is most important, the analyst can assign a greater
  /// value to Availability metrics relative to Confidentiality and
  /// Integrity. Each Security Requirement has three possible values: Low,
  /// Medium, or High, or the default value of Not Defined (`X`).
  ///
  /// The full effect on the environmental score is determined by the
  /// corresponding Modified Base Impact metrics. Following the concept of
  /// assuming “reasonable worst case”, in absence of explicit values, these
  /// metrics are set to the default value of Not Defined (`X`), which is
  /// equivalent to the metric value of High (`H`).
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.1: Confidentiality, Integrity, and Availability Requirements (CR, IR, AR)][doc]
  ///
  /// # Examples
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Requirement, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "IR:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::IntegrityRequirement(Requirement::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Requirement, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::IntegrityRequirement(Requirement::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "IR:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Requirement, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::IntegrityRequirement(Requirement::Medium));
  ///
  /// // check result
  /// assert_eq!(name, Name::IntegrityRequirement);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Confidentiality-Integrity-and-Availability-Requirements-CR-IR-AR
  ///   "CVSS v4.0 Specification, Section 4.1: Confidentiality, Integrity, and Availability Requirements (CR, IR, AR)"
  IntegrityRequirement(Requirement), // Integrity Requirement (IR)

  /// Availability Requirement (`AR`) metric.
  ///
  /// # Description
  ///
  /// These metrics enable the consumer to customize the assessment
  /// depending on the importance of the affected IT asset to the analyst’s
  /// organization, measured in terms of Confidentiality, Integrity, and
  /// Availability. That is, if an IT asset supports a business function for
  /// which Availability is most important, the analyst can assign a greater
  /// value to Availability metrics relative to Confidentiality and
  /// Integrity. Each Security Requirement has three possible values: Low,
  /// Medium, or High, or the default value of Not Defined (`X`).
  ///
  /// The full effect on the environmental score is determined by the
  /// corresponding Modified Base Impact metrics. Following the concept of
  /// assuming “reasonable worst case”, in absence of explicit values, these
  /// metrics are set to the default value of Not Defined (`X`), which is
  /// equivalent to the metric value of High (`H`).
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.1: Confidentiality, Integrity, and Availability Requirements (CR, IR, AR)][doc]
  ///
  /// # Examples
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Requirement, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "AR:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::AvailabilityRequirement(Requirement::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Requirement, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::AvailabilityRequirement(Requirement::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "AR:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Requirement, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::AvailabilityRequirement(Requirement::Medium));
  ///
  /// // check result
  /// assert_eq!(name, Name::AvailabilityRequirement);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Availability-Integrity-and-Availability-Requirements-CR-IR-AR
  ///   "CVSS v4.0 Specification, Section 4.1: Availability, Integrity, and Availability Requirements (CR, IR, AR)"
  AvailabilityRequirement(Requirement), // Availability Requirement (AR)

  /// Modified Attack Vector (`MAV`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::AttackVector`][]
  /// (`AV`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric and check it:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ModifiedAttackVector, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "MAV:N".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedAttackVector(ModifiedAttackVector::Network));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedAttackVector, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "MAV:A");
  /// # }
  /// ```
  ///
  /// Get metric name
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedAttackVector, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ModifiedAttackVector(ModifiedAttackVector::Local));
  ///
  /// // check result
  /// assert_eq!(name, Name::ModifiedAttackVector);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
  ///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
  ModifiedAttackVector(ModifiedAttackVector), // Modified Attack Vector (MAV)

  /// Modified Attack Complexity (`MAC`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::AttackComplexity`][]
  /// (`AC`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ModifiedAttackComplexity, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "MAC:L".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedAttackComplexity, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "MAC:H");
  /// # }
  /// ```
  ///
  /// Get metric name
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedAttackComplexity, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High));
  ///
  /// // check result
  /// assert_eq!(name, Name::ModifiedAttackComplexity);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
  ///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
  ModifiedAttackComplexity(ModifiedAttackComplexity), // Modified Attack Complexity (MAC)

  /// Modified Attack Requirements (`MAT`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::AttackRequirements`][]
  /// (`AT`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ModifiedAttackRequirements, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "MAT:N".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::None));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedAttackRequirements, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::Present).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "MAT:P");
  /// # }
  /// ```
  ///
  /// Get metric name
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedAttackRequirements, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::ModifiedAttackRequirements);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
  ///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
  ModifiedAttackRequirements(ModifiedAttackRequirements), // Modified Attack Requirements (MAT)

  /// Modified Privileges Required (`MPR`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::PrivilegesRequired`][]
  /// (`PR`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ModifiedPrivilegesRequired, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "MPR:N".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedPrivilegesRequired, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "MPR:L");
  /// # }
  /// ```
  ///
  /// Get metric name
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedPrivilegesRequired, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High));
  ///
  /// // check result
  /// assert_eq!(name, Name::ModifiedPrivilegesRequired);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
  ///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
  ModifiedPrivilegesRequired(ModifiedPrivilegesRequired), // Modified Privileges Required (MPR)

  /// Modified User Interaction (`MUI`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::UserInteraction`][]
  /// (`UI`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ModifiedUserInteraction, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "MUI:N".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedUserInteraction(ModifiedUserInteraction::None));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedUserInteraction, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ModifiedUserInteraction(ModifiedUserInteraction::Passive).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "MUI:P");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedUserInteraction, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ModifiedUserInteraction(ModifiedUserInteraction::Active));
  ///
  /// // check result
  /// assert_eq!(name, Name::ModifiedUserInteraction);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
  ///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
  ModifiedUserInteraction(ModifiedUserInteraction), // Modified User Interaction (MUI)

  /// Modified Vulnerable System Confidentiality (`MVC`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::VulnerableSystemConfidentialityImpact`][]
  /// (`VC`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ModifiedImpact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "MVC:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedImpact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "MVC:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedImpact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::ModifiedVulnerableSystemConfidentiality);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
  ///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
  ModifiedVulnerableSystemConfidentiality(ModifiedImpact), // Modified Vulnerable System Confidentiality (MVC)

  /// Modified Vulnerable System Integrity (`MVI`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::VulnerableSystemIntegrityImpact`][]
  /// (`VI`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ModifiedImpact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "MVI:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedImpact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "MVI:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedImpact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::ModifiedVulnerableSystemIntegrity);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
  ///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
  ModifiedVulnerableSystemIntegrity(ModifiedImpact), // Modified Vulnerable System Integrity (MVI)

  /// Modified Vulnerable System Availability (`MVA`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::VulnerableSystemAvailabilityImpact`][]
  /// (`VA`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ModifiedImpact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "MVA:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedImpact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "MVA:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedImpact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::ModifiedVulnerableSystemAvailability);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
  ///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
  ModifiedVulnerableSystemAvailability(ModifiedImpact), // Modified Vulnerable System Availability (MVA)

  /// Modified Subsequent System Confidentiality (`MSC`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::SubsequentSystemConfidentialityImpact`][]
  /// (`SC`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ModifiedImpact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "MSC:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedImpact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "MSC:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedImpact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::ModifiedSubsequentSystemConfidentiality);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
  ///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
  ModifiedSubsequentSystemConfidentiality(ModifiedImpact), // Modified Subsequent System Confidentiality (MSC)

  /// Modified Subsequent System Integrity (`MSI`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::SubsequentSystemIntegrityImpact`][]
  /// (`SI`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ModifiedSubsequentImpact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "MSI:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedSubsequentImpact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "MSI:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedSubsequentImpact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::ModifiedSubsequentSystemIntegrity);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
  ///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
  ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact), // Modified Subsequent System Integrity (MSI)

  /// Modified Subsequent System Availability (`MSA`) metric.
  ///
  /// # Description
  ///
  /// Metric value which overrides the base [`Metric::SubsequentSystemAvailabilityImpact`][]
  /// (`SA`) metric value.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Environmental Metrics][Group::Environmental]
  /// - Documentation: [CVSS v4.0 Specification, Section 4.2: Modified Base Metrics][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ModifiedSubsequentImpact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "MSA:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedSubsequentImpact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Low).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "MSA:L");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{ModifiedSubsequentImpact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::ModifiedSubsequentSystemAvailability);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Modified-Base-Metrics
  ///   "CVSS v4.0 Specification, Section 4.2: Modified Base Metrics"
  ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact), // Modified Subsequent System Availability (MSA)

  /// Safety (`S`) metric.
  ///
  /// # Description
  ///
  /// The Safety supplemental metric value indicates the degree of impact
  /// to the Safety of a human actor or participant that can be predictably
  /// injured as a result of the vulnerability being exploited.
  ///
  /// Note that Safety metrics are defined in both Environmental and
  /// Supplemental contexts, although the vector string values differ. As a
  /// Supplemental metric, and consistent with the IEC 61508 Definitions
  /// table below, Safety can be described with metric values of `S:X`,
  /// `S:P`, or `S:N`.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Supplemental Metrics][Group::Supplemental]
  /// - Documentation: [CVSS v4.0 Specification, Section 5.1: Safety (`S`)][doc]
  ///
  /// ## IEC 61508 Definitions
  ///
  /// | Category     | Definition                            |
  /// |--------------|---------------------------------------|
  /// | Catastrophic | Multiple loss of life                 |
  /// | Critical     | Loss of a single life                 |
  /// | Marginal     | Major injuries to one or more persons |
  /// | Negligible   | Minor injuries at worst               |
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Safety, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "S:P".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Safety(Safety::Present));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Safety, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Safety(Safety::Negligible).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "S:N");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Safety, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Safety(Safety::NotDefined));
  ///
  /// // check result
  /// assert_eq!(name, Name::Safety);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Safety-S
  ///   "CVSS v4.0 Specification, Section 5.1: Safety (S)"
  Safety(Safety), // Safety (S)

  /// Automatable (`AU`) metric.
  ///
  /// # Description
  ///
  /// The “Automatable” metric captures the answer to the question ”Can an
  /// attacker automate exploitation events for this vulnerability across
  /// multiple targets?” based on steps 1-4 of the kill chain2 [Hutchins et
  /// al., 2011]. These steps are reconnaissance, weaponization, delivery,
  /// and exploitation. If evaluated, the metric can take the values no or
  /// yes.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Supplemental Metrics][Group::Supplemental]
  /// - Documentation: [CVSS v4.0 Specification, Section 5.2: Automatable (`AU`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Automatable, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "AU:N".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Automatable(Automatable::No));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Automatable, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Automatable(Automatable::Yes).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "AU:Y");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Automatable, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Automatable(Automatable::NotDefined));
  ///
  /// // check result
  /// assert_eq!(name, Name::Automatable);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Automatable-AU
  ///   "CVSS v4.0 Specification, Section 5.2: Automatable (AU)"
  Automatable(Automatable), // Automatable (AU)

  /// Recovery (`R`) metric.
  ///
  /// # Description
  ///
  /// Recovery describes the resilience of a system to recover services,
  /// in terms of performance and availability, after an attack has been
  /// performed.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Supplemental Metrics][Group::Supplemental]
  /// - Documentation: [CVSS v4.0 Specification, Section 5.4: Recovery (`R`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{Recovery, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "R:A".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Recovery(Recovery::Automatic));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{Recovery, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Recovery(Recovery::User).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "R:U");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{Recovery, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Recovery(Recovery::Irrecoverable));
  ///
  /// // check result
  /// assert_eq!(name, Name::Recovery);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Recovery-R
  ///   "CVSS v4.0 Specification, Section 5.4: Recovery (R)"
  Recovery(Recovery), // Recovery (R)

  /// Value Density (`V`) metric.
  ///
  /// # Description
  ///
  /// Value Density describes the resources that the attacker will gain
  /// control over with a single exploitation event. It has two possible
  /// values, diffuse and concentrated:
  ///
  /// # Properties
  ///
  /// - Metric Group: [Supplemental Metrics][Group::Supplemental]
  /// - Documentation: [CVSS v4.0 Specification, Section 5.5: Value Density (`V`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ValueDensity, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "V:D".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ValueDensity(ValueDensity::Diffuse));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ValueDensity, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ValueDensity(ValueDensity::Concentrated).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "V:C");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{ValueDensity, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ValueDensity(ValueDensity::NotDefined));
  ///
  /// // check result
  /// assert_eq!(name, Name::ValueDensity);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Value-Density-V
  ///   "CVSS v4.0 Specification, Section 5.5: Value Density (V)"
  ValueDensity(ValueDensity), // Value Density (V)

  /// Vulnerability Reqponse Effort (`RE`) metric.
  ///
  /// # Description
  ///
  /// The intention of the Vulnerability Response Effort metric is to
  /// provide supplemental information on how difficult it is for consumers
  /// to provide an initial response to the impact of vulnerabilities for
  /// deployed products and services in their infrastructure. The consumer
  /// can then take this additional information on effort required into
  /// consideration when applying mitigations and/or scheduling remediation.
  ///
  /// When calculating Vulnerability Response Effort, the effort required
  /// to deploy the quickest available response should be considered.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Supplemental Metrics][Group::Supplemental]
  /// - Documentation: [CVSS v4.0 Specification, Section 5.6: Vulnerability Response Effort (`RE`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{VulnerabilityResponseEffort, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "RE:L".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Low));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{VulnerabilityResponseEffort, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Moderate).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "RE:M");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{VulnerabilityResponseEffort, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::NotDefined));
  ///
  /// // check result
  /// assert_eq!(name, Name::VulnerabilityResponseEffort);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Vulnerability-Response-Effort-RE
  ///   "CVSS v4.0 Specification, Section 5.6: Vulnerability Response Effort (RE)"
  VulnerabilityResponseEffort(VulnerabilityResponseEffort), // Vulnerability Response Effort (RE)

  /// Provider Urgency (`U`) metric.
  ///
  /// # Description
  ///
  /// Many vendors currently provide supplemental severity ratings to
  /// consumers via product security advisories. Other vendors publish
  /// Qualitative Severity Ratings from the CVSS Specification Document in
  /// their advisories.
  ///
  /// To facilitate a standardized method to incorporate additional
  /// provider-supplied assessment, an optional “pass-through” Supplemental
  /// Metric called Provider Urgency is available.
  ///
  /// Note: While any assessment provider along the product supply chain
  /// may provide a Provider Urgency rating:
  ///
  /// Library Maintainer → OS/Distro Maintainer → Provider 1 … Provider n
  /// (PPP) → Consumer
  ///
  /// The Penultimate Product Provider (PPP) is best positioned to provide
  /// a direct assessment of Provider Urgency.
  ///
  /// # Properties
  ///
  /// - Metric Group: [Supplemental Metrics][Group::Supplemental]
  /// - Documentation: [CVSS v4.0 Specification, Section 5.3: Provider Urgency (`U`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v4::{ProviderUrgency, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "U:Red".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ProviderUrgency(ProviderUrgency::Red));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v4::{ProviderUrgency, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ProviderUrgency(ProviderUrgency::Amber).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "U:Amber");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v4::{ProviderUrgency, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ProviderUrgency(ProviderUrgency::NotDefined));
  ///
  /// // check result
  /// assert_eq!(name, Name::ProviderUrgency);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v4-0/specification-document#Provider-Urgency-U
  ///   "CVSS v4.0 Specification, Section 5.3: Provider Urgency (U)"
  ProviderUrgency(ProviderUrgency), // Provider Urgency (U)
}

impl std::fmt::Display for Metric {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{}", match self {
      Metric::AttackVector(AttackVector::Network) => "AV:N",
      Metric::AttackVector(AttackVector::Adjacent) => "AV:A",
      Metric::AttackVector(AttackVector::Local) => "AV:L",
      Metric::AttackVector(AttackVector::Physical) => "AV:P",

      Metric::AttackComplexity(AttackComplexity::Low) => "AC:L",
      Metric::AttackComplexity(AttackComplexity::High) => "AC:H",

      Metric::AttackRequirements(AttackRequirements::None) => "AT:N",
      Metric::AttackRequirements(AttackRequirements::Present) => "AT:P",

      Metric::PrivilegesRequired(PrivilegesRequired::None) => "PR:N",
      Metric::PrivilegesRequired(PrivilegesRequired::Low) => "PR:L",
      Metric::PrivilegesRequired(PrivilegesRequired::High) => "PR:H",

      Metric::UserInteraction(UserInteraction::None) => "UI:N",
      Metric::UserInteraction(UserInteraction::Passive) => "UI:P",
      Metric::UserInteraction(UserInteraction::Active) => "UI:A",

      // base 9 = 3*3
      Metric::VulnerableSystemConfidentialityImpact(Impact::High) => "VC:H",
      Metric::VulnerableSystemConfidentialityImpact(Impact::Low) => "VC:L",
      Metric::VulnerableSystemConfidentialityImpact(Impact::None) => "VC:N",

      // base 27 = 3*3*3
      Metric::VulnerableSystemIntegrityImpact(Impact::High) => "VI:H",
      Metric::VulnerableSystemIntegrityImpact(Impact::Low) => "VI:L",
      Metric::VulnerableSystemIntegrityImpact(Impact::None) => "VI:N",

      // base 81 = 3*3*3*3
      Metric::VulnerableSystemAvailabilityImpact(Impact::High) => "VA:H",
      Metric::VulnerableSystemAvailabilityImpact(Impact::Low) => "VA:L",
      Metric::VulnerableSystemAvailabilityImpact(Impact::None) => "VA:N",

      // base 243 = 3*3*3*3*3
      Metric::SubsequentSystemConfidentialityImpact(Impact::High) => "SC:H",
      Metric::SubsequentSystemConfidentialityImpact(Impact::Low) => "SC:L",
      Metric::SubsequentSystemConfidentialityImpact(Impact::None) => "SC:N",

      // base 729 = 3*3*3*3*3*3
      Metric::SubsequentSystemIntegrityImpact(Impact::High) => "SI:H",
      Metric::SubsequentSystemIntegrityImpact(Impact::Low) => "SI:L",
      Metric::SubsequentSystemIntegrityImpact(Impact::None) => "SI:N",

      // base 2187 = 3*3*3*3*3*3*3
      Metric::SubsequentSystemAvailabilityImpact(Impact::High) => "SA:H",
      Metric::SubsequentSystemAvailabilityImpact(Impact::Low) => "SA:L",
      Metric::SubsequentSystemAvailabilityImpact(Impact::None) => "SA:N",

      Metric::ExploitMaturity(ExploitMaturity::NotDefined) => "E:X",
      Metric::ExploitMaturity(ExploitMaturity::Attacked) => "E:A",
      Metric::ExploitMaturity(ExploitMaturity::ProofOfConcept) => "E:P",
      Metric::ExploitMaturity(ExploitMaturity::Unreported) => "E:U",

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

      // base 6561 = 3*3*3*3*3*3*3*3
      Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined) => "MAV:X",
      Metric::ModifiedAttackVector(ModifiedAttackVector::Network) => "MAV:N",
      Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent) => "MAV:A",
      Metric::ModifiedAttackVector(ModifiedAttackVector::Local) => "MAV:L",
      Metric::ModifiedAttackVector(ModifiedAttackVector::Physical) => "MAV:P",

      // base 32805 = 3*3*3*3*3*3*3*3*5
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined) => "MAC:X",
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low) => "MAC:L",
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High) => "MAC:H",

      // base 98415 = 3*3*3*3*3*3*3*3*5*3
      Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::NotDefined) => "MAT:X",
      Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::None) => "MAT:N",
      Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::Present) => "MAT:P",

      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined) => "MPR:X",
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None) => "MPR:N",
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low) => "MPR:L",
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High) => "MPR:H",

      Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined) => "MUI:X",
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::None) => "MUI:N",
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::Passive) => "MUI:P",
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::Active) => "MUI:A",

      Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::NotDefined) => "MVC:X",
      Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::High) => "MVC:H",
      Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::Low) => "MVC:L",
      Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::None) => "MVC:N",

      Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::NotDefined) => "MVI:X",
      Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::High) => "MVI:H",
      Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::Low) => "MVI:L",
      Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::None) => "MVI:N",

      Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::NotDefined) => "MVA:X",
      Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::High) => "MVA:H",
      Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::Low) => "MVA:L",
      Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::None) => "MVA:N",

      Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::NotDefined) => "MSC:X",
      Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::High) => "MSC:H",
      Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::Low) => "MSC:L",
      Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::None) => "MSC:N",

      // base 295245 = 3*3*3*3*3*3*3*3*5*3*3
      Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::NotDefined) => "MSI:X",
      Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::High) => "MSI:H",
      Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Low) => "MSI:L",
      Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::None) => "MSI:N",
      Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Safety) => "MSI:S",

      // base 1476225 = 3*3*3*3*3*3*3*3*5*3*3*5
      Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::NotDefined) => "MSA:X",
      Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::High) => "MSA:H",
      Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Low) => "MSA:L",
      Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::None) => "MSA:N",
      Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Safety) => "MSA:S",

      // base 7381125 = 3*3*3*3*3*3*3*3*5*3*3*5*5
      Metric::Safety(Safety::NotDefined) => "S:X",
      Metric::Safety(Safety::Present) => "S:P",
      Metric::Safety(Safety::Negligible) => "S:N",

      // base 22143375 = 3*3*3*3*3*3*3*3*5*3*3*5*5*3
      Metric::Automatable(Automatable::NotDefined) => "AU:X",
      Metric::Automatable(Automatable::No) => "AU:N",
      Metric::Automatable(Automatable::Yes) => "AU:Y",

      Metric::Recovery(Recovery::NotDefined) => "R:X",
      Metric::Recovery(Recovery::Automatic) => "R:A",
      Metric::Recovery(Recovery::User) => "R:U",
      Metric::Recovery(Recovery::Irrecoverable) => "R:I",

      // base 66430125 = 3*3*3*3*3*3*3*5*3*3*3*5*5*3*3
      Metric::ValueDensity(ValueDensity::NotDefined) => "V:X",
      Metric::ValueDensity(ValueDensity::Diffuse) => "V:D",
      Metric::ValueDensity(ValueDensity::Concentrated) => "V:C",

      Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::NotDefined) => "RE:X",
      Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Low) => "RE:L",
      Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Moderate) => "RE:M",
      Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::High) => "RE:H",

      // base 199290375 = 3*3*3*3*3*3*3*5*3*3*3*5*5*3*3*3
      Metric::ProviderUrgency(ProviderUrgency::NotDefined) => "U:X",
      Metric::ProviderUrgency(ProviderUrgency::Red) => "U:Red",
      Metric::ProviderUrgency(ProviderUrgency::Amber) => "U:Amber",
      Metric::ProviderUrgency(ProviderUrgency::Green) => "U:Green",
      Metric::ProviderUrgency(ProviderUrgency::Clear) => "U:Clear",
    })
  }
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

      "AT:N" => Ok(Metric::AttackRequirements(AttackRequirements::None)),
      "AT:P" => Ok(Metric::AttackRequirements(AttackRequirements::Present)),

      "PR:N" => Ok(Metric::PrivilegesRequired(PrivilegesRequired::None)),
      "PR:L" => Ok(Metric::PrivilegesRequired(PrivilegesRequired::Low)),
      "PR:H" => Ok(Metric::PrivilegesRequired(PrivilegesRequired::High)),

      "UI:N" => Ok(Metric::UserInteraction(UserInteraction::None)),
      "UI:P" => Ok(Metric::UserInteraction(UserInteraction::Passive)),
      "UI:A" => Ok(Metric::UserInteraction(UserInteraction::Active)),

      // base 9 = 3*3
      "VC:H" => Ok(Metric::VulnerableSystemConfidentialityImpact(Impact::High)),
      "VC:L" => Ok(Metric::VulnerableSystemConfidentialityImpact(Impact::Low)),
      "VC:N" => Ok(Metric::VulnerableSystemConfidentialityImpact(Impact::None)),

      // base 27 = 3*3*3
      "VI:H" => Ok(Metric::VulnerableSystemIntegrityImpact(Impact::High)),
      "VI:L" => Ok(Metric::VulnerableSystemIntegrityImpact(Impact::Low)),
      "VI:N" => Ok(Metric::VulnerableSystemIntegrityImpact(Impact::None)),

      // base 81 = 3*3*3*3
      "VA:H" => Ok(Metric::VulnerableSystemAvailabilityImpact(Impact::High)),
      "VA:L" => Ok(Metric::VulnerableSystemAvailabilityImpact(Impact::Low)),
      "VA:N" => Ok(Metric::VulnerableSystemAvailabilityImpact(Impact::None)),

      // base 243 = 3*3*3*3*3
      "SC:H" => Ok(Metric::SubsequentSystemConfidentialityImpact(Impact::High)),
      "SC:L" => Ok(Metric::SubsequentSystemConfidentialityImpact(Impact::Low)),
      "SC:N" => Ok(Metric::SubsequentSystemConfidentialityImpact(Impact::None)),

      // base 729 = 3*3*3*3*3*3
      "SI:H" => Ok(Metric::SubsequentSystemIntegrityImpact(Impact::High)),
      "SI:L" => Ok(Metric::SubsequentSystemIntegrityImpact(Impact::Low)),
      "SI:N" => Ok(Metric::SubsequentSystemIntegrityImpact(Impact::None)),

      // base 2187 = 3*3*3*3*3*3*3
      "SA:H" => Ok(Metric::SubsequentSystemAvailabilityImpact(Impact::High)),
      "SA:L" => Ok(Metric::SubsequentSystemAvailabilityImpact(Impact::Low)),
      "SA:N" => Ok(Metric::SubsequentSystemAvailabilityImpact(Impact::None)),

      "E:X" => Ok(Metric::ExploitMaturity(ExploitMaturity::NotDefined)),
      "E:A" => Ok(Metric::ExploitMaturity(ExploitMaturity::Attacked)),
      "E:P" => Ok(Metric::ExploitMaturity(ExploitMaturity::ProofOfConcept)),
      "E:U" => Ok(Metric::ExploitMaturity(ExploitMaturity::Unreported)),

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

      // base 6561 = 3*3*3*3*3*3*3*3
      "MAV:X" => Ok(Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined)),
      "MAV:N" => Ok(Metric::ModifiedAttackVector(ModifiedAttackVector::Network)),
      "MAV:A" => Ok(Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent)),
      "MAV:L" => Ok(Metric::ModifiedAttackVector(ModifiedAttackVector::Local)),
      "MAV:P" => Ok(Metric::ModifiedAttackVector(ModifiedAttackVector::Physical)),

      // base 32805 = 3*3*3*3*3*3*3*3*5
      "MAC:X" => Ok(Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined)),
      "MAC:L" => Ok(Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low)),
      "MAC:H" => Ok(Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High)),

      // base 98415 = 3*3*3*3*3*3*3*3*5*3
      "MAT:X" => Ok(Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::NotDefined)),
      "MAT:N" => Ok(Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::None)),
      "MAT:P" => Ok(Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::Present)),

      "MPR:X" => Ok(Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined)),
      "MPR:N" => Ok(Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None)),
      "MPR:L" => Ok(Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low)),
      "MPR:H" => Ok(Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High)),

      "MUI:X" => Ok(Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined)),
      "MUI:N" => Ok(Metric::ModifiedUserInteraction(ModifiedUserInteraction::None)),
      "MUI:P" => Ok(Metric::ModifiedUserInteraction(ModifiedUserInteraction::Passive)),
      "MUI:A" => Ok(Metric::ModifiedUserInteraction(ModifiedUserInteraction::Active)),

      "MVC:X" => Ok(Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::NotDefined)),
      "MVC:H" => Ok(Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::High)),
      "MVC:L" => Ok(Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::Low)),
      "MVC:N" => Ok(Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::None)),

      "MVI:X" => Ok(Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::NotDefined)),
      "MVI:H" => Ok(Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::High)),
      "MVI:L" => Ok(Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::Low)),
      "MVI:N" => Ok(Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::None)),

      "MVA:X" => Ok(Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::NotDefined)),
      "MVA:H" => Ok(Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::High)),
      "MVA:L" => Ok(Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::Low)),
      "MVA:N" => Ok(Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::None)),

      "MSC:X" => Ok(Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::NotDefined)),
      "MSC:H" => Ok(Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::High)),
      "MSC:L" => Ok(Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::Low)),
      "MSC:N" => Ok(Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::None)),

      // base 295245 = 3*3*3*3*3*3*3*3*5*3*3
      "MSI:X" => Ok(Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::NotDefined)),
      "MSI:H" => Ok(Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::High)),
      "MSI:L" => Ok(Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Low)),
      "MSI:N" => Ok(Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::None)),
      "MSI:S" => Ok(Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Safety)),

      // base 1476225 = 3*3*3*3*3*3*3*3*5*3*3*5
      "MSA:X" => Ok(Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::NotDefined)),
      "MSA:H" => Ok(Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::High)),
      "MSA:L" => Ok(Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Low)),
      "MSA:N" => Ok(Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::None)),
      "MSA:S" => Ok(Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Safety)),

      // base 7381125 = 3*3*3*3*3*3*3*3*5*3*3*5*5
      "S:X" => Ok(Metric::Safety(Safety::NotDefined)),
      "S:P" => Ok(Metric::Safety(Safety::Present)),
      "S:N" => Ok(Metric::Safety(Safety::Negligible)),

      // base 22143375 = 3*3*3*3*3*3*3*3*5*3*3*5*5*3
      "AU:X" => Ok(Metric::Automatable(Automatable::NotDefined)),
      "AU:N" => Ok(Metric::Automatable(Automatable::No)),
      "AU:Y" => Ok(Metric::Automatable(Automatable::Yes)),

      "R:X" => Ok(Metric::Recovery(Recovery::NotDefined)),
      "R:A" => Ok(Metric::Recovery(Recovery::Automatic)),
      "R:U" => Ok(Metric::Recovery(Recovery::User)),
      "R:I" => Ok(Metric::Recovery(Recovery::Irrecoverable)),

      // base 66430125 = 3*3*3*3*3*3*3*5*3*3*3*5*5*3*3
      "V:X" => Ok(Metric::ValueDensity(ValueDensity::NotDefined)),
      "V:D" => Ok(Metric::ValueDensity(ValueDensity::Diffuse)),
      "V:C" => Ok(Metric::ValueDensity(ValueDensity::Concentrated)),

      "RE:X" => Ok(Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::NotDefined)),
      "RE:L" => Ok(Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Low)),
      "RE:M" => Ok(Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Moderate)),
      "RE:H" => Ok(Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::High)),

      // base 199290375 = 3*3*3*3*3*3*3*5*3*3*3*5*5*3*3*3
      "U:X" => Ok(Metric::ProviderUrgency(ProviderUrgency::NotDefined)),
      "U:Red" => Ok(Metric::ProviderUrgency(ProviderUrgency::Red)),
      "U:Amber" => Ok(Metric::ProviderUrgency(ProviderUrgency::Amber)),
      "U:Green" => Ok(Metric::ProviderUrgency(ProviderUrgency::Green)),
      "U:Clear" => Ok(Metric::ProviderUrgency(ProviderUrgency::Clear)),

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

impl From<Metric> for EncodedMetric {
  fn from(metric: Metric) -> EncodedMetric {
    let (bit, val) = match metric {
      Metric::AttackVector(AttackVector::Network) => (0, EncodedVal::Shift(0)), // Network (AV:N)
      Metric::AttackVector(AttackVector::Adjacent) => (0, EncodedVal::Shift(1)), // Adjacent (AV:A)
      Metric::AttackVector(AttackVector::Local) => (0, EncodedVal::Shift(2)), // Local (AV:L)
      Metric::AttackVector(AttackVector::Physical) => (0, EncodedVal::Shift(3)), // Physical (AV:P)

      Metric::AttackComplexity(AttackComplexity::Low) => (1, EncodedVal::Shift(0)), // Low (AC:L)
      Metric::AttackComplexity(AttackComplexity::High) => (1, EncodedVal::Shift(1 << 2)), // High (AC:H)

      Metric::AttackRequirements(AttackRequirements::None) => (2, EncodedVal::Shift(0)), // None (AT:N)
      Metric::AttackRequirements(AttackRequirements::Present) => (2, EncodedVal::Shift(1 << 3)), // Present (AT:P)

      Metric::PrivilegesRequired(PrivilegesRequired::None) => (3, EncodedVal::Arith(0)), // None (PR:N)
      Metric::PrivilegesRequired(PrivilegesRequired::Low) => (3, EncodedVal::Arith(1)), // Low (PR:L)
      Metric::PrivilegesRequired(PrivilegesRequired::High) => (3, EncodedVal::Arith(2)), // High (PR:H)

      // base 3
      Metric::UserInteraction(UserInteraction::None) => (4, EncodedVal::Arith(0)), // None (UI:N)
      Metric::UserInteraction(UserInteraction::Passive) => (4, EncodedVal::Arith(3)), // Passive (UI:P)
      Metric::UserInteraction(UserInteraction::Active) => (4, EncodedVal::Arith(2 * 3)), // Active (UI:A)

      // base 9 = 3*3
      Metric::VulnerableSystemConfidentialityImpact(Impact::High) => (5, EncodedVal::Arith(0)), // High (VC:H)
      Metric::VulnerableSystemConfidentialityImpact(Impact::Low) => (5, EncodedVal::Arith(9)), // Low (VC:L)
      Metric::VulnerableSystemConfidentialityImpact(Impact::None) => (5, EncodedVal::Arith(2 * 9)), // None (VC:N)

      // base 27 = 3*3*3
      Metric::VulnerableSystemIntegrityImpact(Impact::High) => (6, EncodedVal::Arith(0)), // High (VI:H)
      Metric::VulnerableSystemIntegrityImpact(Impact::Low) => (6, EncodedVal::Arith(27)), // Low (VI:L)
      Metric::VulnerableSystemIntegrityImpact(Impact::None) => (6, EncodedVal::Arith(2 * 27)), // None (VI:N)

      // base 81 = 3*3*3*3
      Metric::VulnerableSystemAvailabilityImpact(Impact::High) => (7, EncodedVal::Arith(0)), // High (VA:H)
      Metric::VulnerableSystemAvailabilityImpact(Impact::Low) => (7, EncodedVal::Arith(81)), // Low (VA:L)
      Metric::VulnerableSystemAvailabilityImpact(Impact::None) => (7, EncodedVal::Arith(2 * 81)), // None (VA:N)

      // base 243 = 3*3*3*3*3
      Metric::SubsequentSystemConfidentialityImpact(Impact::High) => (8, EncodedVal::Arith(0)), // High (SC:H)
      Metric::SubsequentSystemConfidentialityImpact(Impact::Low) => (8, EncodedVal::Arith(243)), // Low (SC:L)
      Metric::SubsequentSystemConfidentialityImpact(Impact::None) => (8, EncodedVal::Arith(2 * 243)), // None (SC:N)

      // base 729 = 3*3*3*3*3*3
      Metric::SubsequentSystemIntegrityImpact(Impact::High) => (9, EncodedVal::Arith(0)), // High (SI:H)
      Metric::SubsequentSystemIntegrityImpact(Impact::Low) => (9, EncodedVal::Arith(729)), // Low (SI:L)
      Metric::SubsequentSystemIntegrityImpact(Impact::None) => (9, EncodedVal::Arith(2 * 729)), // None (SI:N)

      // base 2187 = 3*3*3*3*3*3*3
      Metric::SubsequentSystemAvailabilityImpact(Impact::High) => (10, EncodedVal::Arith(0)), // High (SA:H)
      Metric::SubsequentSystemAvailabilityImpact(Impact::Low) => (10, EncodedVal::Arith(2187)), // Low (SA:L)
      Metric::SubsequentSystemAvailabilityImpact(Impact::None) => (10, EncodedVal::Arith(2 * 2187)), // None (SA:N)

      Metric::ExploitMaturity(ExploitMaturity::NotDefined) => (11, EncodedVal::Shift(0 << 4)), // Not Defined (E:X)
      Metric::ExploitMaturity(ExploitMaturity::Attacked) => (11, EncodedVal::Shift(1 << 4)), // Attacked (E:A)
      Metric::ExploitMaturity(ExploitMaturity::ProofOfConcept) => (11, EncodedVal::Shift(2 << 4)), // Proof-of-Concept (E:P)
      Metric::ExploitMaturity(ExploitMaturity::Unreported) => (11, EncodedVal::Shift(3 << 4)), // Unreported (E:U)

      Metric::ConfidentialityRequirement(Requirement::NotDefined) => (12, EncodedVal::Shift(0 << 6)), // Not Defined (CR:X)
      Metric::ConfidentialityRequirement(Requirement::High) => (12, EncodedVal::Shift(1 << 6)), // High (CR:H)
      Metric::ConfidentialityRequirement(Requirement::Medium) => (12, EncodedVal::Shift(2 << 6)), // Medium (CR:M)
      Metric::ConfidentialityRequirement(Requirement::Low) => (12, EncodedVal::Shift(3 << 6)), // Low (CR:L)

      Metric::IntegrityRequirement(Requirement::NotDefined) => (13, EncodedVal::Shift(0 << 8)), // Not Defined (IR:X)
      Metric::IntegrityRequirement(Requirement::High) => (13, EncodedVal::Shift(1 << 8)), // High (IR:H)
      Metric::IntegrityRequirement(Requirement::Medium) => (13, EncodedVal::Shift(2 << 8)), // Medium (IR:M)
      Metric::IntegrityRequirement(Requirement::Low) => (13, EncodedVal::Shift(3 << 8)), // Low (IR:L)

      Metric::AvailabilityRequirement(Requirement::NotDefined) => (14, EncodedVal::Shift(0 << 10)), // Not Defined (AR:X)
      Metric::AvailabilityRequirement(Requirement::High) => (14, EncodedVal::Shift(1 << 10)), // High (AR:H)
      Metric::AvailabilityRequirement(Requirement::Medium) => (14, EncodedVal::Shift(2 << 10)), // Medium (AR:M)
      Metric::AvailabilityRequirement(Requirement::Low) => (14, EncodedVal::Shift(3 << 10)), // Low (AR:L)

      // base 6561 = 3*3*3*3*3*3*3*3
      Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined) => (15, EncodedVal::Arith(0)), // Not Defined (MAV:X)
      Metric::ModifiedAttackVector(ModifiedAttackVector::Network) => (15, EncodedVal::Arith(6561)), // Network (MAV:N)
      Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent) => (15, EncodedVal::Arith(2 * 6561)), // Adjacent (MAV:A)
      Metric::ModifiedAttackVector(ModifiedAttackVector::Local) => (15, EncodedVal::Arith(3 * 6561)), // Local (MAV:L)
      Metric::ModifiedAttackVector(ModifiedAttackVector::Physical) => (15, EncodedVal::Arith(4 * 6561)), // Physical (MAV:P)

      // base 32805 = 3*3*3*3*3*3*3*3*5
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined) => (16, EncodedVal::Arith(0)), // Not Defined (MAC:X)
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low) => (16, EncodedVal::Arith(32805)), // Low (MAC:L)
      Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High) => (16, EncodedVal::Arith(2 * 32805)), // High (MAC:H)

      // base 98415 = 3*3*3*3*3*3*3*3*5*3
      Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::NotDefined) => (17, EncodedVal::Arith(0)), // Not Defined (MAT:X)
      Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::None) => (17, EncodedVal::Arith(98415)), // None (MAT:N)
      Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::Present) => (17, EncodedVal::Arith(2 * 98415)), // Present (MAT:P)

      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined) => (18, EncodedVal::Shift(0 << 12)), // Not Defined (MPR:X)
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None) => (18, EncodedVal::Shift(1 << 12)), // None (MPR:N)
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low) => (18, EncodedVal::Shift(2 << 12)), // Low (MPR:L)
      Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High) => (18, EncodedVal::Shift(3 << 12)), // High (MPR:H)

      Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined) => (19, EncodedVal::Shift(0 << 14)), // Not Defined (MUI:X)
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::None) => (19, EncodedVal::Shift(1 << 14)), // None (MUI:N)
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::Passive) => (19, EncodedVal::Shift(2 << 14)), // Passive (MUI:P)
      Metric::ModifiedUserInteraction(ModifiedUserInteraction::Active) => (19, EncodedVal::Shift(3 << 14)), // Active (MUI:A)

      Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::NotDefined) => (20, EncodedVal::Shift(0 << 16)), // Not Defined (MVC:X)
      Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::High) => (20, EncodedVal::Shift(1 << 16)), // High (MVC:H)
      Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::Low) => (20, EncodedVal::Shift(2 << 16)), // Low (MVC:L)
      Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::None) => (20, EncodedVal::Shift(3 << 16)), // None (MVC:N)

      Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::NotDefined) => (21, EncodedVal::Shift(0 << 18)), // Not Defined (MVI:X)
      Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::High) => (21, EncodedVal::Shift(1 << 18)), // High (MVI:H)
      Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::Low) => (21, EncodedVal::Shift(2 << 18)), // Low (MVI:L)
      Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::None) => (21, EncodedVal::Shift(3 << 18)), // None (MVI:N)

      Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::NotDefined) => (22, EncodedVal::Shift(0 << 20)), // Not Defined (MVA:X)
      Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::High) => (22, EncodedVal::Shift(1 << 20)), // High (MVA:H)
      Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::Low) => (22, EncodedVal::Shift(2 << 20)), // Low (MVA:L)
      Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::None) => (22, EncodedVal::Shift(3 << 20)), // None (MVA:N)

      Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::NotDefined) => (23, EncodedVal::Shift(0 << 22)), // Not Defined (MSC:X)
      Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::High) => (23, EncodedVal::Shift(1 << 22)), // High (MSC:H)
      Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::Low) => (23, EncodedVal::Shift(2 << 22)), // Low (MSC:L)
      Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::None) => (23, EncodedVal::Shift(3 << 22)), // None (MSC:N)

      // base 295245 = 3*3*3*3*3*3*3*3*5*3*3
      Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::NotDefined) => (24, EncodedVal::Arith(0)), // Not Defined (MSI:X)
      Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::High) => (24, EncodedVal::Arith(295245)), // High (MSI:H)
      Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Low) => (24, EncodedVal::Arith(2 * 295245)), // Low (MSI:L)
      Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::None) => (24, EncodedVal::Arith(3 * 295245)), // None (MSI:N)
      Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Safety) => (24, EncodedVal::Arith(4 * 295245)), // Safety (MSI:S)

      // base 1476225 = 3*3*3*3*3*3*3*3*5*3*3*5
      Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::NotDefined) => (25, EncodedVal::Arith(0)), // Not Defined (MSA:X)
      Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::High) => (25, EncodedVal::Arith(1476225)), // High (MSA:H)
      Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Low) => (25, EncodedVal::Arith(2 * 1476225)), // Low (MSA:L)
      Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::None) => (25, EncodedVal::Arith(3 * 1476225)), // None (MSA:N)
      Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Safety) => (25, EncodedVal::Arith(4 * 1476225)), // Safety (MSA:S)

      // base 7381125 = 3*3*3*3*3*3*3*3*5*3*3*5*5
      Metric::Safety(Safety::NotDefined) => (26, EncodedVal::Arith(0)), // Not Defined (S:X)
      Metric::Safety(Safety::Present) => (26, EncodedVal::Arith(7381125)), // Present (S:P)
      Metric::Safety(Safety::Negligible) => (26, EncodedVal::Arith(2 * 7381125)), // Negligible (S:N)

      // base 22143375 = 3*3*3*3*3*3*3*3*5*3*3*5*5*3
      Metric::Automatable(Automatable::NotDefined) => (27, EncodedVal::Arith(0)), // Not Defined (AU:X)
      Metric::Automatable(Automatable::No) => (27, EncodedVal::Arith(22143375)), // No (AU:N)
      Metric::Automatable(Automatable::Yes) => (27, EncodedVal::Arith(2 * 22143375)), // Yes (AU:Y)

      Metric::Recovery(Recovery::NotDefined) => (28, EncodedVal::Shift(0 << 24)), // Not Defined (R:X)
      Metric::Recovery(Recovery::Automatic) => (28, EncodedVal::Shift(1 << 24)), // Automatic (R:A)
      Metric::Recovery(Recovery::User) => (28, EncodedVal::Shift(2 << 24)), // User (R:U)
      Metric::Recovery(Recovery::Irrecoverable) => (28, EncodedVal::Shift(3 << 24)), // Irrecoverable (R:I)

      // base 66430125 = 3*3*3*3*3*3*3*5*3*3*3*5*5*3*3
      Metric::ValueDensity(ValueDensity::NotDefined) => (29, EncodedVal::Arith(0)), // Not Defined (X)
      Metric::ValueDensity(ValueDensity::Diffuse) => (29, EncodedVal::Arith(66430125)), // Diffuse (D)
      Metric::ValueDensity(ValueDensity::Concentrated) => (29, EncodedVal::Arith(2 * 66430125)), // Concentrated (C)

      Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::NotDefined) => (30, EncodedVal::Shift(0 << 26)), // Not Defined (RE:X)
      Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Low) => (30, EncodedVal::Shift(1 << 26)), // Low (RE:L)
      Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Moderate) => (30, EncodedVal::Shift(2 << 26)), // Moderate (RE:M)
      Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::High) => (30, EncodedVal::Shift(3 << 26)), // High (RE:H)

      // base 199290375 = 3*3*3*3*3*3*3*5*3*3*3*5*5*3*3*3
      Metric::ProviderUrgency(ProviderUrgency::NotDefined) => (31, EncodedVal::Arith(0)), // Not Defined (U:X)
      Metric::ProviderUrgency(ProviderUrgency::Red) => (31, EncodedVal::Arith(199290375)), // U:Red
      Metric::ProviderUrgency(ProviderUrgency::Amber) => (31, EncodedVal::Arith(2 * 199290375)), // U:Amber
      Metric::ProviderUrgency(ProviderUrgency::Green) => (31, EncodedVal::Arith(3 * 199290375)), // U:Green
      Metric::ProviderUrgency(ProviderUrgency::Clear) => (31, EncodedVal::Arith(4 * 199290375)), // U:Clear
    };

    EncodedMetric { bit: 1 << bit, val }
  }
}

// Internal array of metrics.
//
// Used by the following methods to decode metric values from a
// `u64`: `Vector::get()`, `Vector::fmt()`, and
// `VectorIterator::next()`.
const METRICS: [Metric; 115] = [
  Metric::AttackVector(AttackVector::Network), // Network (AV:N)
  Metric::AttackVector(AttackVector::Adjacent), // Adjacent (AV:A)
  Metric::AttackVector(AttackVector::Local), // Local (AV:L)
  Metric::AttackVector(AttackVector::Physical), // Physical (AV:P)

  Metric::AttackComplexity(AttackComplexity::Low), // Low (AC:L)
  Metric::AttackComplexity(AttackComplexity::High), // High (AC:H)

  Metric::AttackRequirements(AttackRequirements::None), // None (AT:N)
  Metric::AttackRequirements(AttackRequirements::Present), // Present (AT:P)

  Metric::PrivilegesRequired(PrivilegesRequired::None), // None (PR:N)
  Metric::PrivilegesRequired(PrivilegesRequired::Low), // Low (PR:L)
  Metric::PrivilegesRequired(PrivilegesRequired::High), // High (PR:H)

  Metric::UserInteraction(UserInteraction::None), // None (UI:N)
  Metric::UserInteraction(UserInteraction::Passive), // Passive (UI:P)
  Metric::UserInteraction(UserInteraction::Active), // Active (UI:A)

  Metric::VulnerableSystemConfidentialityImpact(Impact::High), // High (VC:H)
  Metric::VulnerableSystemConfidentialityImpact(Impact::Low), // Low (VC:L)
  Metric::VulnerableSystemConfidentialityImpact(Impact::None), // None (VC:N)

  Metric::VulnerableSystemIntegrityImpact(Impact::High), // High (VI:H)
  Metric::VulnerableSystemIntegrityImpact(Impact::Low), // Low (VI:L)
  Metric::VulnerableSystemIntegrityImpact(Impact::None), // None (VI:N)

  Metric::VulnerableSystemAvailabilityImpact(Impact::High), // High (VA:H)
  Metric::VulnerableSystemAvailabilityImpact(Impact::Low), // Low (VA:L)
  Metric::VulnerableSystemAvailabilityImpact(Impact::None), // None (VA:N)

  Metric::SubsequentSystemConfidentialityImpact(Impact::High), // High (SC:H)
  Metric::SubsequentSystemConfidentialityImpact(Impact::Low), // Low (SC:L)
  Metric::SubsequentSystemConfidentialityImpact(Impact::None), // None (SC:N)

  Metric::SubsequentSystemIntegrityImpact(Impact::High), // High (SI:H)
  Metric::SubsequentSystemIntegrityImpact(Impact::Low), // Low (SI:L)
  Metric::SubsequentSystemIntegrityImpact(Impact::None), // None (SI:N)

  Metric::SubsequentSystemAvailabilityImpact(Impact::High), // High (SA:H)
  Metric::SubsequentSystemAvailabilityImpact(Impact::Low), // Low (SA:L)
  Metric::SubsequentSystemAvailabilityImpact(Impact::None), // None (SA:N)

  Metric::ExploitMaturity(ExploitMaturity::NotDefined), // Not Defined (E:X)
  Metric::ExploitMaturity(ExploitMaturity::Attacked), // Attacked (E:A)
  Metric::ExploitMaturity(ExploitMaturity::ProofOfConcept), // Proof-of-Concept (E:P)
  Metric::ExploitMaturity(ExploitMaturity::Unreported), // Unreported (E:U)

  Metric::ConfidentialityRequirement(Requirement::NotDefined), // Not Defined (CR:X)
  Metric::ConfidentialityRequirement(Requirement::High), // High (CR:H)
  Metric::ConfidentialityRequirement(Requirement::Medium), // Medium (CR:M)
  Metric::ConfidentialityRequirement(Requirement::Low), // Low (CR:L)

  Metric::IntegrityRequirement(Requirement::NotDefined), // Not Defined (IR:X)
  Metric::IntegrityRequirement(Requirement::High), // High (IR:H)
  Metric::IntegrityRequirement(Requirement::Medium), // Medium (IR:M)
  Metric::IntegrityRequirement(Requirement::Low), // Low (IR:L)

  Metric::AvailabilityRequirement(Requirement::NotDefined), // Not Defined (AR:X)
  Metric::AvailabilityRequirement(Requirement::High), // High (AR:H)
  Metric::AvailabilityRequirement(Requirement::Medium), // Medium (AR:M)
  Metric::AvailabilityRequirement(Requirement::Low), // Low (AR:L)

  Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined), // Not Defined (MAV:X)
  Metric::ModifiedAttackVector(ModifiedAttackVector::Network), // Network (MAV:N)
  Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent), // Adjacent (MAV:A)
  Metric::ModifiedAttackVector(ModifiedAttackVector::Local), // Local (MAV:L)
  Metric::ModifiedAttackVector(ModifiedAttackVector::Physical), // Physical (MAV:P)

  Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined), // Not Defined (MAC:X)
  Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low), // Low (MAC:L)
  Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High), // High (MAC:H)

  Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::NotDefined), // Not Defined (MAT:X)
  Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::None), // None (MAT:N)
  Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::Present), // Present (MAT:P)

  Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined), // Not Defined (MPR:X)
  Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None), // None (MPR:N)
  Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low), // Low (MPR:L)
  Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High), // High (MPR:H)

  Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined), // Not Defined (MUI:X)
  Metric::ModifiedUserInteraction(ModifiedUserInteraction::None), // None (MUI:N)
  Metric::ModifiedUserInteraction(ModifiedUserInteraction::Passive), // Passive (MUI:P)
  Metric::ModifiedUserInteraction(ModifiedUserInteraction::Active), // Active (MUI:A)

  Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::NotDefined), // Not Defined (MVC:X)
  Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::High), // High (MVC:H)
  Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::Low), // Low (MVC:L)
  Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::None), // None (MVC:N)

  Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::NotDefined), // Not Defined (MVI:X)
  Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::High), // High (MVI:H)
  Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::Low), // Low (MVI:L)
  Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::None), // None (MVI:N)

  Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::NotDefined), // Not Defined (MVA:X)
  Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::High), // High (MVA:H)
  Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::Low), // Low (MVA:L)
  Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::None), // None (MVA:N)

  Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::NotDefined), // Not Defined (MSC:X)
  Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::High), // High (MSC:H)
  Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::Low), // Low (MSC:L)
  Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::None), // None (MSC:N)

  Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::NotDefined), // Not Defined (MSI:X)
  Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::High), // High (MSI:H)
  Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Low), // Low (MSI:L)
  Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::None), // None (MSI:N)
  Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Safety), // Safety (MSI:S)

  Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::NotDefined), // Not Defined (MSA:X)
  Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::High), // High (MSA:H)
  Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Low), // Low (MSA:L)
  Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::None), // None (MSA:N)
  Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Safety), // Safety (MSA:S)

  Metric::Safety(Safety::NotDefined), // Not Defined (S:X)
  Metric::Safety(Safety::Present), // Present (S:P)
  Metric::Safety(Safety::Negligible), // Negligible (S:N)

  Metric::Automatable(Automatable::NotDefined), // Not Defined (AU:X)
  Metric::Automatable(Automatable::No), // No (AU:N)
  Metric::Automatable(Automatable::Yes), // Yes (AU:Y)

  Metric::Recovery(Recovery::NotDefined), // Not Defined (R:X)
  Metric::Recovery(Recovery::Automatic), // Automatic (R:A)
  Metric::Recovery(Recovery::User), // User (R:U)
  Metric::Recovery(Recovery::Irrecoverable), // Irrecoverable (R:I)

  Metric::ValueDensity(ValueDensity::NotDefined), // Not Defined (X)
  Metric::ValueDensity(ValueDensity::Diffuse), // Diffuse (D)
  Metric::ValueDensity(ValueDensity::Concentrated), // Concentrated (C)

  Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::NotDefined), // Not Defined (RE:X)
  Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Low), // Low (RE:L)
  Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Moderate), // Moderate (RE:M)
  Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::High), // High (RE:H)

  Metric::ProviderUrgency(ProviderUrgency::NotDefined), // Not Defined (U:X)
  Metric::ProviderUrgency(ProviderUrgency::Red), // U:Red
  Metric::ProviderUrgency(ProviderUrgency::Amber), // U:Amber
  Metric::ProviderUrgency(ProviderUrgency::Green), // U:Green
  Metric::ProviderUrgency(ProviderUrgency::Clear), // U:Clear
];

// Data used to decode metrics from a u64-encoded vector.
enum Decode {
  Shift(Name, usize, (usize, usize)), // name, shift, values range
  Arith(Name, usize, (usize, usize)), // name, denominator, values range
}

impl From<Name> for Decode {
  fn from(name: Name) -> Decode {
    // note: copied from `DECODES` above
    match name {
       Name::AttackVector => Decode::Shift(Name::AttackVector, 0, (0, 4)),
       Name::AttackComplexity => Decode::Shift(Name::AttackComplexity, 2, (4, 6)),
       Name::AttackRequirements => Decode::Shift(Name::AttackRequirements, 3, (6, 8)),
       Name::PrivilegesRequired => Decode::Arith(Name::PrivilegesRequired, 1, (8, 11)),
       Name::UserInteraction => Decode::Arith(Name::UserInteraction, 3, (11, 14)),
       Name::VulnerableSystemConfidentialityImpact => Decode::Arith(Name::VulnerableSystemConfidentialityImpact, 3*3, (14, 17)),
       Name::VulnerableSystemIntegrityImpact => Decode::Arith(Name::VulnerableSystemIntegrityImpact, 3*3*3, (17, 20)),
       Name::VulnerableSystemAvailabilityImpact => Decode::Arith(Name::VulnerableSystemAvailabilityImpact, 3*3*3*3, (20, 23)),
       Name::SubsequentSystemConfidentialityImpact => Decode::Arith(Name::SubsequentSystemConfidentialityImpact, 3*3*3*3*3, (23, 26)),
       Name::SubsequentSystemIntegrityImpact => Decode::Arith(Name::SubsequentSystemIntegrityImpact, 3*3*3*3*3*3, (26, 29)),
       Name::SubsequentSystemAvailabilityImpact => Decode::Arith(Name::SubsequentSystemAvailabilityImpact, 3*3*3*3*3*3*3, (29, 32)),
       Name::ExploitMaturity => Decode::Shift(Name::ExploitMaturity, 4, (32, 36)),
       Name::ConfidentialityRequirement => Decode::Shift(Name::ConfidentialityRequirement, 6, (36, 40)),
       Name::IntegrityRequirement => Decode::Shift(Name::IntegrityRequirement, 8, (40, 44)),
       Name::AvailabilityRequirement => Decode::Shift(Name::AvailabilityRequirement, 10, (44, 48)),
       Name::ModifiedAttackVector => Decode::Arith(Name::ModifiedAttackVector, 3*3*3*3*3*3*3*3, (48, 53)),
       Name::ModifiedAttackComplexity => Decode::Arith(Name::ModifiedAttackComplexity, 3*3*3*3*3*3*3*3*5, (53, 56)),
       Name::ModifiedAttackRequirements => Decode::Arith(Name::ModifiedAttackRequirements, 3*3*3*3*3*3*3*3*5*3, (56, 59)),
       Name::ModifiedPrivilegesRequired => Decode::Shift(Name::ModifiedPrivilegesRequired, 12, (59, 63)),
       Name::ModifiedUserInteraction => Decode::Shift(Name::ModifiedUserInteraction, 14, (63, 67)),
       Name::ModifiedVulnerableSystemConfidentiality => Decode::Shift(Name::ModifiedVulnerableSystemConfidentiality, 16, (67, 71)),
       Name::ModifiedVulnerableSystemIntegrity => Decode::Shift(Name::ModifiedVulnerableSystemIntegrity, 18, (71, 75)),
       Name::ModifiedVulnerableSystemAvailability => Decode::Shift(Name::ModifiedVulnerableSystemAvailability, 20, (75, 79)),
       Name::ModifiedSubsequentSystemConfidentiality => Decode::Shift(Name::ModifiedSubsequentSystemConfidentiality, 22, (79, 83)),
       Name::ModifiedSubsequentSystemIntegrity => Decode::Arith(Name::ModifiedSubsequentSystemIntegrity, 3*3*3*3*3*3*3*3*5*3*3, (83, 88)),
       Name::ModifiedSubsequentSystemAvailability => Decode::Arith(Name::ModifiedSubsequentSystemAvailability, 3*3*3*3*3*3*3*3*5*3*3*5, (88, 93)),
       Name::Safety => Decode::Arith(Name::Safety, 3*3*3*3*3*3*3*3*5*3*3*5*5, (93, 96)),
       Name::Automatable => Decode::Arith(Name::Automatable, 3*3*3*3*3*3*3*3*5*3*3*5*5*3, (96, 99)),
       Name::Recovery => Decode::Shift(Name::Recovery, 24, (99, 103)),
       Name::ValueDensity => Decode::Arith(Name::ValueDensity, 3*3*3*3*3*3*3*3*5*3*3*5*5*3*3, (103, 106)),
       Name::VulnerabilityResponseEffort => Decode::Shift(Name::VulnerabilityResponseEffort, 26, (106, 110)),
       Name::ProviderUrgency => Decode::Arith(Name::ProviderUrgency, 3*3*3*3*3*3*3*3*5*3*3*5*5*3*3*3, (110, 115)),
    }
  }
}

// Metric decodes.
//
// Used by `Vector::fmt()` and `VectorIterator::next()` to decode a
// u64-encoded vector into individual metrics in canonical order.
//
// Sorted in order specified in Table 23 in [Section 7 of the CVSS v4.0
// specification][vector-string].
//
// [vector-string]: https://www.first.org/cvss/v4-0/specification-document#Vector-String
//   "CVSS v4.0 Specification, Section 7: Vector String"
const DECODES: [Decode; 32] = [
  Decode::Shift(Name::AttackVector, 0, (0, 4)),
  Decode::Shift(Name::AttackComplexity, 2, (4, 6)),
  Decode::Shift(Name::AttackRequirements, 3, (6, 8)),
  Decode::Arith(Name::PrivilegesRequired, 1, (8, 11)),
  Decode::Arith(Name::UserInteraction, 3, (11, 14)),
  Decode::Arith(Name::VulnerableSystemConfidentialityImpact, 3*3, (14, 17)),
  Decode::Arith(Name::VulnerableSystemIntegrityImpact, 3*3*3, (17, 20)),
  Decode::Arith(Name::VulnerableSystemAvailabilityImpact, 3*3*3*3, (20, 23)),
  Decode::Arith(Name::SubsequentSystemConfidentialityImpact, 3*3*3*3*3, (23, 26)),
  Decode::Arith(Name::SubsequentSystemIntegrityImpact, 3*3*3*3*3*3, (26, 29)),
  Decode::Arith(Name::SubsequentSystemAvailabilityImpact, 3*3*3*3*3*3*3, (29, 32)),
  Decode::Shift(Name::ExploitMaturity, 4, (32, 36)),
  Decode::Shift(Name::ConfidentialityRequirement, 6, (36, 40)),
  Decode::Shift(Name::IntegrityRequirement, 8, (40, 44)),
  Decode::Shift(Name::AvailabilityRequirement, 10, (44, 48)),
  Decode::Arith(Name::ModifiedAttackVector, 3*3*3*3*3*3*3*3, (48, 53)),
  Decode::Arith(Name::ModifiedAttackComplexity, 3*3*3*3*3*3*3*3*5, (53, 56)),
  Decode::Arith(Name::ModifiedAttackRequirements, 3*3*3*3*3*3*3*3*5*3, (56, 59)),
  Decode::Shift(Name::ModifiedPrivilegesRequired, 12, (59, 63)),
  Decode::Shift(Name::ModifiedUserInteraction, 14, (63, 67)),
  Decode::Shift(Name::ModifiedVulnerableSystemConfidentiality, 16, (67, 71)),
  Decode::Shift(Name::ModifiedVulnerableSystemIntegrity, 18, (71, 75)),
  Decode::Shift(Name::ModifiedVulnerableSystemAvailability, 20, (75, 79)),
  Decode::Shift(Name::ModifiedSubsequentSystemConfidentiality, 22, (79, 83)),
  Decode::Arith(Name::ModifiedSubsequentSystemIntegrity, 3*3*3*3*3*3*3*3*5*3*3, (83, 88)),
  Decode::Arith(Name::ModifiedSubsequentSystemAvailability, 3*3*3*3*3*3*3*3*5*3*3*5, (88, 93)),
  Decode::Arith(Name::Safety, 3*3*3*3*3*3*3*3*5*3*3*5*5, (93, 96)),
  Decode::Arith(Name::Automatable, 3*3*3*3*3*3*3*3*5*3*3*5*5*3, (96, 99)),
  Decode::Shift(Name::Recovery, 24, (99, 103)),
  Decode::Arith(Name::ValueDensity, 3*3*3*3*3*3*3*3*5*3*3*5*5*3*3, (103, 106)),
  Decode::Shift(Name::VulnerabilityResponseEffort, 26, (106, 110)),
  Decode::Arith(Name::ProviderUrgency, 3*3*3*3*3*3*3*3*5*3*3*5*5*3*3*3, (110, 115)),
];

/// [`Vector`][] iterator.
///
/// # Description
///
/// Used to iterate over the defined [`Metric`s][Metric] of a
/// [`Vector`][] in the order specified in Table 23 in [Section 7 of
/// the CVSS v4.0 specification][vector-string].
///
/// Created by [`Vector::into_iter()`][].
///
/// # Examples
///
/// Iterate over [`Vector`][] and appending each [`Metric`][]
/// to a [`std::vec::Vec`][]:
///
/// ```
/// # use polycvss::{Err, v4::{AttackVector, AttackComplexity, AttackRequirements, PrivilegesRequired, UserInteraction, Impact, Metric, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse string as vector
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
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
///   Metric::AttackRequirements(AttackRequirements::None),
///   Metric::PrivilegesRequired(PrivilegesRequired::None),
///   Metric::UserInteraction(UserInteraction::None),
///   Metric::VulnerableSystemConfidentialityImpact(Impact::High),
///   Metric::VulnerableSystemIntegrityImpact(Impact::High),
///   Metric::VulnerableSystemAvailabilityImpact(Impact::High),
///   Metric::SubsequentSystemConfidentialityImpact(Impact::High),
///   Metric::SubsequentSystemIntegrityImpact(Impact::High),
///   Metric::SubsequentSystemAvailabilityImpact(Impact::High),
/// ));
/// # Ok(())
/// # }
/// ```
///
/// Create a explicit iterator over [`Vector`][] and get the first
/// [`Metric`][]:
///
/// ```
/// # use polycvss::{Err, v4::{AttackVector, Metric, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse string as vector
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
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
/// [vector-string]: https://www.first.org/cvss/v4-0/specification-document#Vector-String
///   "CVSS v4.0 Specification, Section 7: Vector String"
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

      let (found, val) = match &DECODES[self.pos - 1] {
        Decode::Shift(name, shift, range) => {
          let vals = &METRICS[range.0..range.1];
          let ofs = ((self.val >> shift) as usize) & (vals.len() - 1);
          (name.is_mandatory() || ofs > 0, vals[ofs])
        },
        Decode::Arith(name, denom, range) => {
          let vals = &METRICS[range.0..range.1];
          let ofs = ((((self.val & VAL_MASK) >> 28) as usize)/(denom)) % vals.len();
          (name.is_mandatory() || ofs > 0, vals[ofs])
        },
      };

      if found {
        return Some(val) // found defined metric, return it
      }

      self.pos += 1; // step
    }
  }
}

/// [CVSS v4][cvss40] vector.
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
/// # use polycvss::{Err, v4::{Vector}};
/// # fn main() -> Result<(), Err> {
/// // CVSS v4.0 vector string
/// let s = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";
///
/// // parse string as Vector
/// let v: Vector = s.parse()?;
/// # Ok(())
/// # }
/// ```
///
/// Iterate over [`Metric`s][Metric] in a [`Vector`][]:
///
/// ```
/// # use polycvss::{Err, v4::Vector};
/// # fn main() -> Result<(), Err> {
/// // parse vector string
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
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
/// # use polycvss::{Err, v4::{AttackVector, Vector, Metric, Name}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
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
/// # use polycvss::{Err, v4::Vector};
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
/// [`Vector`][] back to a string:
///
/// ```
/// # use polycvss::{Err, v4::Vector};
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
/// Verify that a vector is the same size as a `u64`:
///
/// ```
/// # use polycvss::v4::Vector;
/// # fn main() {
/// assert_eq!(size_of::<Vector>(), size_of::<u64>());
/// # }
/// ```
///
/// # Internal Representation
///
/// A CVSS v4 [`Vector`][] is represented internally as a [bit
/// field][bit-field] within a [`u64`][].  Metric values are stored in
/// the lower 59 bits (bits `0..59`) and the CVSS version is stored in
/// the in the upper 4 bits (bits `60..64`):
///
/// | Bit Range | Description                          |
/// | --------- | ------------------------------------ |
/// | `0..28`   | Metrics with 2 or 4 possible values. |
/// | `28..59`  | Metrics with 3 or 5 possible values. |
/// | `59..60`  | 1 unused bit.                        |
/// | `60..64`  | CVSS version (4.0).                  |
///
/// - Metrics with 2 or 4 possible values are stored in the lower 28
///   bits (bits `0..28`).  The value of metrics with 2 possible values
///   are represented as 1 bit.  The value of metrics with 4 possible
///   values are represented as 2 bits.
/// - Metrics with 3 or 5 possible values are encoded in the next 30
///   bits (bits `28..59`).  The value of these metrics are encoded as
///   multiples of a base consisting of powers of 3 and 5.
///
/// [cvss40]: https://www.first.org/cvss/v4-0/specification-document
///   "CVSS v4.0 Specification"
/// [bit-field]: https://en.wikipedia.org/wiki/Bit_field
///   "Bit field (Wikipedia)"
/// [vector-string]: https://www.first.org/cvss/v4-0/specification-document#Vector-String
///   "CVSS v4.0 Specification, Section 7: Vector String"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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
  /// # use polycvss::{Err, v4::{AttackVector, Vector, Metric, Name}};
  /// # fn main() -> Result<(), Err> {
  /// // parse vector string
  /// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
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
  /// # use polycvss::{Err, v4::{ModifiedAttackVector, Vector, Metric, Name}};
  /// # fn main() -> Result<(), Err> {
  /// // parse vector string
  /// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse()?;
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
    match Decode::from(name) {
      Decode::Shift(_, shift, range) => {
        let vals = &METRICS[range.0..range.1];
        let ofs = ((self.0 >> shift) as usize) & (vals.len() - 1);
        vals[ofs]
      },
      Decode::Arith(_, denom, range) => {
        let vals = &METRICS[range.0..range.1];
        let ofs = ((((self.0 & VAL_MASK) >> 28) as usize)/(denom)) % vals.len();
        vals[ofs]
      },
    }
  }
}

impl IntoIterator for Vector {
  type Item = Metric;
  type IntoIter = VectorIterator;

  // Create iterator from vector.
  fn into_iter(self) -> Self::IntoIter {
    Self::IntoIter { pos: 0, val: self.0 }
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
    Scores::from(vec).score
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
    if &s[0..9] != "CVSS:4.0/" {
      return Err(Err::Prefix);
    }

    // split into metrics, then encode as u64
    let mut val = 0; // encoded PoT metrics
    let mut acc = 0; // encoded non-PoT metrics
    let mut seen: u32 = 0; // seen names
    for s in s[9..].split('/') {
      let c = EncodedMetric::from(s.parse::<Metric>()?); // parse metric

      // check for duplicate name
      if seen & c.bit != 0 {
        return Err(Err::DuplicateName);
      }
      seen |= c.bit; // mark name as seen

      match c.val {
        EncodedVal::Shift(v) => val |= v, // encode PoT value
        EncodedVal::Arith(v) => acc += v, // encode non-PoT value
      }
    }

    // check for missing mandatory metrics
    if seen & 0x7ff != 0x7ff {
      return Err(Err::MissingMandatoryMetrics);
    }

    // return encoded vector
    Ok(Vector(u64::from(Version::V40) | (acc << 28) | val))
  }
}

impl TryFrom<String> for Vector {
  type Error = Err;

  fn try_from(s: String) -> Result<Self, Self::Error> {
    s.parse::<Vector>()
  }
}

impl std::fmt::Display for Vector {
  // Format CVSSv4.0 vector as a string.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    // write prefix
    write!(f, "CVSS:4.0")?;

    // write metrics
    for decode in DECODES {
      let (found, val) = match decode {
        Decode::Shift(name, shift, range) => {
          let vals = &METRICS[range.0..range.1];
          let ofs = ((self.0 >> shift) as usize) & (vals.len() - 1);
          (name.is_mandatory() || ofs > 0, vals[ofs])
        },
        Decode::Arith(name, denom, range) => {
          let vals = &METRICS[range.0..range.1];
          let ofs = ((((self.0 & VAL_MASK) >> 28) as usize)/(denom)) % vals.len();
          (name.is_mandatory() || ofs > 0, vals[ofs])
        },
      };

      if found {
        write!(f, "/{val}")?;
      }
    }

    Ok(())
  }
}

/// [CVSS v4][doc] effective vector metric values.
///
/// Used to calculate scores in [`MacroVector`][].
#[derive(Clone,Debug,PartialEq,Eq)]
struct Values {
  /// Effective Attack Vector (`AV`) metric value.
  av: AttackVector,

  /// Effective Attack Complexity (`AC`) metric value.
  ac: AttackComplexity,

  /// Effective Attack Requirements (`AT`) metric value.
  at: AttackRequirements,

  /// Effective Privileges Required (`PR`) metric value.
  pr: PrivilegesRequired,

  /// Effective User Interaction (`UI`) metric value.
  ui: UserInteraction,

  /// Effective Vulnerable System Confidentiality Impact (`VC`) metric value.
  vc: Impact,

  /// Effective Vulnerable System Integrity Impact (`VI`) metric value.
  vi: Impact,

  /// Effective Vulnerable System Availability Impact (`VA`) metric value.
  va: Impact,

  /// Effective Subsequent System Confidentiality Impact (`SC`) metric value.
  sc: Impact,

  /// Effective Subsequent System Integrity Impact (`SI`) metric value.
  si: SubsequentImpact,

  /// Effective Subsequent System Availability Impact (`SA`) metric value.
  sa: SubsequentImpact,

  /// Confidentiality Requirement (`CR`) metric value.
  cr: Requirement,

  /// Integrity Requirement (`IR`) metric value.
  ir: Requirement,

  /// Availability Requirement (`AR`) metric value.
  ar: Requirement,

  /// Exploit Maturity (`E`) metric value.
  e: ExploitMaturity,
}

impl From<Vector> for Values {
  fn from(vec: Vector) -> Values {
    Values {
      av: match (vec.get(Name::ModifiedAttackVector), vec.get(Name::AttackVector)) {
        (Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined), Metric::AttackVector(av)) => av,
        (Metric::ModifiedAttackVector(ModifiedAttackVector::Network), _) => AttackVector::Network,
        (Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent), _) => AttackVector::Adjacent,
        (Metric::ModifiedAttackVector(ModifiedAttackVector::Local), _) => AttackVector::Local,
        (Metric::ModifiedAttackVector(ModifiedAttackVector::Physical), _) => AttackVector::Physical,
        _ => unreachable!(),
      },

      ac: match (vec.get(Name::ModifiedAttackComplexity), vec.get(Name::AttackComplexity)) {
        (Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined), Metric::AttackComplexity(ac)) => ac,
        (Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low), _) => AttackComplexity::Low,
        (Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High), _) => AttackComplexity::High,
        _ => unreachable!(),
      },

      at: match (vec.get(Name::ModifiedAttackRequirements), vec.get(Name::AttackRequirements)) {
        (Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::NotDefined), Metric::AttackRequirements(at)) => at,
        (Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::None), _) => AttackRequirements::None,
        (Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::Present), _) => AttackRequirements::Present,
        _ => unreachable!(),
      },

      pr: match (vec.get(Name::ModifiedPrivilegesRequired), vec.get(Name::PrivilegesRequired)) {
        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined), Metric::PrivilegesRequired(pr)) => pr,
        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None), _) => PrivilegesRequired::None,
        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low), _) => PrivilegesRequired::Low,
        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High), _) => PrivilegesRequired::High,
        _ => unreachable!(),
      },

      ui: match (vec.get(Name::ModifiedUserInteraction), vec.get(Name::UserInteraction)) {
        (Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined), Metric::UserInteraction(ui)) => ui,
        (Metric::ModifiedUserInteraction(ModifiedUserInteraction::None), _) => UserInteraction::None,
        (Metric::ModifiedUserInteraction(ModifiedUserInteraction::Passive), _) => UserInteraction::Passive,
        (Metric::ModifiedUserInteraction(ModifiedUserInteraction::Active), _) => UserInteraction::Active,
        _ => unreachable!(),
      },

      vc: match (vec.get(Name::ModifiedVulnerableSystemConfidentiality), vec.get(Name::VulnerableSystemConfidentialityImpact)) {
        (Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::NotDefined), Metric::VulnerableSystemConfidentialityImpact(vc)) => vc,
        (Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::High), _) => Impact::High,
        (Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::Low), _) => Impact::Low,
        (Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::None), _) => Impact::None,
        _ => unreachable!(),
      },

      vi: match (vec.get(Name::ModifiedVulnerableSystemIntegrity), vec.get(Name::VulnerableSystemIntegrityImpact)) {
        (Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::NotDefined), Metric::VulnerableSystemIntegrityImpact(vi)) => vi,
        (Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::High), _) => Impact::High,
        (Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::Low), _) => Impact::Low,
        (Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::None), _) => Impact::None,
        _ => unreachable!(),
      },

      va: match (vec.get(Name::ModifiedVulnerableSystemAvailability), vec.get(Name::VulnerableSystemAvailabilityImpact)) {
        (Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::NotDefined), Metric::VulnerableSystemAvailabilityImpact(va)) => va,
        (Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::High), _) => Impact::High,
        (Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::Low), _) => Impact::Low,
        (Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::None), _) => Impact::None,
        _ => unreachable!(),
      },

      sc: match (vec.get(Name::ModifiedSubsequentSystemConfidentiality), vec.get(Name::SubsequentSystemConfidentialityImpact)) {
        (Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::NotDefined), Metric::SubsequentSystemConfidentialityImpact(sc)) => sc,
        (Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::High), _) => Impact::High,
        (Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::Low), _) => Impact::Low,
        (Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::None), _) => Impact::None,
        _ => unreachable!(),
      },

      si: match (vec.get(Name::ModifiedSubsequentSystemIntegrity), vec.get(Name::SubsequentSystemIntegrityImpact)) {
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::NotDefined), Metric::SubsequentSystemIntegrityImpact(Impact::High)) => SubsequentImpact::High,
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::NotDefined), Metric::SubsequentSystemIntegrityImpact(Impact::Low)) => SubsequentImpact::Low,
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::NotDefined), Metric::SubsequentSystemIntegrityImpact(Impact::None)) => SubsequentImpact::None,
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::High), _) => SubsequentImpact::High,
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Low), _) => SubsequentImpact::Low,
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::None), _) => SubsequentImpact::None,
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Safety), _) => SubsequentImpact::Safety,
        _ => unreachable!(),
      },

      sa: match (vec.get(Name::ModifiedSubsequentSystemAvailability), vec.get(Name::SubsequentSystemAvailabilityImpact)) {
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::NotDefined), Metric::SubsequentSystemAvailabilityImpact(Impact::High)) => SubsequentImpact::High,
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::NotDefined), Metric::SubsequentSystemAvailabilityImpact(Impact::Low)) => SubsequentImpact::Low,
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::NotDefined), Metric::SubsequentSystemAvailabilityImpact(Impact::None)) => SubsequentImpact::None,
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::High), _) => SubsequentImpact::High,
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Low), _) => SubsequentImpact::Low,
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::None), _) => SubsequentImpact::None,
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Safety), _) => SubsequentImpact::Safety,
        _ => unreachable!(),
      },

      // EQ5 (Table 28)
      // If E=X it will default to the worst case (i.e., E=A).
      e: match vec.get(Name::ExploitMaturity) {
        Metric::ExploitMaturity(ExploitMaturity::NotDefined) => ExploitMaturity::Attacked,
        Metric::ExploitMaturity(e) => e,
        _ => unreachable!(),
      },

      // EQ6 (Table 29)
      // If CR=X, IR=X or AR=X they will default to the worst case (i.e.,
      // CR=H, IR=H and AR=H).
      cr: match vec.get(Name::ConfidentialityRequirement) {
        Metric::ConfidentialityRequirement(Requirement::NotDefined) => Requirement::High,
        Metric::ConfidentialityRequirement(r) => r,
        _ => unreachable!(),
      },

      // EQ6 (Table 29)
      // If CR=X, IR=X or AR=X they will default to the worst case (i.e.,
      // CR=H, IR=H and AR=H).
      ir: match vec.get(Name::IntegrityRequirement) {
        Metric::IntegrityRequirement(Requirement::NotDefined) => Requirement::High,
        Metric::IntegrityRequirement(r) => r,
        _ => unreachable!(),
      },

      // EQ6 (Table 29)
      // If CR=X, IR=X or AR=X they will default to the worst case (i.e.,
      // CR=H, IR=H and AR=H).
      ar: match vec.get(Name::AvailabilityRequirement) {
        Metric::AvailabilityRequirement(Requirement::NotDefined) => Requirement::High,
        Metric::AvailabilityRequirement(r) => r,
        _ => unreachable!(),
      },
    }
  }
}

/// Equivalence class attributes
struct EqClass {
  /// Decoding denominator
  denom: u16,

  /// Number of sets in EQ
  size: u16,

  // Maximum severity distance from the highest severity vectors and
  // the lowest severity vector(s) of the macrovector
  // depth: u32,
}

const EQS: [EqClass; 6] = [
  // eq1
  EqClass {
    denom: 1,
    size: 3,
    // depth: 6, // AV:N/PR:N/UI:N -> AV:A/PR:L/UI:P
  },

  // eq2
  EqClass {
    denom: 3,
    size: 2,
    // depth: 1, // AC:L/AT:N -> AC:L/AT:P
  },

  // eq3
  EqClass {
    denom: 6,
    size: 3,
    // depth: 3, // VC:H/VI:H/VA:H -> VC:L/VI:L/VA:L
  },

  // eq4
  EqClass {
    denom: 18,
    size: 3,
    // depth: 5, // SC:H/SI:S/SA:S -> SC:L/SI:L/SA:L
  },

  // eq5
  EqClass {
    denom: 54,
    size: 3,
    // depth: 2, // E:A -> E:U
  },

  // eq6
  EqClass {
    denom: 162,
    size: 2,
    // depth: 3, // VC:H/VI:H/VA:H/CR:H/IR:H/AR:H -> VC:L/VI:L/VA:L/CR:H/IR:H/AR:H
  }
];

/// [CVSS v4][doc] macro vector.
///
/// Set of [CVSS v4][doc] vectors used to calculate the score of a
/// vector.
///
/// Represented internally as a `u16`.
///
/// See [CVSS v4.0 Specification, Section 8: CVSS v4.0 Scoring][scoring].
///
/// # Example
///
/// Get [`MacroVector`][] for [CVSS v4][doc] vector string:
///
/// ```
/// # use polycvss::{Err, v4::{MacroVector,Vector}};
/// # fn main() -> Result<(), Err> {
/// // expected macrovector
/// let exp = MacroVector::try_from(002201).unwrap();
///
/// // parse vector string
/// let vec: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N".parse()?;
///
/// // get macrovector
/// let got = MacroVector::from(vec);
///
/// // check result
/// assert_eq!(got, exp);
/// assert_eq!(got.to_string(), "002201");
/// # Ok(())
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document
///   "CVSS v4.0 Specification"
/// [scoring]: https://www.first.org/cvss/v4-0/specification-document#CVSS-v4-0-Scoring
///   "CVSS v4.0 Specification, Section 8: CVSS v4.0 Scoring"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct MacroVector(u16);

impl MacroVector {
  /// Get equivalence class value.
  fn eq(self, pos: usize) -> u16 {
    let eq = &EQS[pos];
    (self.0 / eq.denom) % eq.size
  }
}

impl TryFrom<u32> for MacroVector {
  type Error = super::Err;

  fn try_from(val: u32) -> Result<MacroVector, Self::Error> {
    let eq1 = ((val / 100_000) % 10) as u16;
    let eq2 = ((val / 10_000) % 10) as u16;
    let eq3 = ((val / 1_000) % 10) as u16;
    let eq4 = ((val / 100) % 10) as u16;
    let eq5 = ((val / 10) % 10) as u16;
    let eq6 = (val % 10) as u16;

    if val < 1_000_000 && eq1 < 3 && eq2 < 2 && eq3 < 3 && eq4 < 3 && eq5 < 3 && eq6 < 2 {
      Ok(MacroVector(eq1 + eq2*3 + eq3*6 + eq4*18 + eq5*54 + eq6*162))
    } else {
      Err(Err::InvalidMacroVector)
    }
  }
}

impl From<Vector> for MacroVector {
  fn from(vec: Vector) -> MacroVector {
    let vals = Values::from(vec);

    // EQ1 (Table 24)
    // 0  AV:N and PR:N and UI:N
    // 1  (AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
    // 2  AV:P or not(AV:N or PR:N or UI:N)
    let eq1: u32 = {
      let av_n = vals.av == AttackVector::Network;
      let av_p = vals.av == AttackVector::Physical;
      let pr_n = vals.pr == PrivilegesRequired::None;
      let ui_n = vals.ui == UserInteraction::None;

      if av_n && pr_n && ui_n {
        0
      } else if (av_n || pr_n || ui_n) && !(av_n && pr_n && ui_n) && !av_p {
        1
      } else {
        2
      }
    };

    // EQ2 (Table 25)
    // 0  AC:L and AT:N
    // 1  not (AC:L and AT:N)
    let eq2: u32 = {
      let ac_l = vals.ac == AttackComplexity::Low;
      let at_n = vals.at == AttackRequirements::None;

      if ac_l && at_n { 0 } else { 1 }
    };

    // EQ3 (Table 26)
    // 0  VC:H and VI:H
    // 1  not (VC:H and VI:H) and (VC:H or VI:H or VA:H)
    // 2  not (VC:H or VI:H or VA:H)
    let eq3 = {
      let vc_h = vals.vc == Impact::High;
      let vi_h = vals.vi == Impact::High;
      let va_h = vals.va == Impact::High;

      if vc_h && vi_h {
        0
      } else if !(vc_h && vi_h) && (vc_h || vi_h || va_h) {
        1
      } else {
        2
      }
    };

    // EQ4 (Table 27)
    // 0  MSI:S or MSA:S
    // 1  not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
    // 2  not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)
    //
    // If MSI=X or MSA=X they will default to the corresponding value of
    // SI and SA according to the rules of Modified Base Metrics in
    // section 4.2 (See Table 15). So if there are no modified base
    // metrics, the highest value that EQ4 can reach is 1.
    let eq4 = {
      let sc_h = vals.sc == Impact::High;
      let si_s = vals.si == SubsequentImpact::Safety;
      let si_h = vals.si == SubsequentImpact::High;
      let sa_s = vals.sa == SubsequentImpact::Safety;
      let sa_h = vals.sa == SubsequentImpact::High;

      if si_s || sa_s {
        0
      } else if !(si_s || sa_s) && (sc_h || si_h || sa_h) {
        1
      } else {
        2
      }
    };

    // EQ5 (Table 28)
    // 0  E:A
    // 1  E:P
    // 2  E:U
    //
    // If E=X it will default to the worst case (i.e., E=A).
    let eq5 = match vals.e {
      ExploitMaturity::Attacked => 0,
      ExploitMaturity::ProofOfConcept => 1,
      ExploitMaturity::Unreported => 2,
      ExploitMaturity::NotDefined => unreachable!(),
    };

    // EQ6 (Table 29)
    // 0  (CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
    // 1  not (CR:H and VC:H) and not (IR:H and VI:H) and not (AR:H and VA:H)
    //
    // If CR=X, IR=X or AR=X they will default to the worst case (i.e.,
    // CR=H, IR=H and AR=H).
    let eq6: u32 = {
      let cr_h = vals.cr == Requirement::High;
      let vc_h = vals.vc == Impact::High;
      let ir_h = vals.ir == Requirement::High;
      let vi_h = vals.vi == Impact::High;
      let ar_h = vals.ar == Requirement::High;
      let va_h = vals.va == Impact::High;

      if (cr_h && vc_h) || (ir_h && vi_h) || (ar_h && va_h) {
        0
      } else {
        1
      }
    };

    // encode eqs as u32
    let val: u32 = eq1*100_000 + eq2*10_000 + eq3*1_000 + eq4*100 + eq5*10 + eq6;

    // create macrovector
    // note: the code above always creates a valid macrovector, so
    // unwrap() is safe
    MacroVector::try_from(val).unwrap()
  }
}

impl From<MacroVector> for u32 {
  fn from(mv: MacroVector) -> u32 {
    EQS.iter().enumerate().map(|(i, eq)| {
      let pos = 10_u32.pow(5 - (i as u32)); // digit position
      let val = ((mv.0 / eq.denom) % eq.size) as u32; // decode value
      pos * val
    }).sum::<u32>()
  }
}

impl From<MacroVector> for Score {
  fn from(mv: MacroVector) -> Score {
    Score(match mv.0 {
      0 => 100, // 000000
      162 => 99, // 000001
      54 => 98, // 000010
      216 => 95, // 000011
      108 => 95, // 000020
      270 => 92, // 000021
      18 => 100, // 000100
      180 => 96, // 000101
      72 => 93, // 000110
      234 => 87, // 000111
      126 => 91, // 000120
      288 => 81, // 000121
      36 => 93, // 000200
      198 => 90, // 000201
      90 => 89, // 000210
      252 => 80, // 000211
      144 => 81, // 000220
      306 => 68, // 000221
      6 => 98, // 001000
      168 => 95, // 001001
      60 => 95, // 001010
      222 => 92, // 001011
      114 => 90, // 001020
      276 => 84, // 001021
      24 => 93, // 001100
      186 => 92, // 001101
      78 => 89, // 001110
      240 => 81, // 001111
      132 => 81, // 001120
      294 => 65, // 001121
      42 => 88, // 001200
      204 => 80, // 001201
      96 => 78, // 001210
      258 => 70, // 001211
      150 => 69, // 001220
      312 => 48, // 001221
      174 => 92, // 002001
      228 => 82, // 002011
      282 => 72, // 002021
      192 => 79, // 002101
      246 => 69, // 002111
      300 => 50, // 002121
      210 => 69, // 002201
      264 => 55, // 002211
      318 => 27, // 002221
      3 => 99, // 010000
      165 => 97, // 010001
      57 => 95, // 010010
      219 => 92, // 010011
      111 => 92, // 010020
      273 => 85, // 010021
      21 => 95, // 010100
      183 => 91, // 010101
      75 => 90, // 010110
      237 => 83, // 010111
      129 => 84, // 010120
      291 => 71, // 010121
      39 => 92, // 010200
      201 => 81, // 010201
      93 => 82, // 010210
      255 => 71, // 010211
      147 => 72, // 010220
      309 => 53, // 010221
      9 => 95, // 011000
      171 => 93, // 011001
      63 => 92, // 011010
      225 => 85, // 011011
      117 => 85, // 011020
      279 => 73, // 011021
      27 => 92, // 011100
      189 => 82, // 011101
      81 => 80, // 011110
      243 => 72, // 011111
      135 => 70, // 011120
      297 => 59, // 011121
      45 => 84, // 011200
      207 => 70, // 011201
      99 => 71, // 011210
      261 => 52, // 011211
      153 => 50, // 011220
      315 => 30, // 011221
      177 => 86, // 012001
      231 => 75, // 012011
      285 => 52, // 012021
      195 => 71, // 012101
      249 => 52, // 012111
      303 => 29, // 012121
      213 => 63, // 012201
      267 => 29, // 012211
      321 => 17, // 012221
      1 => 98, // 100000
      163 => 95, // 100001
      55 => 94, // 100010
      217 => 87, // 100011
      109 => 91, // 100020
      271 => 81, // 100021
      19 => 94, // 100100
      181 => 89, // 100101
      73 => 86, // 100110
      235 => 74, // 100111
      127 => 77, // 100120
      289 => 64, // 100121
      37 => 87, // 100200
      199 => 75, // 100201
      91 => 74, // 100210
      253 => 63, // 100211
      145 => 63, // 100220
      307 => 49, // 100221
      7 => 94, // 101000
      169 => 89, // 101001
      61 => 88, // 101010
      223 => 77, // 101011
      115 => 76, // 101020
      277 => 67, // 101021
      25 => 86, // 101100
      187 => 76, // 101101
      79 => 74, // 101110
      241 => 58, // 101111
      133 => 59, // 101120
      295 => 50, // 101121
      43 => 72, // 101200
      205 => 57, // 101201
      97 => 57, // 101210
      259 => 52, // 101211
      151 => 52, // 101220
      313 => 25, // 101221
      175 => 83, // 102001
      229 => 70, // 102011
      283 => 54, // 102021
      193 => 65, // 102101
      247 => 58, // 102111
      301 => 26, // 102121
      211 => 53, // 102201
      265 => 21, // 102211
      319 => 13, // 102221
      4 => 95, // 110000
      166 => 90, // 110001
      58 => 88, // 110010
      220 => 76, // 110011
      112 => 76, // 110020
      274 => 70, // 110021
      22 => 90, // 110100
      184 => 77, // 110101
      76 => 75, // 110110
      238 => 62, // 110111
      130 => 61, // 110120
      292 => 53, // 110121
      40 => 77, // 110200
      202 => 66, // 110201
      94 => 68, // 110210
      256 => 59, // 110211
      148 => 52, // 110220
      310 => 30, // 110221
      10 => 89, // 111000
      172 => 78, // 111001
      64 => 76, // 111010
      226 => 67, // 111011
      118 => 62, // 111020
      280 => 58, // 111021
      28 => 74, // 111100
      190 => 59, // 111101
      82 => 57, // 111110
      244 => 57, // 111111
      136 => 47, // 111120
      298 => 23, // 111121
      46 => 61, // 111200
      208 => 52, // 111201
      100 => 57, // 111210
      262 => 29, // 111211
      154 => 24, // 111220
      316 => 16, // 111221
      178 => 71, // 112001
      232 => 59, // 112011
      286 => 30, // 112021
      196 => 58, // 112101
      250 => 26, // 112111
      304 => 15, // 112121
      214 => 23, // 112201
      268 => 13, // 112211
      322 => 6, // 112221
      2 => 93, // 200000
      164 => 87, // 200001
      56 => 86, // 200010
      218 => 72, // 200011
      110 => 75, // 200020
      272 => 58, // 200021
      20 => 86, // 200100
      182 => 74, // 200101
      74 => 74, // 200110
      236 => 61, // 200111
      128 => 56, // 200120
      290 => 34, // 200121
      38 => 70, // 200200
      200 => 54, // 200201
      92 => 52, // 200210
      254 => 40, // 200211
      146 => 40, // 200220
      308 => 22, // 200221
      8 => 85, // 201000
      170 => 75, // 201001
      62 => 74, // 201010
      224 => 55, // 201011
      116 => 62, // 201020
      278 => 51, // 201021
      26 => 72, // 201100
      188 => 57, // 201101
      80 => 55, // 201110
      242 => 41, // 201111
      134 => 46, // 201120
      296 => 19, // 201121
      44 => 53, // 201200
      206 => 36, // 201201
      98 => 34, // 201210
      260 => 19, // 201211
      152 => 19, // 201220
      314 => 8, // 201221
      176 => 64, // 202001
      230 => 51, // 202011
      284 => 20, // 202021
      194 => 47, // 202101
      248 => 21, // 202111
      302 => 11, // 202121
      212 => 24, // 202201
      266 => 9, // 202211
      320 => 4, // 202221
      5 => 88, // 210000
      167 => 75, // 210001
      59 => 73, // 210010
      221 => 53, // 210011
      113 => 60, // 210020
      275 => 50, // 210021
      23 => 73, // 210100
      185 => 55, // 210101
      77 => 59, // 210110
      239 => 40, // 210111
      131 => 41, // 210120
      293 => 20, // 210121
      41 => 54, // 210200
      203 => 43, // 210201
      95 => 45, // 210210
      257 => 22, // 210211
      149 => 20, // 210220
      311 => 11, // 210221
      11 => 75, // 211000
      173 => 55, // 211001
      65 => 58, // 211010
      227 => 45, // 211011
      119 => 40, // 211020
      281 => 21, // 211021
      29 => 61, // 211100
      191 => 51, // 211101
      83 => 48, // 211110
      245 => 18, // 211111
      137 => 20, // 211120
      299 => 9, // 211121
      47 => 46, // 211200
      209 => 18, // 211201
      101 => 17, // 211210
      263 => 7, // 211211
      155 => 8, // 211220
      317 => 2, // 211221
      179 => 53, // 212001
      233 => 24, // 212011
      287 => 14, // 212021
      197 => 24, // 212101
      251 => 12, // 212111
      305 => 5, // 212121
      215 => 10, // 212201
      269 => 3, // 212211
      323 => 1, // 212221
      _ => unreachable!(), // never reached
    })
  }
}

impl std::fmt::Display for MacroVector {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{:06}", u32::from(*self))
  }
}

/// [CVSS v4][doc] macro vector and score.
///
/// [CVSS v4][doc] vector score and macrovector.
///
/// See [CVSS v4.0 Specification, Section 8: CVSS v4.0 Scoring][scoring].
///
/// # Example
///
/// Get score for [CVSS v4][doc] vector:
///
/// ```
/// # use polycvss::{Err, v4::{Scores, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v4 vector string
/// let v: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N".parse()?;
///
/// // get scores
/// let scores = Scores::from(v);
///
/// // check result
/// assert_eq!(scores.score.to_string(), "6.9");
/// # Ok(())
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v4-0/specification-document
///   "CVSS v4.0 Specification"
/// [scoring]: https://www.first.org/cvss/v4-0/specification-document#CVSS-v4-0-Scoring
///   "CVSS v4.0 Specification, Section 8: CVSS v4.0 Scoring"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Scores {
  /// Macrovector
  pub macrovector: MacroVector,

  /// Score
  pub score: Score,
}

impl From<Vector> for Scores {
  fn from(vec: Vector) -> Scores {
    const AV_A: AttackVector = AttackVector::Adjacent;
    const AV_N: AttackVector = AttackVector::Network;
    const AV_P: AttackVector = AttackVector::Physical;

    const AC_L: AttackComplexity = AttackComplexity::Low;
    const AC_H: AttackComplexity = AttackComplexity::High;

    const AT_N: AttackRequirements = AttackRequirements::None;
    const AT_P: AttackRequirements = AttackRequirements::Present;

    const PR_N: PrivilegesRequired = PrivilegesRequired::None;
    const PR_L: PrivilegesRequired = PrivilegesRequired::Low;

    const UI_N: UserInteraction = UserInteraction::None;
    const UI_P: UserInteraction = UserInteraction::Passive;

    const I_H: Impact = Impact::High;
    const I_L: Impact = Impact::Low;
    const I_N: Impact = Impact::None;

    const SI_H: SubsequentImpact = SubsequentImpact::High;
    const SI_L: SubsequentImpact = SubsequentImpact::Low;
    const SI_N: SubsequentImpact = SubsequentImpact::None;
    const SI_S: SubsequentImpact = SubsequentImpact::Safety;

    const R_H: Requirement = Requirement::High;
    const R_M: Requirement = Requirement::Medium;
    // const R_L: Requirement = Requirement::Low;

    const E_A: ExploitMaturity = ExploitMaturity::Attacked;
    const E_P: ExploitMaturity = ExploitMaturity::ProofOfConcept;
    const E_U: ExploitMaturity = ExploitMaturity::Unreported;

    let mv = MacroVector::from(vec); // get macrovector
    let vals = Values::from(vec); // get effective values

    // is there at least one active impact metric?
    let active_impact_metric = {
      vals.vc != I_N || vals.vi != I_N || vals.va != I_N ||
      vals.sc != I_N || vals.si != SI_N || vals.sa != SI_N
    };

    // get vector score
    let score: Score = if active_impact_metric {
      // get current macrovector score and EQ6 value
      let mv_score = Score::from(mv);
      let eq6 = mv.eq(5);

      // get proportional distances
      //
      // eq3 and eq6 are considered together, so this array only has 5
      // elements.
      let pds: [Option<f64>; 5] = core::array::from_fn(|i| {
        // get severity distance
        let sd: u8 = (match (i, mv.eq(i), eq6) {
          // eq1 level 0, table 24:  AV:N/PR:N/UI:N
          (0, 0, _) => vec!(
            vals.av.diff(AV_N) + vals.pr.diff(PR_N) + vals.ui.diff(UI_N),
          ),

          // eq1, level 1, table 24:
          // AV:A/PR:N/UI:N or AV:N/PR:L/UI:N or AV:N/PR:N:/UI:P
          (0, 1, _) => vec!(
            (vals.av.diff(AV_A) + vals.pr.diff(PR_N) + vals.ui.diff(UI_N)),
            (vals.av.diff(AV_N) + vals.pr.diff(PR_L) + vals.ui.diff(UI_N)),
            (vals.av.diff(AV_N) + vals.pr.diff(PR_N) + vals.ui.diff(UI_P)),
          ),

          // eq1, level 2, table 24:
          // AV:P/PR:N/UI:N or AV:A/PR:L/UI:P
          (0, 2, _) => vec!(
            (vals.av.diff(AV_P) + vals.pr.diff(PR_N) + vals.ui.diff(UI_N)),
            (vals.av.diff(AV_A) + vals.pr.diff(PR_L) + vals.ui.diff(UI_P)),
          ),

          // eq2, level 0, table 25:
          // AC:L/AT:N
          (1, 0, _) => vec!(
            vals.ac.diff(AC_L) + vals.at.diff(AT_N),
          ),

          // eq2, level 1, table 25:
          // AC:L/AT:P or AC:H/AT:N
          (1, 1, _) => vec!(
            (vals.ac.diff(AC_L) + vals.at.diff(AT_P)),
            (vals.ac.diff(AC_H) + vals.at.diff(AT_N)),
          ),

          // eq3 level 0, eq6 level 0, table 30:
          // VC:H/VI:H/VA:H/CR:H/IR:H/AR:H
          (2, 0, 0) => vec!(
            (vals.vc.diff(I_H) + vals.vi.diff(I_H) + vals.va.diff(I_H) +
             vals.cr.diff(R_H) + vals.ir.diff(R_H) + vals.ar.diff(R_H))
          ),

          // eq3 level 0, eq6 level 1, table 30:
          // VC:H/VI:H/VA:H/CR:M/IR:M/AR:M or VC:H/VI:H/VA:L/CR:M/IR:M/AR:H
          (2, 0, 1) => vec!(
            // VC:H/VI:H/VA:H/CR:M/IR:M/AR:M
            (vals.vc.diff(I_H) + vals.vi.diff(I_H) + vals.va.diff(I_H) +
             vals.cr.diff(R_M) + vals.ir.diff(R_M) + vals.ar.diff(R_M)),
            // VC:H/VI:H/VA:L/CR:M/IR:M/AR:H
            (vals.vc.diff(I_H) + vals.vi.diff(I_H) + vals.va.diff(I_L) +
             vals.cr.diff(R_M) + vals.ir.diff(R_M) + vals.ar.diff(R_H)),
          ),

          // eq3 level 1, eq6 level 0, table 30:
          // VC:L/VI:H/VA:H/CR:H/IR:H/AR:H or VC:H/VI:L/VA:H/CR:H/IR:H/AR:H
          (2, 1, 0) => vec!(
            // VC:L/VI:H/VA:H/CR:H/IR:H/AR:H
            (vals.vc.diff(I_L) + vals.vi.diff(I_H) + vals.va.diff(I_H) +
             vals.cr.diff(R_H) + vals.ir.diff(R_H) + vals.ar.diff(R_H)),
            // VC:H/VI:L/VA:H/CR:H/IR:H/AR:H
            (vals.vc.diff(I_H) + vals.vi.diff(I_L) + vals.va.diff(I_H) +
             vals.cr.diff(R_H) + vals.ir.diff(R_H) + vals.ar.diff(R_H)),
          ),

          // eq3 level 1, eq6 level 1, table 30:
          // VC:H/VI:L/VA:H/CR:M/IR:H/AR:M or VC:H/VI:L/VA:L/CR:M/IR:H/AR:H or
          // VC:L/VI:H/VA:H/CR:H/IR:M/AR:M or VC:L/VI:H/VA:L/CR:H/IR:M/AR:H or
          // VC:L/VI:L/VA:H/CR:H/IR:H/AR:M
          (2, 1, 1) => vec!(
            // VC:H/VI:L/VA:H/CR:M/IR:H/AR:M
            (vals.vc.diff(I_H) + vals.vi.diff(I_L) + vals.va.diff(I_H) +
             vals.cr.diff(R_M) + vals.ir.diff(R_H) + vals.ar.diff(R_M)),
            // VC:H/VI:L/VA:L/CR:M/IR:H/AR:H
            (vals.vc.diff(I_H) + vals.vi.diff(I_L) + vals.va.diff(I_L) +
             vals.cr.diff(R_M) + vals.ir.diff(R_H) + vals.ar.diff(R_H)),
            // VC:L/VI:H/VA:H/CR:H/IR:M/AR:M
            (vals.vc.diff(I_L) + vals.vi.diff(I_H) + vals.va.diff(I_H) +
             vals.cr.diff(R_H) + vals.ir.diff(R_M) + vals.ar.diff(R_M)),
            // VC:L/VI:H/VA:L/CR:H/IR:M/AR:H
            (vals.vc.diff(I_L) + vals.vi.diff(I_H) + vals.va.diff(I_L) +
             vals.cr.diff(R_H) + vals.ir.diff(R_M) + vals.ar.diff(R_H)),
            // VC:L/VI:L/VA:H/CR:H/IR:H/AR:M
            (vals.vc.diff(I_L) + vals.vi.diff(I_L) + vals.va.diff(I_H) +
             vals.cr.diff(R_H) + vals.ir.diff(R_H) + vals.ar.diff(R_M)),
          ),

          // eq3 level 2, eq6 level 1, table 30:
          // VC:L/VI:L/VA:L/CR:H/IR:H/AR:H
          (2, 2, 1) => vec!(
            // VC:L/VI:L/VA:L/CR:H/IR:H/AR:H
            (vals.vc.diff(I_L) + vals.vi.diff(I_L) + vals.va.diff(I_L) +
             vals.cr.diff(R_H) + vals.ir.diff(R_H) + vals.ar.diff(R_H)),
          ),

          // eq4, level 0, table 27:
          // SC:H/SI:S/SA:S
          (3, 0, _) => vec!(
            vals.sc.diff(I_H) + vals.si.diff(SI_S) + vals.sa.diff(SI_S)
          ),

          // eq4, level 1, table 27:
          // SC:H/SI:H/SA:H
          (3, 1, _) => vec!(
            vals.sc.diff(I_H) + vals.si.diff(SI_H) + vals.sa.diff(SI_H)
          ),

          // eq4, level 2, table 27:
          // SC:L/SI:L/SA:L
          (3, 2, _) => vec!(
            vals.sc.diff(I_L) + vals.si.diff(SI_L) + vals.sa.diff(SI_L)
          ),

          // eq5, level 0, table 28:
          // E:A
          (4, 0, _) => vec!(
            vals.e.diff(E_A)
          ),

          // eq5, level 1, table 28:
          // E:P
          (4, 1, _) => vec!(
            vals.e.diff(E_P)
          ),

          // eq5, level 2, table 28:
          // E:U
          (4, 2, _) => vec!(
            vals.e.diff(E_U)
          ),

          _ => unreachable!(), // never reached
        }).into_iter().fold(u8::MAX, u8::min);

        let eq = &EQS[i]; // get EQ metadata
        let level = mv.eq(i); // get EQ level

        // is there another level for this EQ?
        if level < (eq.size - 1) {
          // get max score difference
          let msd = mv_score - ((match (i, level, eq6) {
            // eq3=0 and eq6=0, so there are two possible MVs (eq3=1
            // and eq6=1). check both MVs.
            (2, 0, 0) => vec!(2, 5),

            // eq3=2,eq6=0 is invalid (section 8.2, table 30), so only
            // consider eq3=1,eq6=1
            (2, 1, 0) => vec!(5),
            _ => vec!(i),
          }).into_iter().map(|e|
            Score::from(MacroVector(mv.0 + EQS[e].denom))
          ).fold(Score(0), Score::max));

          // calculate depth.  depth is the maximum severity distance
          // between the highest severity vector in this MV and the
          // lowest severity vector(s) in this MV
          //
          // ref: https://nvd.nist.gov/site-scripts/cvss-v4-calculator-main/max_severity.js?v=1
          // eq3 and eq6 are considered together
          let depth = match (i, level, eq6) {
            (0, 0, _) => 1, // eq1 level 0
            (0, 1, _) => 4, // eq1 level 1
            (0, 2, _) => 5, // eq1 level 2
            (1, 0, _) => 1, // eq2 level 0
            (1, 1, _) => 2, // eq2 level 1
            (2, 0, 0) => 7, // eq3 level 0, eq6 level 0
            (2, 0, 1) => 6, // eq3 level 0, eq6 level 1
            (2, 1, 0) => 8, // eq3 level 1, eq6 level 0
            (2, 1, 1) => 8, // eq3 level 1, eq6 level 1
            (2, 2, 0) => unreachable!(), // eq3 level 2, eq6 level 0 (invalid)
            (2, 2, 1) => 10, // eq3 level 2, eq6 level 1?
            (3, 0, _) => 6, // eq4 level 0
            (3, 1, _) => 5, // eq4 level 1
            (3, 2, _) => 4, // eq4 level 2
            (4, 0, _) => 1, // eq5 level 0
            (4, 1, _) => 1, // eq5 level 1
            (4, 2, _) => 1, // eq5 level 2
            _ => unreachable!(),
          };

          // println!("DEBUG: msd={msd}, sd={sd}, depth={depth}");
          // get proportional distance
          Some(((msd.0 as u16) * (sd as u16)) as f64 / ((10 * depth) as f64))
        } else {
          None // no other EQ level, so no proportional distance
        }
      });

      // println!("DEBUG: pds={pds:?}");
      // calculate mean proportional distance
      let mean_pd = {
        let sum = pds.iter().filter_map(|d| *d).sum::<f64>(); // numerator
        let count = pds.iter().filter(|d| d.is_some()).count(); // denominator
        // println!("DEBUG: sum={sum}, count={count}");
        if count > 0 { sum / (count as f64) } else { 0.0 } // mean
      };

      // generate final score by doing the following:
      //
      // 1. convert the MacroVector score into an f64,
      // 2. round the mean proportional distance (MPD) to the 5th decimal
      //    place (see rationale below).
      // 3. subtract MPD from the MacroVector score.
      //
      // the rounding to account for minor scoring differences due to
      // floating point imprecision between the JS-based official NVD
      // CVSS calculator and this implementation.
      //
      // specification wording:
      //
      // > 3. The score of the vector is the score of the MacroVector (i.e.
      // >    the score of the highest severity vector) minus the mean distance
      // >    so computed. This score is rounded to one decimal place.
      let mv_score_f64 = f64::from(mv_score);
      // println!("DEBUG: mv_score={mv_score} mean_pd={mean_pd:0.20}");
      Score::from(mv_score_f64 - ((100_000.0*mean_pd).round()/100_000.0))
    } else {
      // no active impact metric; return 0.0
      Score(0)
    };

    Scores { macrovector: mv, score }
  }
}

#[cfg(test)]
mod tests {
  mod group {
    use super::super::{Name, Group};

    #[test]
    fn test_from_name() {
      let tests = vec!(
        (Name::AttackVector, Group::Base),
        (Name::ExploitMaturity, Group::Threat),
        (Name::ConfidentialityRequirement, Group::Environmental),
        (Name::Safety, Group::Supplemental),
      );

      for (name, group) in tests {
        assert_eq!(Group::from(name), group, "{}", group);
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Group::Base, "Base"),
        (Group::Threat, "Threat"),
        (Group::Environmental, "Environmental"),
        (Group::Supplemental, "Supplemental"),
      );

      for (group, exp) in tests {
        assert_eq!(group.to_string(), exp, "{}", exp);
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

      for (name, s, exp) in tests {
        assert_eq!(s.parse::<Name>(), Err(exp), "{name}");
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        ("AV", Name::AttackVector),
        ("AC", Name::AttackComplexity),
        ("AT", Name::AttackRequirements),
        ("PR", Name::PrivilegesRequired),
        ("UI", Name::UserInteraction),
        ("VC", Name::VulnerableSystemConfidentialityImpact),
        ("VI", Name::VulnerableSystemIntegrityImpact),
        ("VA", Name::VulnerableSystemAvailabilityImpact),
        ("SC", Name::SubsequentSystemConfidentialityImpact),
        ("SI", Name::SubsequentSystemIntegrityImpact),
        ("SA", Name::SubsequentSystemAvailabilityImpact),
        ("E", Name::ExploitMaturity),
        ("CR", Name::ConfidentialityRequirement),
        ("IR", Name::IntegrityRequirement),
        ("AR", Name::AvailabilityRequirement),
        ("MAV", Name::ModifiedAttackVector),
        ("MAC", Name::ModifiedAttackComplexity),
        ("MAT", Name::ModifiedAttackRequirements),
        ("MPR", Name::ModifiedPrivilegesRequired),
        ("MUI", Name::ModifiedUserInteraction),
        ("MVC", Name::ModifiedVulnerableSystemConfidentiality),
        ("MVI", Name::ModifiedVulnerableSystemIntegrity),
        ("MVA", Name::ModifiedVulnerableSystemAvailability),
        ("MSC", Name::ModifiedSubsequentSystemConfidentiality),
        ("MSI", Name::ModifiedSubsequentSystemIntegrity),
        ("MSA", Name::ModifiedSubsequentSystemAvailability),
        ("S", Name::Safety),
        ("AU", Name::Automatable),
        ("R", Name::Recovery),
        ("V", Name::ValueDensity),
        ("RE", Name::VulnerabilityResponseEffort),
        ("U", Name::ProviderUrgency),
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
        (Name::AttackRequirements, "AT"),
        (Name::PrivilegesRequired, "PR"),
        (Name::UserInteraction, "UI"),
        (Name::VulnerableSystemConfidentialityImpact, "VC"),
        (Name::VulnerableSystemIntegrityImpact, "VI"),
        (Name::VulnerableSystemAvailabilityImpact, "VA"),
        (Name::SubsequentSystemConfidentialityImpact, "SC"),
        (Name::SubsequentSystemIntegrityImpact, "SI"),
        (Name::SubsequentSystemAvailabilityImpact, "SA"),
        (Name::ExploitMaturity, "E"),
        (Name::ConfidentialityRequirement, "CR"),
        (Name::IntegrityRequirement, "IR"),
        (Name::AvailabilityRequirement, "AR"),
        (Name::ModifiedAttackVector, "MAV"),
        (Name::ModifiedAttackComplexity, "MAC"),
        (Name::ModifiedAttackRequirements, "MAT"),
        (Name::ModifiedPrivilegesRequired, "MPR"),
        (Name::ModifiedUserInteraction, "MUI"),
        (Name::ModifiedVulnerableSystemConfidentiality, "MVC"),
        (Name::ModifiedVulnerableSystemIntegrity, "MVI"),
        (Name::ModifiedVulnerableSystemAvailability, "MVA"),
        (Name::ModifiedSubsequentSystemConfidentiality, "MSC"),
        (Name::ModifiedSubsequentSystemIntegrity, "MSI"),
        (Name::ModifiedSubsequentSystemAvailability, "MSA"),
        (Name::Safety, "S"),
        (Name::Automatable, "AU"),
        (Name::Recovery, "R"),
        (Name::ValueDensity, "V"),
        (Name::VulnerabilityResponseEffort, "RE"),
        (Name::ProviderUrgency, "U"),
      );

      for (name, exp) in tests {
        assert_eq!(name.to_string(), exp, "{exp}");
      }
    }
  }

  mod nomenclature {
    use super::super::{super::Err, Nomenclature, Vector};

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        ("CVSS-B", Nomenclature::CvssB),
        ("CVSS-BE", Nomenclature::CvssBe),
        ("CVSS-BT", Nomenclature::CvssBt),
        ("CVSS-BTE", Nomenclature::CvssBte),
      );

      for (s, exp) in tests {
        assert_eq!(s.parse::<Nomenclature>().unwrap(), exp, "{exp}");
      }
    }

    #[test]
    fn test_from_str_fail() {
      let tests = vec!(
        "asdf",
      );

      for s in tests {
        assert_eq!(s.parse::<Nomenclature>(), Err(Err::UnknownNomenclature), "{s}");
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Nomenclature::CvssB, "CVSS-B"),
        (Nomenclature::CvssBe, "CVSS-BE"),
        (Nomenclature::CvssBt, "CVSS-BT"),
        (Nomenclature::CvssBte, "CVSS-BTE"),
      );

      for (n, exp) in tests {
        assert_eq!(n.to_string(), exp, "{exp}");
      }
    }

    #[test]
    fn test_from_vector() {
      let tests = vec!(
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", Nomenclature::CvssB),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:N", Nomenclature::CvssBe),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A", Nomenclature::CvssBt),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/MAV:N", Nomenclature::CvssBte),
      );

      for (s, exp) in tests {
        let vec: Vector = s.parse().unwrap();
        assert_eq!(Nomenclature::from(vec), exp, "{exp}");
      }
    }
  }

  mod metric {
    use super::super::{
      Err,
      Metric,
      AttackVector,
      AttackComplexity,
      AttackRequirements,
      PrivilegesRequired,
      UserInteraction,
      Impact,
      ExploitMaturity,
      Requirement,
      ModifiedAttackVector,
      ModifiedAttackComplexity,
      ModifiedAttackRequirements,
      ModifiedPrivilegesRequired,
      ModifiedUserInteraction,
      ModifiedImpact,
      ModifiedSubsequentImpact,
      Safety,
      Automatable,
      Recovery,
      ValueDensity,
      VulnerabilityResponseEffort,
      ProviderUrgency,
    };

    #[test]
    fn test_from_str_fail() {
      let tests = vec!(
        ("empty", "", Err::UnknownMetric),
      );

      for (name, s, exp) in tests {
        assert_eq!(s.parse::<Metric>(), Err(exp), "{name}");
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        ("AV:N", Metric::AttackVector(AttackVector::Network)),
        ("AV:A", Metric::AttackVector(AttackVector::Adjacent)),
        ("AV:L", Metric::AttackVector(AttackVector::Local)),
        ("AV:P", Metric::AttackVector(AttackVector::Physical)),

        ("AC:L", Metric::AttackComplexity(AttackComplexity::Low)),
        ("AC:H", Metric::AttackComplexity(AttackComplexity::High)),

        ("AT:N", Metric::AttackRequirements(AttackRequirements::None)),
        ("AT:P", Metric::AttackRequirements(AttackRequirements::Present)),

        ("PR:N", Metric::PrivilegesRequired(PrivilegesRequired::None)),
        ("PR:L", Metric::PrivilegesRequired(PrivilegesRequired::Low)),
        ("PR:H", Metric::PrivilegesRequired(PrivilegesRequired::High)),

        ("UI:N", Metric::UserInteraction(UserInteraction::None)),
        ("UI:P", Metric::UserInteraction(UserInteraction::Passive)),
        ("UI:A", Metric::UserInteraction(UserInteraction::Active)),

        // base 9 = 3*3
        ("VC:H", Metric::VulnerableSystemConfidentialityImpact(Impact::High)),
        ("VC:L", Metric::VulnerableSystemConfidentialityImpact(Impact::Low)),
        ("VC:N", Metric::VulnerableSystemConfidentialityImpact(Impact::None)),

        // base 27 = 3*3*3
        ("VI:H", Metric::VulnerableSystemIntegrityImpact(Impact::High)),
        ("VI:L", Metric::VulnerableSystemIntegrityImpact(Impact::Low)),
        ("VI:N", Metric::VulnerableSystemIntegrityImpact(Impact::None)),

        // base 81 = 3*3*3*3
        ("VA:H", Metric::VulnerableSystemAvailabilityImpact(Impact::High)),
        ("VA:L", Metric::VulnerableSystemAvailabilityImpact(Impact::Low)),
        ("VA:N", Metric::VulnerableSystemAvailabilityImpact(Impact::None)),

        // base 243 = 3*3*3*3*3
        ("SC:H", Metric::SubsequentSystemConfidentialityImpact(Impact::High)),
        ("SC:L", Metric::SubsequentSystemConfidentialityImpact(Impact::Low)),
        ("SC:N", Metric::SubsequentSystemConfidentialityImpact(Impact::None)),

        // base 729 = 3*3*3*3*3*3
        ("SI:H", Metric::SubsequentSystemIntegrityImpact(Impact::High)),
        ("SI:L", Metric::SubsequentSystemIntegrityImpact(Impact::Low)),
        ("SI:N", Metric::SubsequentSystemIntegrityImpact(Impact::None)),

        // base 2187 = 3*3*3*3*3*3*3
        ("SA:H", Metric::SubsequentSystemAvailabilityImpact(Impact::High)),
        ("SA:L", Metric::SubsequentSystemAvailabilityImpact(Impact::Low)),
        ("SA:N", Metric::SubsequentSystemAvailabilityImpact(Impact::None)),

        ("E:X", Metric::ExploitMaturity(ExploitMaturity::NotDefined)),
        ("E:A", Metric::ExploitMaturity(ExploitMaturity::Attacked)),
        ("E:P", Metric::ExploitMaturity(ExploitMaturity::ProofOfConcept)),
        ("E:U", Metric::ExploitMaturity(ExploitMaturity::Unreported)),

        ("CR:X", Metric::ConfidentialityRequirement(Requirement::NotDefined)),
        ("CR:H", Metric::ConfidentialityRequirement(Requirement::High)),
        ("CR:M", Metric::ConfidentialityRequirement(Requirement::Medium)),
        ("CR:L", Metric::ConfidentialityRequirement(Requirement::Low)),

        ("IR:X", Metric::IntegrityRequirement(Requirement::NotDefined)),
        ("IR:H", Metric::IntegrityRequirement(Requirement::High)),
        ("IR:M", Metric::IntegrityRequirement(Requirement::Medium)),
        ("IR:L", Metric::IntegrityRequirement(Requirement::Low)),

        ("AR:X", Metric::AvailabilityRequirement(Requirement::NotDefined)),
        ("AR:H", Metric::AvailabilityRequirement(Requirement::High)),
        ("AR:M", Metric::AvailabilityRequirement(Requirement::Medium)),
        ("AR:L", Metric::AvailabilityRequirement(Requirement::Low)),

        // base 6561 = 3*3*3*3*3*3*3*3
        ("MAV:X", Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined)),
        ("MAV:N", Metric::ModifiedAttackVector(ModifiedAttackVector::Network)),
        ("MAV:A", Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent)),
        ("MAV:L", Metric::ModifiedAttackVector(ModifiedAttackVector::Local)),
        ("MAV:P", Metric::ModifiedAttackVector(ModifiedAttackVector::Physical)),

        // base 32805 = 3*3*3*3*3*3*3*3*5
        ("MAC:X", Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined)),
        ("MAC:L", Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low)),
        ("MAC:H", Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High)),

        // base 98415 = 3*3*3*3*3*3*3*3*5*3
        ("MAT:X", Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::NotDefined)),
        ("MAT:N", Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::None)),
        ("MAT:P", Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::Present)),

        ("MPR:X", Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined)),
        ("MPR:N", Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None)),
        ("MPR:L", Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low)),
        ("MPR:H", Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High)),

        ("MUI:X", Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined)),
        ("MUI:N", Metric::ModifiedUserInteraction(ModifiedUserInteraction::None)),
        ("MUI:P", Metric::ModifiedUserInteraction(ModifiedUserInteraction::Passive)),
        ("MUI:A", Metric::ModifiedUserInteraction(ModifiedUserInteraction::Active)),

        ("MVC:X", Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::NotDefined)),
        ("MVC:H", Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::High)),
        ("MVC:L", Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::Low)),
        ("MVC:N", Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::None)),

        ("MVI:X", Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::NotDefined)),
        ("MVI:H", Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::High)),
        ("MVI:L", Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::Low)),
        ("MVI:N", Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::None)),

        ("MVA:X", Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::NotDefined)),
        ("MVA:H", Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::High)),
        ("MVA:L", Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::Low)),
        ("MVA:N", Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::None)),

        ("MSC:X", Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::NotDefined)),
        ("MSC:H", Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::High)),
        ("MSC:L", Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::Low)),
        ("MSC:N", Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::None)),

        // base 295245 = 3*3*3*3*3*3*3*3*5*3*3
        ("MSI:X", Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::NotDefined)),
        ("MSI:H", Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::High)),
        ("MSI:L", Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Low)),
        ("MSI:N", Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::None)),
        ("MSI:S", Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Safety)),

        // base 1476225 = 3*3*3*3*3*3*3*3*5*3*3*5
        ("MSA:X", Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::NotDefined)),
        ("MSA:H", Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::High)),
        ("MSA:L", Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Low)),
        ("MSA:N", Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::None)),
        ("MSA:S", Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Safety)),

        // base 7381125 = 3*3*3*3*3*3*3*3*5*3*3*5*5
        ("S:X", Metric::Safety(Safety::NotDefined)),
        ("S:P", Metric::Safety(Safety::Present)),
        ("S:N", Metric::Safety(Safety::Negligible)),

        // base 22143375 = 3*3*3*3*3*3*3*3*5*3*3*5*5*3
        ("AU:X", Metric::Automatable(Automatable::NotDefined)),
        ("AU:N", Metric::Automatable(Automatable::No)),
        ("AU:Y", Metric::Automatable(Automatable::Yes)),

        ("R:X", Metric::Recovery(Recovery::NotDefined)),
        ("R:A", Metric::Recovery(Recovery::Automatic)),
        ("R:U", Metric::Recovery(Recovery::User)),
        ("R:I", Metric::Recovery(Recovery::Irrecoverable)),

        // base 66430125 = 3*3*3*3*3*3*3*5*3*3*3*5*5*3*3
        ("V:X", Metric::ValueDensity(ValueDensity::NotDefined)),
        ("V:D", Metric::ValueDensity(ValueDensity::Diffuse)),
        ("V:C", Metric::ValueDensity(ValueDensity::Concentrated)),

        ("RE:X", Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::NotDefined)),
        ("RE:L", Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Low)),
        ("RE:M", Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Moderate)),
        ("RE:H", Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::High)),

        // base 199290375 = 3*3*3*3*3*3*3*5*3*3*3*5*5*3*3*3
        ("U:X", Metric::ProviderUrgency(ProviderUrgency::NotDefined)),
        ("U:Red", Metric::ProviderUrgency(ProviderUrgency::Red)),
        ("U:Amber", Metric::ProviderUrgency(ProviderUrgency::Amber)),
        ("U:Green", Metric::ProviderUrgency(ProviderUrgency::Green)),
        ("U:Clear", Metric::ProviderUrgency(ProviderUrgency::Clear)),
      );

      for (s, exp) in tests {
        assert_eq!(s.parse::<Metric>().unwrap(), exp);
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Metric::AttackVector(AttackVector::Network), "AV:N"),
        (Metric::AttackVector(AttackVector::Adjacent), "AV:A"),
        (Metric::AttackVector(AttackVector::Local), "AV:L"),
        (Metric::AttackVector(AttackVector::Physical), "AV:P"),

        (Metric::AttackComplexity(AttackComplexity::Low), "AC:L"),
        (Metric::AttackComplexity(AttackComplexity::High), "AC:H"),

        (Metric::AttackRequirements(AttackRequirements::None), "AT:N"),
        (Metric::AttackRequirements(AttackRequirements::Present), "AT:P"),

        (Metric::PrivilegesRequired(PrivilegesRequired::None), "PR:N"),
        (Metric::PrivilegesRequired(PrivilegesRequired::Low), "PR:L"),
        (Metric::PrivilegesRequired(PrivilegesRequired::High), "PR:H"),

        (Metric::UserInteraction(UserInteraction::None), "UI:N"),
        (Metric::UserInteraction(UserInteraction::Passive), "UI:P"),
        (Metric::UserInteraction(UserInteraction::Active), "UI:A"),

        // base 9 = 3*3
        (Metric::VulnerableSystemConfidentialityImpact(Impact::High), "VC:H"),
        (Metric::VulnerableSystemConfidentialityImpact(Impact::Low), "VC:L"),
        (Metric::VulnerableSystemConfidentialityImpact(Impact::None), "VC:N"),

        // base 27 = 3*3*3
        (Metric::VulnerableSystemIntegrityImpact(Impact::High), "VI:H"),
        (Metric::VulnerableSystemIntegrityImpact(Impact::Low), "VI:L"),
        (Metric::VulnerableSystemIntegrityImpact(Impact::None), "VI:N"),

        // base 81 = 3*3*3*3
        (Metric::VulnerableSystemAvailabilityImpact(Impact::High), "VA:H"),
        (Metric::VulnerableSystemAvailabilityImpact(Impact::Low), "VA:L"),
        (Metric::VulnerableSystemAvailabilityImpact(Impact::None), "VA:N"),

        // base 243 = 3*3*3*3*3
        (Metric::SubsequentSystemConfidentialityImpact(Impact::High), "SC:H"),
        (Metric::SubsequentSystemConfidentialityImpact(Impact::Low), "SC:L"),
        (Metric::SubsequentSystemConfidentialityImpact(Impact::None), "SC:N"),

        // base 729 = 3*3*3*3*3*3
        (Metric::SubsequentSystemIntegrityImpact(Impact::High), "SI:H"),
        (Metric::SubsequentSystemIntegrityImpact(Impact::Low), "SI:L"),
        (Metric::SubsequentSystemIntegrityImpact(Impact::None), "SI:N"),

        // base 2187 = 3*3*3*3*3*3*3
        (Metric::SubsequentSystemAvailabilityImpact(Impact::High), "SA:H"),
        (Metric::SubsequentSystemAvailabilityImpact(Impact::Low), "SA:L"),
        (Metric::SubsequentSystemAvailabilityImpact(Impact::None), "SA:N"),

        (Metric::ExploitMaturity(ExploitMaturity::NotDefined), "E:X"),
        (Metric::ExploitMaturity(ExploitMaturity::Attacked), "E:A"),
        (Metric::ExploitMaturity(ExploitMaturity::ProofOfConcept), "E:P"),
        (Metric::ExploitMaturity(ExploitMaturity::Unreported), "E:U"),

        (Metric::ConfidentialityRequirement(Requirement::NotDefined), "CR:X"),
        (Metric::ConfidentialityRequirement(Requirement::High), "CR:H"),
        (Metric::ConfidentialityRequirement(Requirement::Medium), "CR:M"),
        (Metric::ConfidentialityRequirement(Requirement::Low), "CR:L"),

        (Metric::IntegrityRequirement(Requirement::NotDefined), "IR:X"),
        (Metric::IntegrityRequirement(Requirement::High), "IR:H"),
        (Metric::IntegrityRequirement(Requirement::Medium), "IR:M"),
        (Metric::IntegrityRequirement(Requirement::Low), "IR:L"),

        (Metric::AvailabilityRequirement(Requirement::NotDefined), "AR:X"),
        (Metric::AvailabilityRequirement(Requirement::High), "AR:H"),
        (Metric::AvailabilityRequirement(Requirement::Medium), "AR:M"),
        (Metric::AvailabilityRequirement(Requirement::Low), "AR:L"),

        // base 6561 = 3*3*3*3*3*3*3*3
        (Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined), "MAV:X"),
        (Metric::ModifiedAttackVector(ModifiedAttackVector::Network), "MAV:N"),
        (Metric::ModifiedAttackVector(ModifiedAttackVector::Adjacent), "MAV:A"),
        (Metric::ModifiedAttackVector(ModifiedAttackVector::Local), "MAV:L"),
        (Metric::ModifiedAttackVector(ModifiedAttackVector::Physical), "MAV:P"),

        // base 32805 = 3*3*3*3*3*3*3*3*5
        (Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::NotDefined), "MAC:X"),
        (Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::Low), "MAC:L"),
        (Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High), "MAC:H"),

        // base 98415 = 3*3*3*3*3*3*3*3*5*3
        (Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::NotDefined), "MAT:X"),
        (Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::None), "MAT:N"),
        (Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::Present), "MAT:P"),

        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::NotDefined), "MPR:X"),
        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::None), "MPR:N"),
        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::Low), "MPR:L"),
        (Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High), "MPR:H"),

        (Metric::ModifiedUserInteraction(ModifiedUserInteraction::NotDefined), "MUI:X"),
        (Metric::ModifiedUserInteraction(ModifiedUserInteraction::None), "MUI:N"),
        (Metric::ModifiedUserInteraction(ModifiedUserInteraction::Passive), "MUI:P"),
        (Metric::ModifiedUserInteraction(ModifiedUserInteraction::Active), "MUI:A"),

        (Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::NotDefined), "MVC:X"),
        (Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::High), "MVC:H"),
        (Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::Low), "MVC:L"),
        (Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::None), "MVC:N"),

        (Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::NotDefined), "MVI:X"),
        (Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::High), "MVI:H"),
        (Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::Low), "MVI:L"),
        (Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::None), "MVI:N"),

        (Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::NotDefined), "MVA:X"),
        (Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::High), "MVA:H"),
        (Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::Low), "MVA:L"),
        (Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::None), "MVA:N"),

        (Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::NotDefined), "MSC:X"),
        (Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::High), "MSC:H"),
        (Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::Low), "MSC:L"),
        (Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::None), "MSC:N"),

        // base 295245 = 3*3*3*3*3*3*3*3*5*3*3
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::NotDefined), "MSI:X"),
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::High), "MSI:H"),
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Low), "MSI:L"),
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::None), "MSI:N"),
        (Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Safety), "MSI:S"),

        // base 1476225 = 3*3*3*3*3*3*3*3*5*3*3*5
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::NotDefined), "MSA:X"),
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::High), "MSA:H"),
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Low), "MSA:L"),
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::None), "MSA:N"),
        (Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Safety), "MSA:S"),

        // base 7381125 = 3*3*3*3*3*3*3*3*5*3*3*5*5
        (Metric::Safety(Safety::NotDefined), "S:X"),
        (Metric::Safety(Safety::Present), "S:P"),
        (Metric::Safety(Safety::Negligible), "S:N"),

        // base 22143375 = 3*3*3*3*3*3*3*3*5*3*3*5*5*3
        (Metric::Automatable(Automatable::NotDefined), "AU:X"),
        (Metric::Automatable(Automatable::No), "AU:N"),
        (Metric::Automatable(Automatable::Yes), "AU:Y"),

        (Metric::Recovery(Recovery::NotDefined), "R:X"),
        (Metric::Recovery(Recovery::Automatic), "R:A"),
        (Metric::Recovery(Recovery::User), "R:U"),
        (Metric::Recovery(Recovery::Irrecoverable), "R:I"),

        // base 66430125 = 3*3*3*3*3*3*3*5*3*3*3*5*5*3*3
        (Metric::ValueDensity(ValueDensity::NotDefined), "V:X"),
        (Metric::ValueDensity(ValueDensity::Diffuse), "V:D"),
        (Metric::ValueDensity(ValueDensity::Concentrated), "V:C"),

        (Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::NotDefined), "RE:X"),
        (Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Low), "RE:L"),
        (Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::Moderate), "RE:M"),
        (Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::High), "RE:H"),

        // base 199290375 = 3*3*3*3*3*3*3*5*3*3*3*5*5*3*3*3
        (Metric::ProviderUrgency(ProviderUrgency::NotDefined), "U:X"),
        (Metric::ProviderUrgency(ProviderUrgency::Red), "U:Red"),
        (Metric::ProviderUrgency(ProviderUrgency::Amber), "U:Amber"),
        (Metric::ProviderUrgency(ProviderUrgency::Green), "U:Green"),
        (Metric::ProviderUrgency(ProviderUrgency::Clear), "U:Clear"),
      );

      for (metric, exp) in tests {
        assert_eq!(metric.to_string(), exp);
      }
    }

    #[test]
    fn test_size() {
      assert_eq!(size_of::<Metric>(), size_of::<u16>());
    }
  }

  mod vector {
    use super::super::{
      super::Version,
      Err,
      Name,
      Metric,
      Vector,
      AttackVector,
      AttackComplexity,
      AttackRequirements,
      PrivilegesRequired,
      UserInteraction,
      Impact,
      ExploitMaturity,
      Requirement,
      ModifiedAttackVector,
      ModifiedAttackComplexity,
      ModifiedAttackRequirements,
      ModifiedPrivilegesRequired,
      ModifiedUserInteraction,
      ModifiedImpact,
      ModifiedSubsequentImpact,
      Safety,
      Automatable,
      Recovery,
      ValueDensity,
      VulnerabilityResponseEffort,
      ProviderUrgency,
    };

    #[test]
    fn test_from_str_fail() {
      let tests = vec!(
        ("empty", "", Err::Len),
        ("wrong prefix", "CVSS:3.1/", Err::Prefix),
        ("dup metric", "CVSS:4.0/AV:N/AV:N", Err::DuplicateName),
        ("dup name", "CVSS:4.0/AV:N/AV:A", Err::DuplicateName),
        ("unknown val", "CVSS:4.0/AV:Z", Err::UnknownMetric),
        ("unknown name", "CVSS:4.0/ZZ:Z", Err::UnknownMetric),
        ("missing AV", "CVSS:4.0/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", Err::MissingMandatoryMetrics),
        ("missing AC", "CVSS:4.0/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", Err::MissingMandatoryMetrics),
        ("missing AT", "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", Err::MissingMandatoryMetrics),
        ("missing PR", "CVSS:4.0/AV:N/AC:L/AT:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", Err::MissingMandatoryMetrics),
        ("missing UI", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", Err::MissingMandatoryMetrics),
        ("missing VC", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VI:H/VA:H/SC:H/SI:H/SA:H", Err::MissingMandatoryMetrics),
        ("missing VI", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VA:H/SC:H/SI:H/SA:H", Err::MissingMandatoryMetrics),
        ("missing VA", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/SC:H/SI:H/SA:H", Err::MissingMandatoryMetrics),
        ("missing SC", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SI:H/SA:H", Err::MissingMandatoryMetrics),
        ("missing SI", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SA:H", Err::MissingMandatoryMetrics),
        ("missing SA", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H", Err::MissingMandatoryMetrics),
      );

      for (name, s, exp) in tests {
        assert_eq!(s.parse::<Vector>(), Err(exp), "{name}");
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        // AV
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // AV:N
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // AV:N
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // AV:N
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // AV:N

        // AC
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // AC:L
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // AC:L

        // AT
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // AT:N
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // AT:P

        // PR
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // PR:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // PR:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // PR:H

        // UI
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // UI:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // UI:P
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // UI:A

        // VC
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // VC:H
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:H/SI:H/SA:H", // VC:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:H/SI:H/SA:H", // VC:L

        // VI
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // VI:H
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:H/SI:H/SA:H", // VI:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H", // VI:L

        // VA
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // VA:H
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:H", // VA:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:H", // VA:L

        // SC
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // SC:H
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:H", // SC:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:H", // SC:N

        // SI
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // SI:H
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H", // SI:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:N/SA:H", // SI:N

        // SA
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // SA:H
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:L", // SA:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N", // SA:N

        // E
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:X", // E:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A", // E:A
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P", // E:P
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U", // E:U

        // CR
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:X", // CR:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:H", // CR:H
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:M", // CR:M
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:L", // CR:L

        // IR
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/IR:X", // IR:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/IR:H", // IR:H
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/IR:M", // IR:M
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/IR:L", // IR:L

        // AR
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/AR:X", // AR:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/AR:H", // AR:H
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/AR:M", // AR:M
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/AR:L", // AR:L

        // MAV
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:X", // MAV:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:N", // MAV:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:A", // MAV:A
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:L", // MAV:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:P", // MAV:P

        // MAC
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAC:X", // MAC:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAC:L", // MAC:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAC:H", // MAC:H

        // MAT
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAT:X", // MAT:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAT:N", // MAT:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAT:P", // MAT:P

        // MPR
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MPR:X", // MPR:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MPR:N", // MPR:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MPR:L", // MPR:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MPR:H", // MPR:H

        // MUI
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MUI:X", // MUI:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MUI:N", // MUI:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MUI:P", // MUI:P
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MUI:A", // MUI:A

        // MVC
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVC:X", // MVC:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVC:N", // MVC:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVC:L", // MVC:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVC:H", // MVC:H

        // MVI
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVI:X", // MVI:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVI:N", // MVI:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVI:L", // MVI:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVI:H", // MVI:H

        // MVA
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVA:X", // MVA:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVA:N", // MVA:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVA:L", // MVA:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVA:H", // MVA:H

        // MSC
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSC:X", // MSC:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSC:N", // MSC:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSC:L", // MSC:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSC:H", // MSC:H

        // MSI
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:X", // MSI:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:N", // MSI:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:L", // MSI:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:H", // MSI:H
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:S", // MSI:S

        // MSA
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSA:X", // MSA:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSA:N", // MSA:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSA:L", // MSA:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSA:H", // MSA:H
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSA:S", // MSA:S

        // S
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:X", // S:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:N", // S:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P", // S:P

        // AU
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/AU:X", // AU:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/AU:N", // AU:N
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/AU:Y", // AU:Y

        // R
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:X", // R:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:A", // R:A
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:U", // R:U
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:I", // R:I

        // V
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/V:X", // V:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/V:D", // V:D
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/V:C", // V:C

        // RE
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/RE:X", // RE:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/RE:L", // RE:L
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/RE:M", // RE:M
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/RE:H", // RE:H

        // U
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/U:X", // U:X
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/U:Clear", // U:Clear
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/U:Green", // U:Green
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/U:Amber", // U:Amber
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/U:Red", // U:Red
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
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // val
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // exp
        ),

        (
          "everything", // name
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AV:A", // name
          "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AV:L", // name
          "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AV:L", // name
          "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AV:L", // name
          "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AV:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AT:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AT:P", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "PR:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "PR:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "PR:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "UI:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "UI:P", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "UI:A", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "VC:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "VC:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "VC:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "VI:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:H/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:H/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "VI:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "VI:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "VA:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "VA:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "VA:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "SC:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:H/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:H/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "SC:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "SC:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "SI:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:H/SI:H/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:H/SI:H/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "SI:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "SI:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "SA:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:H/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:H/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "SA:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "SA:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "E:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:X/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "E:A", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "E:P", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:P/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:P/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "E:U", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "CR:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:X/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "CR:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "CR:M", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:M/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:M/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "CR:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "IR:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:X/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "IR:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "IR:M", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:M/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:M/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "IR:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AR:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:X/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AR:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AR:M", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:M/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:M/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AR:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MAV:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:X/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MAV:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MAV:A", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:A/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:A/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MAV:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MAV:P", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MAC:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:X/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MAC:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MAC:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MAT:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:X/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MAT:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MAT:P", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MPR:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:X/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MPR:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MPR:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:L/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:L/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MPR:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MUI:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:X/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MUI:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MUI:P", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:P/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:P/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MUI:A", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVC:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:X/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVC:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVC:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:L/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:L/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVC:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVI:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:X/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVI:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVI:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:L/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:L/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVI:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVA:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:X/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVA:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVA:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:L/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:L/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MVA:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSC:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:X/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSC:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSC:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:L/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:L/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSC:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSI:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:X/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSI:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSI:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:L/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:L/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSI:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:H/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:H/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSI:S", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSA:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:X/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSA:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSA:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:L/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:L/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSA:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:H/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:H/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "MSA:S", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "S:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:X/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "S:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:N/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "S:P", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AU:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:X/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AU:N", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:N/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:N/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "AU:Y", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "R:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:X/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/V:D/RE:L/U:Clear", // exp
        ),

        (
          "R:A", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:A/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:A/V:D/RE:L/U:Clear", // exp
        ),

        (
          "R:U", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:U/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:U/V:D/RE:L/U:Clear", // exp
        ),

        (
          "R:I", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:D/RE:L/U:Clear", // exp
        ),

        (
          "V:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:X/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/RE:L/U:Clear", // exp
        ),

        (
          "V:D", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:D/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:D/RE:L/U:Clear", // exp
        ),

        (
          "V:C", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:L/U:Clear", // exp
        ),

        (
          "RE:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:X/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/U:Clear", // exp
        ),

        (
          "RE:L", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:L/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:L/U:Clear", // exp
        ),

        (
          "RE:M", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:M/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:M/U:Clear", // exp
        ),

        (
          "RE:H", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Clear", // exp
        ),

        (
          "U:X", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:X", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H", // exp
        ),

        (
          "U:Clear", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Clear", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Clear", // exp
        ),

        (
          "U:Green", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Green", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Green", // exp
        ),

        (
          "U:Amber", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Amber", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Amber", // exp
        ),

        (
          "U:Red", // name
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Red", // val
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Red", // exp
        ),
      );

      for (name, s, exp) in tests {
        assert_eq!(s.parse::<Vector>().expect(name).to_string(), exp, "{name}");
      }
    }

    #[test]
    fn test_get() {
      let tests = vec!((
        "base metric", // test name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // val
        Name::AttackVector, // metric name
        Metric::AttackVector(AttackVector::Network), // exp
      ), (
        "optional metric, not defined", // test name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // val
        Name::ModifiedAttackVector, // metric name
        Metric::ModifiedAttackVector(ModifiedAttackVector::NotDefined), // exp
      ), (
        "optional metric, defined", // test name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:P", // val
        Name::ModifiedAttackVector, // metric name
        Metric::ModifiedAttackVector(ModifiedAttackVector::Physical), // exp
      ));

      for (test_name, s, metric_name, exp) in tests {
        let v: Vector = s.parse().unwrap();
        assert_eq!(v.get(metric_name), exp, "{}", test_name);
      }
    }

    #[test]
    fn test_iter_explicit() {
      let tests = vec!(
        (
          "basic",
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
          vec!(
            Metric::AttackVector(AttackVector::Network),
            Metric::AttackComplexity(AttackComplexity::Low),
            Metric::AttackRequirements(AttackRequirements::None),
            Metric::PrivilegesRequired(PrivilegesRequired::None),
            Metric::UserInteraction(UserInteraction::None),
            Metric::VulnerableSystemConfidentialityImpact(Impact::High),
            Metric::VulnerableSystemIntegrityImpact(Impact::High),
            Metric::VulnerableSystemAvailabilityImpact(Impact::High),
            Metric::SubsequentSystemConfidentialityImpact(Impact::High),
            Metric::SubsequentSystemIntegrityImpact(Impact::High),
            Metric::SubsequentSystemAvailabilityImpact(Impact::High),
          )
        ),

        (
          "everything",
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:S/MSA:S/S:N/AU:Y/R:I/V:C/RE:H/U:Clear",
          vec!(
            Metric::AttackVector(AttackVector::Physical),
            Metric::AttackComplexity(AttackComplexity::High),
            Metric::AttackRequirements(AttackRequirements::Present),
            Metric::PrivilegesRequired(PrivilegesRequired::High),
            Metric::UserInteraction(UserInteraction::Active),
            Metric::VulnerableSystemConfidentialityImpact(Impact::High),
            Metric::VulnerableSystemIntegrityImpact(Impact::High),
            Metric::VulnerableSystemAvailabilityImpact(Impact::High),
            Metric::SubsequentSystemConfidentialityImpact(Impact::High),
            Metric::SubsequentSystemIntegrityImpact(Impact::High),
            Metric::SubsequentSystemAvailabilityImpact(Impact::High),
            Metric::ExploitMaturity(ExploitMaturity::Attacked),
            Metric::ConfidentialityRequirement(Requirement::High),
            Metric::IntegrityRequirement(Requirement::High),
            Metric::AvailabilityRequirement(Requirement::High),
            Metric::ModifiedAttackVector(ModifiedAttackVector::Physical),
            Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High),
            Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::Present),
            Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High),
            Metric::ModifiedUserInteraction(ModifiedUserInteraction::Active),
            Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::None),
            Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::None),
            Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::None),
            Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::None),
            Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Safety),
            Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Safety),
            Metric::Safety(Safety::Negligible),
            Metric::Automatable(Automatable::Yes),
            Metric::Recovery(Recovery::Irrecoverable),
            Metric::ValueDensity(ValueDensity::Concentrated),
            Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::High),
            Metric::ProviderUrgency(ProviderUrgency::Clear),
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
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
          vec!(
            Metric::AttackVector(AttackVector::Network),
            Metric::AttackComplexity(AttackComplexity::Low),
            Metric::AttackRequirements(AttackRequirements::None),
            Metric::PrivilegesRequired(PrivilegesRequired::None),
            Metric::UserInteraction(UserInteraction::None),
            Metric::VulnerableSystemConfidentialityImpact(Impact::High),
            Metric::VulnerableSystemIntegrityImpact(Impact::High),
            Metric::VulnerableSystemAvailabilityImpact(Impact::High),
            Metric::SubsequentSystemConfidentialityImpact(Impact::High),
            Metric::SubsequentSystemIntegrityImpact(Impact::High),
            Metric::SubsequentSystemAvailabilityImpact(Impact::High),
          )
        ),

        (
          "everything",
          "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:S/MSA:S/S:N/AU:Y/R:I/V:C/RE:H/U:Clear",
          vec!(
            Metric::AttackVector(AttackVector::Physical),
            Metric::AttackComplexity(AttackComplexity::High),
            Metric::AttackRequirements(AttackRequirements::Present),
            Metric::PrivilegesRequired(PrivilegesRequired::High),
            Metric::UserInteraction(UserInteraction::Active),
            Metric::VulnerableSystemConfidentialityImpact(Impact::High),
            Metric::VulnerableSystemIntegrityImpact(Impact::High),
            Metric::VulnerableSystemAvailabilityImpact(Impact::High),
            Metric::SubsequentSystemConfidentialityImpact(Impact::High),
            Metric::SubsequentSystemIntegrityImpact(Impact::High),
            Metric::SubsequentSystemAvailabilityImpact(Impact::High),
            Metric::ExploitMaturity(ExploitMaturity::Attacked),
            Metric::ConfidentialityRequirement(Requirement::High),
            Metric::IntegrityRequirement(Requirement::High),
            Metric::AvailabilityRequirement(Requirement::High),
            Metric::ModifiedAttackVector(ModifiedAttackVector::Physical),
            Metric::ModifiedAttackComplexity(ModifiedAttackComplexity::High),
            Metric::ModifiedAttackRequirements(ModifiedAttackRequirements::Present),
            Metric::ModifiedPrivilegesRequired(ModifiedPrivilegesRequired::High),
            Metric::ModifiedUserInteraction(ModifiedUserInteraction::Active),
            Metric::ModifiedVulnerableSystemConfidentiality(ModifiedImpact::None),
            Metric::ModifiedVulnerableSystemIntegrity(ModifiedImpact::None),
            Metric::ModifiedVulnerableSystemAvailability(ModifiedImpact::None),
            Metric::ModifiedSubsequentSystemConfidentiality(ModifiedImpact::None),
            Metric::ModifiedSubsequentSystemIntegrity(ModifiedSubsequentImpact::Safety),
            Metric::ModifiedSubsequentSystemAvailability(ModifiedSubsequentImpact::Safety),
            Metric::Safety(Safety::Negligible),
            Metric::Automatable(Automatable::Yes),
            Metric::Recovery(Recovery::Irrecoverable),
            Metric::ValueDensity(ValueDensity::Concentrated),
            Metric::VulnerabilityResponseEffort(VulnerabilityResponseEffort::High),
            Metric::ProviderUrgency(ProviderUrgency::Clear),
          )
        ),
      );

      for (name, s, exp) in tests {
        let mut got = Vec::new();
        for c in s.parse::<Vector>().unwrap() {
          got.push(c);
        }
        assert_eq!(got, exp, "{name}");
      }
    }

    #[test]
    fn test_from_vector() {
      let vec: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse().unwrap();
      assert_eq!(Version::from(vec), Version::V40);
    }

    #[test]
    fn test_size() {
      assert_eq!(size_of::<Vector>(), size_of::<u64>());
    }
  }

  mod values {
    use super::super::{
      Values,
      Vector,
      AttackVector,
      AttackComplexity,
      AttackRequirements,
      PrivilegesRequired,
      UserInteraction,
      Impact,
      SubsequentImpact,
      ExploitMaturity,
      Requirement,
    };

    #[test]
    fn test_from_vector() {
      let tests = vec!((
        "basic", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "mav", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MAV:P", // vec
        Values {
          av: AttackVector::Physical,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "mac", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MAC:H", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::High,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "mat", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MAT:N", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::None,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "mpr", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MPR:N", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::None,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "mui", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MUI:A", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::Active,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "mvc", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MVC:N", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::None,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "mvi", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MVI:L", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::Low,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "mva", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MVA:L", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::Low,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "msc", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MSC:L", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::Low,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "msi", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MSI:L", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::Low,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "msi:s", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MSI:S", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::Safety,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "msa", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MSA:L", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::Low,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "msa:s", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/MSA:S", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::Safety,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "cr", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/CR:L", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::Low,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "ir", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/IR:L", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::Low,
          ar: Requirement::High,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "ar", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/AR:L", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::Low,
          e: ExploitMaturity::Attacked,
        }, // exp
      ), (
        "e", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/E:U", // vec
        Values {
          av: AttackVector::Network,
          ac: AttackComplexity::Low,
          at: AttackRequirements::Present,
          pr: PrivilegesRequired::High,
          ui: UserInteraction::None,
          vc: Impact::Low,
          vi: Impact::None,
          va: Impact::None,
          sc: Impact::None,
          si: SubsequentImpact::High,
          sa: SubsequentImpact::None,
          cr: Requirement::High,
          ir: Requirement::High,
          ar: Requirement::High,
          e: ExploitMaturity::Unreported,
        }, // exp
      ));

      for (name, s, exp) in tests {
        let got = Values::from(s.parse::<Vector>().unwrap());
        assert_eq!(got, exp, "{name}");
      }
    }
  }

  mod macrovector {
    use super::super::{super::{Err, Score}, MacroVector, Vector};

    #[test]
    fn test_try_from_u32_fail() {
      let tests = vec!(
        ("eq1", 302211),
        ("eq2", 222211),
        ("eq3", 203211),
        ("eq4", 202311),
        ("eq5", 202231),
        ("eq6", 202212),
        ("max", 1202211),
      );

      for (name, val) in tests {
        let got = MacroVector::try_from(val as u32);
        assert_eq!(got, Err(Err::InvalidMacroVector), "{}", name);
      }
    }

    #[test]
    fn test_try_from_u32_pass() {
      let tests = vec!(
        (000000, MacroVector(0), Score(100)),
        (202211, MacroVector(266), Score(9)),
        (202221, MacroVector(320), Score(4)),
        (210000, MacroVector(5), Score(88)),
        (210001, MacroVector(167), Score(75)),
        (210010, MacroVector(59), Score(73)),
        (210011, MacroVector(221), Score(53)),
        (210020, MacroVector(113), Score(60)),
        (210021, MacroVector(275), Score(50)),
        (210100, MacroVector(23), Score(73)),
        (210101, MacroVector(185), Score(55)),
        (210110, MacroVector(77), Score(59)),
        (210111, MacroVector(239), Score(40)),
        (210120, MacroVector(131), Score(41)),
        (210121, MacroVector(293), Score(20)),
        (210200, MacroVector(41), Score(54)),
        (210201, MacroVector(203), Score(43)),
        (210210, MacroVector(95), Score(45)),
        (210211, MacroVector(257), Score(22)),
        (210220, MacroVector(149), Score(20)),
        (210221, MacroVector(311), Score(11)),
        (211000, MacroVector(11), Score(75)),
        (211001, MacroVector(173), Score(55)),
        (211010, MacroVector(65), Score(58)),
        (211011, MacroVector(227), Score(45)),
        (211020, MacroVector(119), Score(40)),
        (211021, MacroVector(281), Score(21)),
        (211100, MacroVector(29), Score(61)),
        (211101, MacroVector(191), Score(51)),
        (211110, MacroVector(83), Score(48)),
        (211111, MacroVector(245), Score(18)),
        (211120, MacroVector(137), Score(20)),
        (211121, MacroVector(299), Score(9)),
        (211200, MacroVector(47), Score(46)),
        (211201, MacroVector(209), Score(18)),
        (211210, MacroVector(101), Score(17)),
        (211211, MacroVector(263), Score(7)),
        (211220, MacroVector(155), Score(8)),
        (211221, MacroVector(317), Score(2)),
        (212001, MacroVector(179), Score(53)),
        (212011, MacroVector(233), Score(24)),
        (212021, MacroVector(287), Score(14)),
        (212101, MacroVector(197), Score(24)),
        (212111, MacroVector(251), Score(12)),
        (212121, MacroVector(305), Score(5)),
        (212201, MacroVector(215), Score(10)),
        (212211, MacroVector(269), Score(3)),
        (212221, MacroVector(323), Score(1)),
      );

      for (val, exp_mv, exp_score) in tests {
        let got_mv: MacroVector = (val as u32).try_into().unwrap();
        let got_score = Score::from(got_mv);
        assert_eq!((got_mv, got_score), (exp_mv, exp_score), "{val:06}");
      }
    }

    #[test]
    fn test_into_u32() {
      let tests = vec!(
        (MacroVector(0), 000000),
        (MacroVector(266), 202211),
        (MacroVector(266), 202211),
        (MacroVector(320), 202221),
        (MacroVector(5), 210000),
        (MacroVector(167), 210001),
        (MacroVector(59), 210010),
        (MacroVector(221), 210011),
        (MacroVector(113), 210020),
        (MacroVector(275), 210021),
        (MacroVector(23), 210100),
        (MacroVector(185), 210101),
        (MacroVector(77), 210110),
        (MacroVector(239), 210111),
        (MacroVector(131), 210120),
        (MacroVector(293), 210121),
        (MacroVector(41), 210200),
        (MacroVector(203), 210201),
        (MacroVector(95), 210210),
        (MacroVector(257), 210211),
        (MacroVector(149), 210220),
        (MacroVector(311), 210221),
        (MacroVector(11), 211000),
        (MacroVector(173), 211001),
        (MacroVector(65), 211010),
        (MacroVector(227), 211011),
        (MacroVector(119), 211020),
        (MacroVector(281), 211021),
        (MacroVector(29), 211100),
        (MacroVector(191), 211101),
        (MacroVector(83), 211110),
        (MacroVector(245), 211111),
        (MacroVector(137), 211120),
        (MacroVector(299), 211121),
        (MacroVector(47), 211200),
        (MacroVector(209), 211201),
        (MacroVector(101), 211210),
        (MacroVector(263), 211211),
        (MacroVector(155), 211220),
        (MacroVector(317), 211221),
        (MacroVector(179), 212001),
        (MacroVector(233), 212011),
        (MacroVector(287), 212021),
        (MacroVector(197), 212101),
        (MacroVector(251), 212111),
        (MacroVector(305), 212121),
        (MacroVector(215), 212201),
        (MacroVector(269), 212211),
        (MacroVector(323), 212221),
      );

      for (val, exp) in tests {
        assert_eq!(u32::from(val), exp, "{val}");
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (MacroVector(0), "000000"),
        (MacroVector(266), "202211"),
        (MacroVector(320), "202221"),
        (MacroVector(5), "210000"),
        (MacroVector(167), "210001"),
        (MacroVector(59), "210010"),
        (MacroVector(221), "210011"),
        (MacroVector(113), "210020"),
        (MacroVector(275), "210021"),
        (MacroVector(23), "210100"),
        (MacroVector(185), "210101"),
        (MacroVector(77), "210110"),
        (MacroVector(239), "210111"),
        (MacroVector(131), "210120"),
        (MacroVector(293), "210121"),
        (MacroVector(41), "210200"),
        (MacroVector(203), "210201"),
        (MacroVector(95), "210210"),
        (MacroVector(257), "210211"),
        (MacroVector(149), "210220"),
        (MacroVector(311), "210221"),
        (MacroVector(11), "211000"),
        (MacroVector(173), "211001"),
        (MacroVector(65), "211010"),
        (MacroVector(227), "211011"),
        (MacroVector(119), "211020"),
        (MacroVector(281), "211021"),
        (MacroVector(29), "211100"),
        (MacroVector(191), "211101"),
        (MacroVector(83), "211110"),
        (MacroVector(245), "211111"),
        (MacroVector(137), "211120"),
        (MacroVector(299), "211121"),
        (MacroVector(47), "211200"),
        (MacroVector(209), "211201"),
        (MacroVector(101), "211210"),
        (MacroVector(263), "211211"),
        (MacroVector(155), "211220"),
        (MacroVector(317), "211221"),
        (MacroVector(179), "212001"),
        (MacroVector(233), "212011"),
        (MacroVector(287), "212021"),
        (MacroVector(197), "212101"),
        (MacroVector(251), "212111"),
        (MacroVector(305), "212121"),
        (MacroVector(215), "212201"),
        (MacroVector(269), "212211"),
        (MacroVector(323), "212221"),
      );

      for (val, exp) in tests {
        assert_eq!(val.to_string(), exp, "{exp}");
      }
    }

    #[test]
    fn test_from_vector() {
      let tests = vec!((
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", // vec
        002201, // exp
      ), (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", // vec
        112201, // exp
      ), (
       "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:H/SA:N/CR:M/IR:L/MAC:H/MAT:P/S:N/AU:N/R:U/RE:L/U:Clear", // vec
       112101, // exp
      ));

      for (s, exp) in tests {
        let got = MacroVector::from(s.parse::<Vector>().unwrap());
        let exp: MacroVector = exp.try_into().unwrap();
        assert_eq!(got, exp, "{s}");
      }
    }
  }

  mod scores {
    use super::super::{super::Score, MacroVector, Scores, Vector};

    #[test]
    fn test_from_vector() {
      let tests = vec!((
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", // val
        002201, // exp mv
        Score(69), // exp score
      ), (
        "test 9.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", // val
        000200, // exp mv
        Score(93), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", // val
        100200, // exp mv
        Score(85), // exp score
      ), (
        "test 8.8 asdf", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", // val
        001200, // exp mv
        Score(88), // exp score
      ), (
        "test 7.0", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N", // val
        101200, // exp mv
        Score(70), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:H/SA:H", // val
        211100, // exp mv
        Score(59), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:H/SA:H", // val
        210100, // exp mv
        Score(72), // exp score
      ), (
        "test 6.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:H/SA:H/MSC:H/MSI:S/MSA:S", // val
        202001, // exp mv
        Score(64), // exp score
      ), (
        "test 6.0", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:H/SA:H", // val
        211100, // exp mv
        Score(60), // exp score
      ), (
        "test 9.1",
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:H/SA:H", // val
        011100, // exp mv
        Score(91), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:L/VI:N/VA:L/SC:H/SI:L/SA:H/E:X/CR:X/IR:M/AR:L/MAV:N/MAC:X/MAT:X/MPR:H/MUI:X/MVC:L/MVI:L/MVA:N/MSC:H/MSI:N/MSA:H", // val
        112101, // exp mv
        Score(45), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:L/SC:L/SI:H/SA:L/E:P/CR:H/IR:L/AR:L/MAV:P/MAC:L/MAT:X/MPR:L/MUI:P/MVC:H/MVI:L/MVA:H/MSC:H/MSI:N/MSA:X", // val
        211110, // exp mv
        Score(37), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:H/SI:N/SA:N/E:A/CR:M/IR:M/AR:H/MAV:N/MAC:X/MAT:P/MPR:X/MUI:A/MVC:X/MVI:H/MVA:X/MSC:H/MSI:X/MSA:H", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:P/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N/E:U/CR:M/IR:X/AR:X/MAV:L/MAC:H/MAT:N/MPR:X/MUI:X/MVC:L/MVI:H/MVA:L/MSC:L/MSI:H/MSA:L", // val
        211120, // exp mv
        Score(16), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:N/VA:N/SC:H/SI:N/SA:L/E:X/CR:X/IR:M/AR:X/MAV:N/MAC:X/MAT:X/MPR:N/MUI:A/MVC:X/MVI:H/MVA:H/MSC:H/MSI:X/MSA:H", // val
        101100, // exp mv
        Score(84), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:N/VC:H/VI:N/VA:H/SC:N/SI:L/SA:L/E:P/CR:M/IR:H/AR:L/MAV:L/MAC:X/MAT:N/MPR:N/MUI:X/MVC:N/MVI:X/MVA:X/MSC:L/MSI:N/MSA:L", // val
        101211, // exp mv
        Score(46), // exp score
      ), (
        "test 6", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:H/VI:H/VA:H/SC:H/SI:L/SA:L/E:U/CR:X/IR:X/AR:L/MAV:A/MAC:L/MAT:X/MPR:H/MUI:A/MVC:H/MVI:L/MVA:H/MSC:H/MSI:S/MSA:H", // val
        201020, // exp mv
        Score(60), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:N/VI:H/VA:H/SC:H/SI:L/SA:H/E:A/CR:X/IR:M/AR:M/MAV:N/MAC:X/MAT:N/MPR:L/MUI:X/MVC:N/MVI:N/MVA:H/MSC:H/MSI:X/MSA:H", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N/E:A/CR:L/IR:X/AR:L/MAV:N/MAC:L/MAT:P/MPR:N/MUI:P/MVC:X/MVI:N/MVA:X/MSC:H/MSI:L/MSA:H", // val
        112101, // exp mv
        Score(56), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:L/E:A/CR:L/IR:M/AR:L/MAV:P/MAC:L/MAT:X/MPR:H/MUI:A/MVC:H/MVI:L/MVA:X/MSC:X/MSI:N/MSA:N", // val
        211201, // exp mv
        Score(16), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:H/VI:L/VA:L/SC:L/SI:L/SA:N/E:U/CR:M/IR:L/AR:X/MAV:L/MAC:X/MAT:N/MPR:N/MUI:A/MVC:L/MVI:L/MVA:X/MSC:X/MSI:N/MSA:S", // val
        112021, // exp mv
        Score(19), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:L/SC:N/SI:H/SA:L/E:A/CR:M/IR:L/AR:H/MAV:A/MAC:X/MAT:N/MPR:N/MUI:N/MVC:X/MVI:L/MVA:H/MSC:N/MSI:N/MSA:N", // val
        101200, // exp mv
        Score(71), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:L/SC:H/SI:H/SA:N/E:X/CR:X/IR:H/AR:H/MAV:L/MAC:H/MAT:P/MPR:L/MUI:N/MVC:N/MVI:H/MVA:H/MSC:L/MSI:S/MSA:N", // val
        111000, // exp mv
        Score(84), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:M/IR:H/AR:X/MAV:X/MAC:X/MAT:P/MPR:X/MUI:N/MVC:X/MVI:L/MVA:N/MSC:X/MSI:L/MSA:N", // val
        112101, // exp mv
        Score(43), // exp score
      ), (
        "test 6.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:L/SI:N/SA:L/E:X/CR:L/IR:L/AR:H/MAV:L/MAC:X/MAT:N/MPR:L/MUI:N/MVC:N/MVI:N/MVA:N/MSC:H/MSI:N/MSA:S", // val
        112001, // exp mv
        Score(66), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H/E:X/CR:H/IR:M/AR:H/MAV:N/MAC:H/MAT:X/MPR:H/MUI:X/MVC:H/MVI:N/MVA:L/MSC:N/MSI:H/MSA:S", // val
        111000, // exp mv
        Score(85), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:H/E:A/CR:L/IR:M/AR:X/MAV:L/MAC:H/MAT:P/MPR:L/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:S", // val
        212001, // exp mv
        Score(41), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N/E:P/CR:H/IR:L/AR:M/MAV:A/MAC:X/MAT:N/MPR:N/MUI:A/MVC:L/MVI:H/MVA:N/MSC:X/MSI:X/MSA:H", // val
        101111, // exp mv
        Score(56), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:N/VI:H/VA:N/SC:N/SI:H/SA:H/E:U/CR:M/IR:H/AR:X/MAV:P/MAC:L/MAT:X/MPR:L/MUI:P/MVC:H/MVI:X/MVA:N/MSC:L/MSI:X/MSA:S", // val
        200020, // exp mv
        Score(71), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:H/E:P/CR:M/IR:X/AR:L/MAV:A/MAC:X/MAT:N/MPR:X/MUI:N/MVC:H/MVI:X/MVA:X/MSC:N/MSI:L/MSA:L", // val
        100210, // exp mv
        Score(71), // exp score
      ), (
        "test 0.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L/E:U/CR:M/IR:H/AR:M/MAV:N/MAC:H/MAT:N/MPR:N/MUI:X/MVC:N/MVI:X/MVA:X/MSC:N/MSI:N/MSA:L", // val
        112221, // exp mv
        Score(5), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:H/E:P/CR:M/IR:X/AR:L/MAV:L/MAC:X/MAT:N/MPR:H/MUI:N/MVC:L/MVI:L/MVA:L/MSC:N/MSI:X/MSA:X", // val
        112111, // exp mv
        Score(19), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:N/VI:N/VA:H/SC:H/SI:L/SA:N/E:X/CR:M/IR:H/AR:M/MAV:P/MAC:X/MAT:N/MPR:N/MUI:X/MVC:H/MVI:H/MVA:H/MSC:H/MSI:L/MSA:L", // val
        200100, // exp mv
        Score(84), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:L/SA:N/E:X/CR:L/IR:L/AR:L/MAV:L/MAC:X/MAT:X/MPR:H/MUI:A/MVC:X/MVI:X/MVA:X/MSC:L/MSI:S/MSA:N", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:H/VI:L/VA:H/SC:N/SI:L/SA:H/E:A/CR:L/IR:M/AR:X/MAV:X/MAC:H/MAT:N/MPR:X/MUI:X/MVC:N/MVI:X/MVA:L/MSC:N/MSI:H/MSA:X", // val
        212101, // exp mv
        Score(21), // exp score
      ), (
        "test 5", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:L/SC:L/SI:L/SA:N/E:P/CR:X/IR:X/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:X/MSA:L", // val
        111210, // exp mv
        Score(50), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:L/SA:L/E:X/CR:H/IR:H/AR:X/MAV:X/MAC:X/MAT:N/MPR:X/MUI:A/MVC:L/MVI:N/MVA:L/MSC:H/MSI:H/MSA:X", // val
        212101, // exp mv
        Score(23), // exp score
      ), (
        "test 4.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:N/SC:L/SI:N/SA:N/E:P/CR:M/IR:X/AR:H/MAV:A/MAC:L/MAT:P/MPR:N/MUI:P/MVC:N/MVI:X/MVA:N/MSC:X/MSI:L/MSA:N", // val
        111210, // exp mv
        Score(49), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:L/E:P/CR:H/IR:X/AR:X/MAV:A/MAC:X/MAT:N/MPR:X/MUI:X/MVC:H/MVI:X/MVA:N/MSC:H/MSI:X/MSA:S", // val
        200010, // exp mv
        Score(85), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:H/SC:H/SI:H/SA:N/E:A/CR:X/IR:H/AR:M/MAV:N/MAC:X/MAT:P/MPR:L/MUI:A/MVC:X/MVI:H/MVA:L/MSC:X/MSI:S/MSA:X", // val
        111000, // exp mv
        Score(85), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:H/E:A/CR:L/IR:H/AR:L/MAV:X/MAC:H/MAT:X/MPR:N/MUI:A/MVC:N/MVI:N/MVA:L/MSC:N/MSI:H/MSA:X", // val
        212101, // exp mv
        Score(21), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N/E:P/CR:H/IR:M/AR:X/MAV:P/MAC:L/MAT:X/MPR:N/MUI:P/MVC:N/MVI:H/MVA:L/MSC:H/MSI:S/MSA:L", // val
        211011, // exp mv
        Score(41), // exp score
      ), (
        "test 3.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:X/IR:X/AR:L/MAV:L/MAC:H/MAT:P/MPR:N/MUI:X/MVC:X/MVI:H/MVA:H/MSC:X/MSI:L/MSA:N", // val
        111120, // exp mv
        Score(36), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:L/VI:N/VA:N/SC:H/SI:H/SA:L/E:X/CR:X/IR:M/AR:L/MAV:A/MAC:L/MAT:X/MPR:N/MUI:N/MVC:H/MVI:X/MVA:X/MSC:H/MSI:L/MSA:L", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:L/VI:H/VA:N/SC:N/SI:H/SA:H/E:P/CR:H/IR:M/AR:H/MAV:X/MAC:H/MAT:X/MPR:L/MUI:A/MVC:H/MVI:L/MVA:L/MSC:N/MSI:N/MSA:X", // val
        211110, // exp mv
        Score(37), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:L/VI:N/VA:H/SC:L/SI:L/SA:H/E:U/CR:L/IR:X/AR:X/MAV:X/MAC:X/MAT:N/MPR:H/MUI:X/MVC:N/MVI:H/MVA:H/MSC:N/MSI:S/MSA:H", // val
        101020, // exp mv
        Score(70), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:L/SC:N/SI:H/SA:N/E:P/CR:M/IR:X/AR:X/MAV:A/MAC:X/MAT:X/MPR:L/MUI:X/MVC:N/MVI:N/MVA:L/MSC:N/MSI:L/MSA:S", // val
        202011, // exp mv
        Score(44), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:H/E:X/CR:M/IR:X/AR:X/MAV:P/MAC:L/MAT:P/MPR:X/MUI:A/MVC:H/MVI:N/MVA:L/MSC:H/MSI:S/MSA:X", // val
        211001, // exp mv
        Score(55), // exp score
      ), (
        "test 4.7", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:P/VC:H/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:L/IR:H/AR:L/MAV:N/MAC:X/MAT:P/MPR:N/MUI:P/MVC:H/MVI:N/MVA:X/MSC:L/MSI:N/MSA:X", // val
        111201, // exp mv
        Score(47), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:L/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:A/MVC:L/MVI:X/MVA:L/MSC:H/MSI:N/MSA:L", // val
        111121, // exp mv
        Score(18), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:P/VC:N/VI:H/VA:H/SC:H/SI:L/SA:N/E:A/CR:L/IR:X/AR:M/MAV:N/MAC:X/MAT:P/MPR:X/MUI:X/MVC:L/MVI:L/MVA:L/MSC:N/MSI:L/MSA:L", // val
        112201, // exp mv
        Score(20), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:L/E:X/CR:L/IR:L/AR:H/MAV:N/MAC:L/MAT:P/MPR:N/MUI:P/MVC:X/MVI:X/MVA:X/MSC:X/MSI:H/MSA:X", // val
        111100, // exp mv
        Score(69), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:H/SI:L/SA:L/E:A/CR:H/IR:M/AR:X/MAV:P/MAC:X/MAT:X/MPR:N/MUI:A/MVC:H/MVI:H/MVA:L/MSC:L/MSI:X/MSA:S", // val
        210000, // exp mv
        Score(84), // exp score
      ), (
        "test 5.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:L/SI:L/SA:L/E:U/CR:M/IR:H/AR:H/MAV:L/MAC:H/MAT:P/MPR:H/MUI:P/MVC:H/MVI:H/MVA:N/MSC:L/MSI:N/MSA:S", // val
        210020, // exp mv
        Score(52), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:H/VI:H/VA:N/SC:H/SI:L/SA:N/E:P/CR:X/IR:X/AR:X/MAV:P/MAC:H/MAT:X/MPR:X/MUI:N/MVC:L/MVI:L/MVA:H/MSC:L/MSI:N/MSA:X", // val
        211210, // exp mv
        Score(16), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:L/E:P/CR:M/IR:X/AR:H/MAV:P/MAC:L/MAT:P/MPR:H/MUI:P/MVC:N/MVI:L/MVA:X/MSC:L/MSI:S/MSA:N", // val
        212011, // exp mv
        Score(20), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:L/VI:N/VA:L/SC:L/SI:N/SA:L/E:A/CR:H/IR:L/AR:H/MAV:L/MAC:X/MAT:X/MPR:L/MUI:P/MVC:H/MVI:X/MVA:X/MSC:X/MSI:N/MSA:N", // val
        211200, // exp mv
        Score(39), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:A/VC:H/VI:N/VA:L/SC:L/SI:H/SA:H/E:A/CR:M/IR:M/AR:X/MAV:N/MAC:H/MAT:N/MPR:X/MUI:P/MVC:N/MVI:N/MVA:H/MSC:L/MSI:N/MSA:N", // val
        111200, // exp mv
        Score(57), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:L/SA:N/E:P/CR:M/IR:M/AR:M/MAV:X/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:L/MVA:L/MSC:X/MSI:N/MSA:H", // val
        112111, // exp mv
        Score(21), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H/E:A/CR:H/IR:M/AR:M/MAV:X/MAC:L/MAT:P/MPR:X/MUI:N/MVC:H/MVI:N/MVA:H/MSC:L/MSI:L/MSA:X", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:L/VI:L/VA:H/SC:L/SI:H/SA:H/E:X/CR:L/IR:M/AR:X/MAV:A/MAC:H/MAT:X/MPR:X/MUI:N/MVC:L/MVI:L/MVA:H/MSC:L/MSI:N/MSA:L", // val
        111200, // exp mv
        Score(58), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:H/SI:L/SA:H/E:X/CR:M/IR:M/AR:H/MAV:P/MAC:X/MAT:N/MPR:H/MUI:P/MVC:H/MVI:N/MVA:X/MSC:H/MSI:S/MSA:X", // val
        201000, // exp mv
        Score(84), // exp score
      ), (
        "test 2.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:L/SA:L/E:U/CR:M/IR:X/AR:L/MAV:X/MAC:H/MAT:N/MPR:X/MUI:A/MVC:N/MVI:H/MVA:H/MSC:N/MSI:S/MSA:L", // val
        211020, // exp mv
        Score(29), // exp score
      ), (
        "test 8.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:H/E:U/CR:H/IR:M/AR:X/MAV:X/MAC:L/MAT:X/MPR:L/MUI:N/MVC:H/MVI:H/MVA:X/MSC:N/MSI:S/MSA:S", // val
        100020, // exp mv
        Score(89), // exp score
      ), (
        "test 9.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:L/SI:N/SA:L/E:X/CR:M/IR:L/AR:X/MAV:N/MAC:X/MAT:N/MPR:X/MUI:N/MVC:L/MVI:X/MVA:X/MSC:X/MSI:S/MSA:H", // val
        011001, // exp mv
        Score(91), // exp score
      ), (
        "test 9.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:N/VI:L/VA:H/SC:L/SI:L/SA:N/E:A/CR:M/IR:M/AR:H/MAV:N/MAC:L/MAT:P/MPR:H/MUI:X/MVC:H/MVI:H/MVA:X/MSC:L/MSI:S/MSA:S", // val
        110000, // exp mv
        Score(94), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:H/SC:H/SI:L/SA:L/E:U/CR:M/IR:M/AR:M/MAV:X/MAC:L/MAT:X/MPR:N/MUI:X/MVC:N/MVI:L/MVA:H/MSC:H/MSI:N/MSA:L", // val
        111121, // exp mv
        Score(19), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:N/VI:L/VA:L/SC:H/SI:L/SA:L/E:P/CR:X/IR:H/AR:H/MAV:N/MAC:L/MAT:X/MPR:X/MUI:X/MVC:L/MVI:X/MVA:L/MSC:X/MSI:H/MSA:L", // val
        102111, // exp mv
        Score(56), // exp score
      ), (
        "test 9.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N/E:P/CR:H/IR:L/AR:M/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:X/MVI:L/MVA:L/MSC:L/MSI:S/MSA:X", // val
        001010, // exp mv
        Score(94), // exp score
      ), (
        "test 5.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:P/CR:X/IR:M/AR:M/MAV:A/MAC:L/MAT:X/MPR:X/MUI:X/MVC:H/MVI:L/MVA:X/MSC:H/MSI:H/MSA:L", // val
        201110, // exp mv
        Score(52), // exp score
      ), (
        "test 6.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:H/VI:N/VA:H/SC:L/SI:N/SA:H/E:A/CR:M/IR:M/AR:M/MAV:A/MAC:L/MAT:N/MPR:N/MUI:P/MVC:N/MVI:N/MVA:L/MSC:X/MSI:H/MSA:L", // val
        102101, // exp mv
        Score(63), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:L/VI:H/VA:L/SC:L/SI:N/SA:N/E:A/CR:M/IR:M/AR:M/MAV:A/MAC:X/MAT:P/MPR:X/MUI:N/MVC:X/MVI:X/MVA:N/MSC:H/MSI:N/MSA:N", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:L/VI:N/VA:H/SC:N/SI:N/SA:H/E:A/CR:M/IR:M/AR:H/MAV:L/MAC:L/MAT:N/MPR:H/MUI:X/MVC:N/MVI:L/MVA:L/MSC:H/MSI:H/MSA:N", // val
        202101, // exp mv
        Score(44), // exp score
      ), (
        "test 9.4", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:H/SC:H/SI:H/SA:L/E:A/CR:X/IR:X/AR:X/MAV:A/MAC:L/MAT:X/MPR:N/MUI:A/MVC:X/MVI:H/MVA:L/MSC:X/MSI:L/MSA:S", // val
        110000, // exp mv
        Score(94), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:L/VI:H/VA:N/SC:L/SI:L/SA:L/E:P/CR:M/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:N/MUI:A/MVC:X/MVI:H/MVA:X/MSC:L/MSI:L/MSA:X", // val
        211210, // exp mv
        Score(15), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:H/SC:L/SI:H/SA:L/E:A/CR:M/IR:M/AR:L/MAV:P/MAC:H/MAT:P/MPR:L/MUI:A/MVC:L/MVI:H/MVA:N/MSC:L/MSI:N/MSA:N", // val
        211201, // exp mv
        Score(16), // exp score
      ), (
        "test 6.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:N/VI:N/VA:N/SC:H/SI:N/SA:L/E:P/CR:M/IR:M/AR:L/MAV:A/MAC:X/MAT:N/MPR:X/MUI:N/MVC:X/MVI:H/MVA:L/MSC:N/MSI:X/MSA:S", // val
        111011, // exp mv
        Score(61), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:H/E:X/CR:X/IR:X/AR:L/MAV:N/MAC:L/MAT:X/MPR:L/MUI:P/MVC:L/MVI:X/MVA:H/MSC:H/MSI:N/MSA:L", // val
        101100, // exp mv
        Score(83), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:H/VA:H/SC:L/SI:H/SA:N/E:A/CR:X/IR:M/AR:X/MAV:P/MAC:L/MAT:P/MPR:X/MUI:N/MVC:N/MVI:N/MVA:L/MSC:L/MSI:N/MSA:N", // val
        212201, // exp mv
        Score(10), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:H/SC:L/SI:L/SA:N/E:X/CR:M/IR:X/AR:M/MAV:A/MAC:L/MAT:P/MPR:X/MUI:A/MVC:N/MVI:H/MVA:X/MSC:X/MSI:S/MSA:N", // val
        211000, // exp mv
        Score(69), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:A/VC:N/VI:L/VA:L/SC:H/SI:L/SA:L/E:P/CR:L/IR:H/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:P/MVC:L/MVI:N/MVA:L/MSC:X/MSI:L/MSA:S", // val
        102011, // exp mv
        Score(67), // exp score
      ), (
        "test 3.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:L/E:X/CR:L/IR:M/AR:L/MAV:N/MAC:X/MAT:N/MPR:H/MUI:X/MVC:N/MVI:H/MVA:X/MSC:N/MSI:L/MSA:X", // val
        111201, // exp mv
        Score(36), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:L/VI:H/VA:N/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:X/MAV:P/MAC:H/MAT:X/MPR:H/MUI:N/MVC:H/MVI:X/MVA:X/MSC:X/MSI:H/MSA:L", // val
        210110, // exp mv
        Score(56), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:H/VI:L/VA:L/SC:N/SI:L/SA:N/E:X/CR:H/IR:H/AR:H/MAV:P/MAC:H/MAT:X/MPR:X/MUI:X/MVC:L/MVI:X/MVA:L/MSC:L/MSI:N/MSA:X", // val
        212201, // exp mv
        Score(10), // exp score
      ), (
        "test 4.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:H/VA:H/SC:H/SI:N/SA:L/E:U/CR:M/IR:L/AR:L/MAV:A/MAC:L/MAT:N/MPR:N/MUI:P/MVC:X/MVI:H/MVA:H/MSC:N/MSI:H/MSA:X", // val
        101121, // exp mv
        Score(42), // exp score
      ), (
        "test 3.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:N/VA:L/SC:H/SI:L/SA:N/E:U/CR:L/IR:L/AR:M/MAV:A/MAC:H/MAT:X/MPR:X/MUI:P/MVC:H/MVI:H/MVA:N/MSC:N/MSI:H/MSA:S", // val
        210021, // exp mv
        Score(33), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:L/SC:N/SI:N/SA:L/E:U/CR:M/IR:L/AR:L/MAV:A/MAC:H/MAT:N/MPR:X/MUI:A/MVC:N/MVI:H/MVA:H/MSC:N/MSI:S/MSA:N", // val
        111021, // exp mv
        Score(37), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:H/SA:N/E:X/CR:L/IR:M/AR:M/MAV:L/MAC:X/MAT:X/MPR:N/MUI:X/MVC:N/MVI:L/MVA:H/MSC:H/MSI:H/MSA:H", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:H/E:U/CR:H/IR:X/AR:L/MAV:X/MAC:L/MAT:P/MPR:X/MUI:A/MVC:L/MVI:N/MVA:N/MSC:H/MSI:N/MSA:X", // val
        112121, // exp mv
        Score(9), // exp score
      ), (
        "test 5", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/CR:X/IR:M/AR:H/MAV:N/MAC:X/MAT:N/MPR:L/MUI:X/MVC:X/MVI:X/MVA:L/MSC:X/MSI:X/MSA:L", // val
        102111, // exp mv
        Score(50), // exp score
      ), (
        "test 6.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:H/SC:L/SI:N/SA:H/E:A/CR:H/IR:X/AR:H/MAV:L/MAC:X/MAT:N/MPR:L/MUI:P/MVC:L/MVI:N/MVA:N/MSC:N/MSI:H/MSA:S", // val
        202001, // exp mv
        Score(61), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:H/E:P/CR:M/IR:H/AR:M/MAV:N/MAC:H/MAT:N/MPR:X/MUI:X/MVC:L/MVI:X/MVA:L/MSC:L/MSI:S/MSA:S", // val
        112011, // exp mv
        Score(57), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H/E:U/CR:L/IR:M/AR:X/MAV:L/MAC:L/MAT:P/MPR:H/MUI:N/MVC:L/MVI:X/MVA:L/MSC:L/MSI:L/MSA:L", // val
        111221, // exp mv
        Score(10), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H/E:U/CR:L/IR:M/AR:X/MAV:X/MAC:L/MAT:P/MPR:H/MUI:N/MVC:L/MVI:X/MVA:N/MSC:L/MSI:N/MSA:X", // val
        111121, // exp mv
        Score(19), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:H/SA:L/E:X/CR:L/IR:M/AR:X/MAV:X/MAC:L/MAT:P/MPR:X/MUI:N/MVC:H/MVI:L/MVA:X/MSC:X/MSI:N/MSA:X", // val
        111201, // exp mv
        Score(46), // exp score
      ), (
        "test 3.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:L/SC:H/SI:H/SA:N/E:U/CR:M/IR:H/AR:X/MAV:P/MAC:H/MAT:X/MPR:N/MUI:X/MVC:N/MVI:H/MVA:X/MSC:H/MSI:S/MSA:L", // val
        211020, // exp mv
        Score(33), // exp score
      ), (
        "test 3.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:N/SC:H/SI:L/SA:H/E:U/CR:L/IR:L/AR:L/MAV:N/MAC:X/MAT:P/MPR:L/MUI:X/MVC:H/MVI:X/MVA:H/MSC:N/MSI:L/MSA:H", // val
        110121, // exp mv
        Score(38), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:N/VI:L/VA:L/SC:N/SI:H/SA:L/E:P/CR:M/IR:H/AR:L/MAV:X/MAC:H/MAT:N/MPR:X/MUI:P/MVC:L/MVI:X/MVA:N/MSC:H/MSI:H/MSA:L", // val
        212111, // exp mv
        Score(11), // exp score
      ), (
        "test 3.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:H/VI:N/VA:H/SC:N/SI:L/SA:L/E:U/CR:M/IR:M/AR:H/MAV:X/MAC:H/MAT:X/MPR:N/MUI:N/MVC:X/MVI:N/MVA:H/MSC:L/MSI:S/MSA:X", // val
        211020, // exp mv
        Score(31), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:H/VI:L/VA:H/SC:N/SI:H/SA:L/E:P/CR:H/IR:H/AR:L/MAV:N/MAC:H/MAT:X/MPR:H/MUI:P/MVC:H/MVI:N/MVA:L/MSC:N/MSI:X/MSA:L", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N/E:A/CR:H/IR:X/AR:M/MAV:P/MAC:L/MAT:P/MPR:X/MUI:A/MVC:X/MVI:H/MVA:X/MSC:N/MSI:S/MSA:H", // val
        211000, // exp mv
        Score(69), // exp score
      ), (
        "test 6.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:H/SC:L/SI:H/SA:H/E:P/CR:L/IR:M/AR:L/MAV:X/MAC:L/MAT:X/MPR:N/MUI:A/MVC:H/MVI:N/MVA:H/MSC:N/MSI:S/MSA:H", // val
        111011, // exp mv
        Score(62), // exp score
      ), (
        "test 7.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:H/SC:L/SI:L/SA:N/E:X/CR:M/IR:M/AR:M/MAV:N/MAC:X/MAT:P/MPR:L/MUI:X/MVC:N/MVI:H/MVA:X/MSC:N/MSI:H/MSA:S", // val
        111001, // exp mv
        Score(75), // exp score
      ), (
        "test 4.2", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:H/SC:L/SI:L/SA:H/E:P/CR:X/IR:M/AR:X/MAV:P/MAC:L/MAT:P/MPR:L/MUI:A/MVC:H/MVI:N/MVA:L/MSC:L/MSI:H/MSA:X", // val
        211110, // exp mv
        Score(42), // exp score
      ), (
        "test 6.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N/E:U/CR:M/IR:M/AR:L/MAV:N/MAC:X/MAT:P/MPR:L/MUI:A/MVC:H/MVI:H/MVA:X/MSC:H/MSI:X/MSA:S", // val
        110021, // exp mv
        Score(63), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:H/VI:N/VA:N/SC:L/SI:H/SA:H/E:X/CR:L/IR:X/AR:L/MAV:X/MAC:X/MAT:P/MPR:N/MUI:P/MVC:X/MVI:X/MVA:H/MSC:L/MSI:N/MSA:S", // val
        111001, // exp mv
        Score(73), // exp score
      ), (
        "test 9.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:L/SA:L/E:A/CR:X/IR:H/AR:M/MAV:N/MAC:H/MAT:X/MPR:N/MUI:X/MVC:X/MVI:H/MVA:N/MSC:X/MSI:S/MSA:H", // val
        110000, // exp mv
        Score(94), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:N/VA:H/SC:L/SI:H/SA:N/E:X/CR:M/IR:M/AR:H/MAV:P/MAC:L/MAT:N/MPR:H/MUI:N/MVC:L/MVI:X/MVA:X/MSC:H/MSI:L/MSA:L", // val
        201100, // exp mv
        Score(68), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:N/VI:L/VA:L/SC:H/SI:L/SA:H/E:X/CR:L/IR:M/AR:M/MAV:N/MAC:H/MAT:P/MPR:L/MUI:X/MVC:L/MVI:N/MVA:L/MSC:H/MSI:S/MSA:S", // val
        112001, // exp mv
        Score(68), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:H/SI:L/SA:L/E:A/CR:X/IR:M/AR:L/MAV:A/MAC:L/MAT:X/MPR:N/MUI:P/MVC:L/MVI:L/MVA:L/MSC:N/MSI:N/MSA:H", // val
        112101, // exp mv
        Score(46), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:H/VI:N/VA:H/SC:N/SI:L/SA:L/E:P/CR:M/IR:H/AR:M/MAV:X/MAC:L/MAT:P/MPR:N/MUI:X/MVC:H/MVI:X/MVA:L/MSC:N/MSI:X/MSA:L", // val
        111211, // exp mv
        Score(24), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:L/VI:L/VA:H/SC:H/SI:L/SA:H/E:A/CR:M/IR:M/AR:H/MAV:A/MAC:H/MAT:X/MPR:X/MUI:A/MVC:X/MVI:L/MVA:H/MSC:L/MSI:X/MSA:S", // val
        211000, // exp mv
        Score(70), // exp score
      ), (
        "test 0.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:L/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:L/IR:L/AR:M/MAV:A/MAC:H/MAT:X/MPR:L/MUI:A/MVC:X/MVI:H/MVA:H/MSC:X/MSI:L/MSA:X", // val
        211221, // exp mv
        Score(2), // exp score
      ), (
        "test 1.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:N/VI:L/VA:H/SC:H/SI:L/SA:L/E:U/CR:H/IR:L/AR:L/MAV:X/MAC:X/MAT:X/MPR:N/MUI:N/MVC:X/MVI:N/MVA:X/MSC:N/MSI:X/MSA:X", // val
        111221, // exp mv
        Score(13), // exp score
      ), (
        "test 0.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:H/SC:L/SI:N/SA:H/E:U/CR:L/IR:H/AR:X/MAV:P/MAC:H/MAT:N/MPR:N/MUI:N/MVC:X/MVI:X/MVA:N/MSC:N/MSI:N/MSA:X", // val
        212121, // exp mv
        Score(2), // exp score
      ), (
        "test 8.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:N/SC:H/SI:N/SA:H/E:A/CR:X/IR:H/AR:X/MAV:P/MAC:L/MAT:N/MPR:N/MUI:A/MVC:H/MVI:H/MVA:X/MSC:H/MSI:N/MSA:N", // val
        200100, // exp mv
        Score(82), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:H/SA:L/E:A/CR:X/IR:H/AR:M/MAV:L/MAC:X/MAT:N/MPR:L/MUI:P/MVC:L/MVI:H/MVA:X/MSC:X/MSI:S/MSA:N", // val
        211000, // exp mv
        Score(69), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:H/VI:N/VA:L/SC:H/SI:N/SA:L/E:A/CR:H/IR:M/AR:X/MAV:A/MAC:H/MAT:P/MPR:L/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:L/MSA:X", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:L/SI:H/SA:N/E:U/CR:H/IR:M/AR:X/MAV:P/MAC:X/MAT:N/MPR:H/MUI:X/MVC:N/MVI:H/MVA:L/MSC:L/MSI:H/MSA:S", // val
        211021, // exp mv
        Score(19), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:H/SA:N/E:A/CR:X/IR:H/AR:H/MAV:P/MAC:H/MAT:X/MPR:N/MUI:A/MVC:H/MVI:N/MVA:H/MSC:H/MSI:S/MSA:L", // val
        211000, // exp mv
        Score(73), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:L/VI:H/VA:H/SC:L/SI:N/SA:N/E:U/CR:M/IR:H/AR:X/MAV:L/MAC:L/MAT:N/MPR:N/MUI:P/MVC:N/MVI:X/MVA:L/MSC:H/MSI:S/MSA:S", // val
        101020, // exp mv
        Score(73), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:L/VI:N/VA:L/SC:N/SI:L/SA:N/E:A/CR:H/IR:H/AR:L/MAV:L/MAC:H/MAT:P/MPR:L/MUI:P/MVC:X/MVI:L/MVA:N/MSC:X/MSI:X/MSA:S", // val
        212001, // exp mv
        Score(43), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:H/SI:L/SA:H/E:A/CR:M/IR:H/AR:L/MAV:L/MAC:L/MAT:X/MPR:L/MUI:A/MVC:H/MVI:L/MVA:X/MSC:H/MSI:S/MSA:X", // val
        201001, // exp mv
        Score(73), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:P/VC:H/VI:L/VA:H/SC:H/SI:N/SA:H/E:P/CR:X/IR:L/AR:H/MAV:A/MAC:H/MAT:P/MPR:H/MUI:N/MVC:N/MVI:H/MVA:H/MSC:N/MSI:X/MSA:H", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:P/VC:H/VI:L/VA:H/SC:N/SI:L/SA:L/E:X/CR:H/IR:M/AR:M/MAV:N/MAC:X/MAT:X/MPR:H/MUI:A/MVC:H/MVI:N/MVA:H/MSC:H/MSI:H/MSA:X", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:P/VC:L/VI:L/VA:N/SC:L/SI:H/SA:H/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:X/MPR:N/MUI:X/MVC:L/MVI:X/MVA:L/MSC:L/MSI:L/MSA:S", // val
        112021, // exp mv
        Score(24), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:A/CR:L/IR:X/AR:X/MAV:L/MAC:H/MAT:N/MPR:N/MUI:N/MVC:H/MVI:X/MVA:N/MSC:X/MSI:H/MSA:H", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:P/VC:N/VI:L/VA:N/SC:L/SI:L/SA:H/E:U/CR:H/IR:L/AR:X/MAV:A/MAC:H/MAT:P/MPR:H/MUI:P/MVC:H/MVI:L/MVA:H/MSC:X/MSI:N/MSA:H", // val
        211120, // exp mv
        Score(15), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:P/VC:N/VI:N/VA:H/SC:H/SI:H/SA:N/E:A/CR:X/IR:L/AR:L/MAV:N/MAC:X/MAT:P/MPR:X/MUI:N/MVC:L/MVI:N/MVA:H/MSC:X/MSI:X/MSA:N", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:H/E:A/CR:M/IR:M/AR:L/MAV:L/MAC:X/MAT:N/MPR:N/MUI:N/MVC:H/MVI:N/MVA:X/MSC:H/MSI:H/MSA:N", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:L/VI:H/VA:H/SC:L/SI:L/SA:L/E:X/CR:M/IR:X/AR:X/MAV:A/MAC:H/MAT:N/MPR:X/MUI:X/MVC:X/MVI:N/MVA:N/MSC:H/MSI:X/MSA:X", // val
        212101, // exp mv
        Score(21), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:H/SA:H/E:X/CR:H/IR:M/AR:M/MAV:L/MAC:H/MAT:P/MPR:L/MUI:X/MVC:N/MVI:N/MVA:L/MSC:N/MSI:S/MSA:H", // val
        212001, // exp mv
        Score(46), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:L/VI:N/VA:H/SC:L/SI:N/SA:L/E:X/CR:H/IR:H/AR:M/MAV:X/MAC:L/MAT:P/MPR:N/MUI:X/MVC:H/MVI:H/MVA:L/MSC:N/MSI:N/MSA:X", // val
        110200, // exp mv
        Score(72), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:L/VI:N/VA:H/SC:N/SI:H/SA:H/E:P/CR:M/IR:L/AR:M/MAV:P/MAC:L/MAT:X/MPR:N/MUI:P/MVC:N/MVI:N/MVA:H/MSC:L/MSI:X/MSA:X", // val
        201111, // exp mv
        Score(37), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:L/VI:N/VA:H/SC:N/SI:H/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:P/MPR:X/MUI:N/MVC:N/MVI:X/MVA:X/MSC:X/MSI:X/MSA:N", // val
        111121, // exp mv
        Score(18), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:N/VI:N/VA:N/SC:L/SI:H/SA:H/E:X/CR:L/IR:X/AR:L/MAV:X/MAC:H/MAT:N/MPR:N/MUI:P/MVC:N/MVI:N/MVA:L/MSC:X/MSI:N/MSA:S", // val
        112001, // exp mv
        Score(67), // exp score
      ), (
        "test 9.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:L/VI:L/VA:H/SC:H/SI:L/SA:L/E:X/CR:L/IR:H/AR:H/MAV:A/MAC:L/MAT:X/MPR:L/MUI:X/MVC:X/MVI:L/MVA:X/MSC:X/MSI:S/MSA:L", // val
        101000, // exp mv
        Score(93), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:L/VI:L/VA:H/SC:L/SI:H/SA:L/E:X/CR:M/IR:X/AR:H/MAV:P/MAC:H/MAT:P/MPR:H/MUI:N/MVC:H/MVI:N/MVA:N/MSC:N/MSI:N/MSA:L", // val
        211201, // exp mv
        Score(17), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:H/E:A/CR:X/IR:X/AR:M/MAV:L/MAC:H/MAT:N/MPR:X/MUI:X/MVC:N/MVI:H/MVA:N/MSC:N/MSI:N/MSA:L", // val
        111200, // exp mv
        Score(57), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N/E:U/CR:H/IR:L/AR:M/MAV:X/MAC:L/MAT:X/MPR:N/MUI:P/MVC:N/MVI:X/MVA:L/MSC:X/MSI:N/MSA:H", // val
        102121, // exp mv
        Score(22), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:L/VI:N/VA:L/SC:L/SI:L/SA:N/E:X/CR:M/IR:L/AR:X/MAV:A/MAC:X/MAT:N/MPR:N/MUI:A/MVC:L/MVI:N/MVA:X/MSC:N/MSI:H/MSA:X", // val
        112101, // exp mv
        Score(43), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:L/SA:H/E:U/CR:H/IR:X/AR:H/MAV:X/MAC:L/MAT:X/MPR:L/MUI:A/MVC:L/MVI:N/MVA:H/MSC:X/MSI:L/MSA:S", // val
        201020, // exp mv
        Score(58), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:L/SI:H/SA:L/E:X/CR:M/IR:M/AR:X/MAV:L/MAC:X/MAT:X/MPR:H/MUI:N/MVC:H/MVI:L/MVA:X/MSC:X/MSI:S/MSA:L", // val
        111001, // exp mv
        Score(71), // exp score
      ), (
        "test 8.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:L/SI:H/SA:H/E:X/CR:X/IR:X/AR:X/MAV:L/MAC:L/MAT:X/MPR:L/MUI:A/MVC:X/MVI:X/MVA:H/MSC:L/MSI:S/MSA:L", // val
        201000, // exp mv
        Score(82), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/E:A/CR:X/IR:M/AR:X/MAV:X/MAC:X/MAT:P/MPR:H/MUI:N/MVC:H/MVI:X/MVA:H/MSC:H/MSI:X/MSA:H", // val
        111100, // exp mv
        Score(71), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:L/SA:L/E:P/CR:X/IR:M/AR:X/MAV:A/MAC:X/MAT:X/MPR:H/MUI:N/MVC:X/MVI:N/MVA:N/MSC:H/MSI:L/MSA:S", // val
        111010, // exp mv
        Score(71), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:H/VI:N/VA:H/SC:H/SI:L/SA:L/E:A/CR:M/IR:L/AR:M/MAV:A/MAC:X/MAT:N/MPR:X/MUI:X/MVC:N/MVI:N/MVA:N/MSC:H/MSI:L/MSA:X", // val
        212101, // exp mv
        Score(21), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:N/SA:N/E:U/CR:L/IR:X/AR:M/MAV:X/MAC:L/MAT:N/MPR:X/MUI:P/MVC:L/MVI:N/MVA:X/MSC:L/MSI:X/MSA:H", // val
        202121, // exp mv
        Score(9), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:N/SI:L/SA:N/E:A/CR:M/IR:H/AR:L/MAV:X/MAC:L/MAT:P/MPR:N/MUI:N/MVC:X/MVI:H/MVA:X/MSC:L/MSI:X/MSA:X", // val
        111200, // exp mv
        Score(59), // exp score
      ), (
        "test 2.5", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:H/SA:H/E:U/CR:X/IR:M/AR:X/MAV:N/MAC:X/MAT:P/MPR:L/MUI:N/MVC:N/MVI:N/MVA:X/MSC:L/MSI:S/MSA:N", // val
        112021, // exp mv
        Score(25), // exp score
      ), (
        "test 4.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:N/VI:H/VA:L/SC:L/SI:N/SA:H/E:A/CR:X/IR:M/AR:L/MAV:L/MAC:L/MAT:X/MPR:H/MUI:P/MVC:X/MVI:L/MVA:L/MSC:X/MSI:N/MSA:X", // val
        202101, // exp mv
        Score(42), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:L/E:X/CR:H/IR:M/AR:X/MAV:A/MAC:L/MAT:X/MPR:N/MUI:A/MVC:L/MVI:X/MVA:N/MSC:N/MSI:L/MSA:L", // val
        102201, // exp mv
        Score(48), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:N/VI:N/VA:L/SC:H/SI:L/SA:L/E:A/CR:X/IR:X/AR:H/MAV:A/MAC:L/MAT:X/MPR:L/MUI:N/MVC:L/MVI:X/MVA:L/MSC:L/MSI:X/MSA:L", // val
        102201, // exp mv
        Score(51), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:N/VI:N/VA:L/SC:L/SI:L/SA:H/E:A/CR:M/IR:L/AR:L/MAV:P/MAC:X/MAT:P/MPR:N/MUI:N/MVC:L/MVI:X/MVA:X/MSC:X/MSI:X/MSA:S", // val
        212001, // exp mv
        Score(46), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:X/IR:L/AR:M/MAV:X/MAC:H/MAT:P/MPR:N/MUI:N/MVC:H/MVI:L/MVA:X/MSC:X/MSI:L/MSA:N", // val
        111220, // exp mv
        Score(22), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:L/SC:L/SI:N/SA:N/E:P/CR:H/IR:M/AR:H/MAV:P/MAC:X/MAT:X/MPR:H/MUI:X/MVC:N/MVI:H/MVA:N/MSC:X/MSI:H/MSA:N", // val
        211111, // exp mv
        Score(15), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:L/VI:H/VA:N/SC:L/SI:H/SA:L/E:U/CR:L/IR:H/AR:H/MAV:N/MAC:H/MAT:P/MPR:H/MUI:P/MVC:N/MVI:X/MVA:X/MSC:X/MSI:H/MSA:S", // val
        111020, // exp mv
        Score(56), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:L/VI:N/VA:L/SC:H/SI:L/SA:H/E:U/CR:H/IR:L/AR:L/MAV:N/MAC:L/MAT:P/MPR:H/MUI:A/MVC:L/MVI:X/MVA:N/MSC:L/MSI:N/MSA:S", // val
        112021, // exp mv
        Score(19), // exp score
      ), (
        "test 4.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:N/VI:H/VA:L/SC:N/SI:H/SA:H/E:X/CR:M/IR:L/AR:X/MAV:X/MAC:X/MAT:N/MPR:N/MUI:N/MVC:L/MVI:N/MVA:N/MSC:N/MSI:X/MSA:N", // val
        112101, // exp mv
        Score(49), // exp score
      ), (
        "test 3.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:N/VI:L/VA:H/SC:L/SI:N/SA:N/E:U/CR:X/IR:X/AR:H/MAV:A/MAC:L/MAT:P/MPR:L/MUI:X/MVC:X/MVI:X/MVA:X/MSC:N/MSI:H/MSA:S", // val
        211020, // exp mv
        Score(33), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:N/VI:L/VA:L/SC:H/SI:N/SA:L/E:A/CR:X/IR:L/AR:X/MAV:X/MAC:X/MAT:P/MPR:L/MUI:X/MVC:N/MVI:L/MVA:H/MSC:H/MSI:L/MSA:L", // val
        211100, // exp mv
        Score(57), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:H/SC:N/SI:L/SA:N/E:P/CR:M/IR:X/AR:M/MAV:N/MAC:H/MAT:X/MPR:H/MUI:N/MVC:N/MVI:H/MVA:H/MSC:X/MSI:S/MSA:N", // val
        111010, // exp mv
        Score(70), // exp score
      ), (
        "test 0.5", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:U/CR:H/IR:M/AR:H/MAV:N/MAC:X/MAT:N/MPR:N/MUI:X/MVC:L/MVI:N/MVA:L/MSC:X/MSI:L/MSA:N", // val
        112221, // exp mv
        Score(5), // exp score
      ), (
        "test 9.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:N/E:X/CR:H/IR:X/AR:X/MAV:A/MAC:L/MAT:N/MPR:L/MUI:X/MVC:L/MVI:H/MVA:X/MSC:L/MSI:S/MSA:H", // val
        101000, // exp mv
        Score(93), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:L/SA:L/E:A/CR:M/IR:H/AR:X/MAV:A/MAC:X/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:H/MSC:L/MSI:H/MSA:N", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 0.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:L/SC:N/SI:L/SA:N/E:P/CR:M/IR:X/AR:X/MAV:P/MAC:L/MAT:P/MPR:H/MUI:X/MVC:H/MVI:X/MVA:L/MSC:L/MSI:N/MSA:N", // val
        211211, // exp mv
        Score(7), // exp score
      ), (
        "test 5.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:L/VI:H/VA:L/SC:L/SI:L/SA:H/E:P/CR:X/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:H/MUI:X/MVC:H/MVI:L/MVA:H/MSC:X/MSI:L/MSA:L", // val
        101210, // exp mv
        Score(52), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:N/SA:L/E:A/CR:L/IR:H/AR:X/MAV:L/MAC:L/MAT:P/MPR:H/MUI:X/MVC:X/MVI:H/MVA:L/MSC:H/MSI:L/MSA:S", // val
        111000, // exp mv
        Score(84), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:L/SI:H/SA:N/E:P/CR:X/IR:X/AR:L/MAV:A/MAC:X/MAT:N/MPR:X/MUI:X/MVC:X/MVI:X/MVA:N/MSC:L/MSI:L/MSA:L", // val
        111210, // exp mv
        Score(51), // exp score
      ), (
        "test 9.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:L/E:A/CR:H/IR:H/AR:X/MAV:A/MAC:L/MAT:X/MPR:X/MUI:N/MVC:H/MVI:X/MVA:L/MSC:L/MSI:S/MSA:S", // val
        101000, // exp mv
        Score(94), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:L/SA:L/E:U/CR:H/IR:X/AR:L/MAV:P/MAC:X/MAT:N/MPR:N/MUI:N/MVC:X/MVI:X/MVA:N/MSC:X/MSI:L/MSA:H", // val
        211120, // exp mv
        Score(16), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:H/SC:L/SI:H/SA:L/E:A/CR:X/IR:M/AR:M/MAV:L/MAC:L/MAT:P/MPR:H/MUI:P/MVC:N/MVI:H/MVA:L/MSC:H/MSI:N/MSA:S", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:H/SC:L/SI:H/SA:N/E:X/CR:X/IR:L/AR:L/MAV:L/MAC:H/MAT:N/MPR:X/MUI:P/MVC:X/MVI:H/MVA:N/MSC:X/MSI:H/MSA:X", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:H/SC:L/SI:L/SA:H/E:U/CR:H/IR:H/AR:M/MAV:A/MAC:L/MAT:N/MPR:H/MUI:X/MVC:X/MVI:X/MVA:L/MSC:N/MSI:N/MSA:S", // val
        202021, // exp mv
        Score(16), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:L/SA:H/E:A/CR:M/IR:M/AR:M/MAV:A/MAC:H/MAT:P/MPR:H/MUI:N/MVC:X/MVI:L/MVA:L/MSC:L/MSI:L/MSA:N", // val
        112201, // exp mv
        Score(20), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:H/SI:N/SA:L/E:A/CR:L/IR:L/AR:M/MAV:L/MAC:H/MAT:P/MPR:X/MUI:P/MVC:L/MVI:L/MVA:H/MSC:H/MSI:L/MSA:S", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N/E:A/CR:L/IR:M/AR:M/MAV:L/MAC:X/MAT:N/MPR:N/MUI:N/MVC:L/MVI:L/MVA:X/MSC:L/MSI:X/MSA:X", // val
        112101, // exp mv
        Score(48), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:H/SC:L/SI:H/SA:L/E:U/CR:M/IR:L/AR:H/MAV:L/MAC:X/MAT:X/MPR:X/MUI:P/MVC:H/MVI:N/MVA:N/MSC:N/MSI:X/MSA:L", // val
        211121, // exp mv
        Score(6), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:H/SC:N/SI:N/SA:L/E:A/CR:H/IR:L/AR:H/MAV:P/MAC:H/MAT:X/MPR:X/MUI:P/MVC:X/MVI:N/MVA:H/MSC:H/MSI:X/MSA:H", // val
        211100, // exp mv
        Score(57), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:H/SC:N/SI:N/SA:L/E:A/CR:L/IR:M/AR:H/MAV:X/MAC:H/MAT:X/MPR:X/MUI:N/MVC:L/MVI:L/MVA:N/MSC:X/MSI:L/MSA:N", // val
        112201, // exp mv
        Score(20), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:N/VI:H/VA:L/SC:H/SI:L/SA:H/E:U/CR:L/IR:H/AR:X/MAV:P/MAC:X/MAT:N/MPR:L/MUI:A/MVC:L/MVI:H/MVA:X/MSC:N/MSI:X/MSA:N", // val
        211220, // exp mv
        Score(6), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:N/VI:L/VA:H/SC:H/SI:H/SA:L/E:U/CR:M/IR:H/AR:M/MAV:A/MAC:L/MAT:X/MPR:N/MUI:A/MVC:H/MVI:L/MVA:X/MSC:H/MSI:X/MSA:N", // val
        111121, // exp mv
        Score(20), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:N/VI:L/VA:N/SC:H/SI:H/SA:L/E:P/CR:X/IR:L/AR:H/MAV:P/MAC:X/MAT:X/MPR:L/MUI:A/MVC:N/MVI:N/MVA:N/MSC:X/MSI:N/MSA:H", // val
        212111, // exp mv
        Score(10), // exp score
      ), (
        "test 1.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:H/SA:L/E:U/CR:X/IR:X/AR:L/MAV:N/MAC:X/MAT:X/MPR:L/MUI:N/MVC:N/MVI:X/MVA:N/MSC:H/MSI:L/MSA:H", // val
        112121, // exp mv
        Score(14), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:L/E:P/CR:H/IR:L/AR:M/MAV:N/MAC:H/MAT:P/MPR:X/MUI:P/MVC:L/MVI:N/MVA:H/MSC:L/MSI:L/MSA:H", // val
        111111, // exp mv
        Score(46), // exp score
      ), (
        "test 1.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:L/VI:H/VA:H/SC:H/SI:N/SA:H/E:P/CR:X/IR:X/AR:X/MAV:A/MAC:X/MAT:P/MPR:N/MUI:X/MVC:L/MVI:L/MVA:L/MSC:N/MSI:X/MSA:L", // val
        112211, // exp mv
        Score(13), // exp score
      ), (
        "test 3.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:L/VI:H/VA:L/SC:N/SI:L/SA:N/E:P/CR:M/IR:L/AR:X/MAV:P/MAC:L/MAT:N/MPR:H/MUI:X/MVC:N/MVI:X/MVA:L/MSC:H/MSI:X/MSA:N", // val
        201111, // exp mv
        Score(36), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:H/SC:N/SI:H/SA:L/E:P/CR:L/IR:X/AR:X/MAV:N/MAC:H/MAT:N/MPR:H/MUI:X/MVC:L/MVI:N/MVA:X/MSC:X/MSI:S/MSA:X", // val
        111010, // exp mv
        Score(71), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:H/SC:N/SI:L/SA:N/E:U/CR:X/IR:M/AR:L/MAV:X/MAC:H/MAT:P/MPR:L/MUI:X/MVC:N/MVI:H/MVA:N/MSC:L/MSI:L/MSA:S", // val
        111021, // exp mv
        Score(44), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:H/SA:N/E:P/CR:H/IR:X/AR:M/MAV:P/MAC:L/MAT:X/MPR:H/MUI:N/MVC:L/MVI:X/MVA:H/MSC:L/MSI:H/MSA:L", // val
        211111, // exp mv
        Score(17), // exp score
      ), (
        "test 0.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:H/SC:H/SI:N/SA:N/E:U/CR:L/IR:H/AR:X/MAV:P/MAC:H/MAT:P/MPR:N/MUI:X/MVC:H/MVI:L/MVA:L/MSC:L/MSI:L/MSA:H", // val
        211121, // exp mv
        Score(7), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:L/SC:N/SI:H/SA:L/E:X/CR:X/IR:X/AR:M/MAV:L/MAC:X/MAT:N/MPR:N/MUI:P/MVC:X/MVI:H/MVA:H/MSC:X/MSI:H/MSA:N", // val
        111100, // exp mv
        Score(69), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:N/SC:L/SI:N/SA:N/E:X/CR:X/IR:X/AR:M/MAV:L/MAC:H/MAT:P/MPR:N/MUI:N/MVC:N/MVI:H/MVA:X/MSC:L/MSI:L/MSA:S", // val
        111000, // exp mv
        Score(85), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:N/VI:L/VA:H/SC:N/SI:H/SA:N/E:P/CR:H/IR:X/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:X/MVC:L/MVI:H/MVA:L/MSC:L/MSI:N/MSA:H", // val
        111110, // exp mv
        Score(57), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:H/VI:H/VA:L/SC:L/SI:L/SA:H/E:P/CR:H/IR:M/AR:L/MAV:A/MAC:X/MAT:P/MPR:L/MUI:X/MVC:L/MVI:L/MVA:H/MSC:L/MSI:H/MSA:X", // val
        211111, // exp mv
        Score(17), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N/E:P/CR:X/IR:L/AR:X/MAV:P/MAC:X/MAT:N/MPR:X/MUI:N/MVC:X/MVI:N/MVA:H/MSC:L/MSI:L/MSA:N", // val
        211210, // exp mv
        Score(15), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:H/VI:H/VA:N/SC:L/SI:N/SA:L/E:U/CR:H/IR:H/AR:H/MAV:X/MAC:X/MAT:X/MPR:H/MUI:N/MVC:N/MVI:N/MVA:N/MSC:L/MSI:H/MSA:S", // val
        112021, // exp mv
        Score(24), // exp score
      ), (
        "test 8.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:L/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:H/MAV:A/MAC:H/MAT:X/MPR:N/MUI:N/MVC:X/MVI:L/MVA:X/MSC:H/MSI:H/MSA:S", // val
        111000, // exp mv
        Score(87), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:N/E:U/CR:M/IR:M/AR:L/MAV:X/MAC:X/MAT:P/MPR:L/MUI:N/MVC:L/MVI:H/MVA:L/MSC:H/MSI:H/MSA:L", // val
        111121, // exp mv
        Score(20), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:L/VI:N/VA:N/SC:N/SI:H/SA:H/E:X/CR:M/IR:H/AR:L/MAV:N/MAC:X/MAT:X/MPR:N/MUI:A/MVC:X/MVI:X/MVA:N/MSC:N/MSI:S/MSA:L", // val
        112001, // exp mv
        Score(67), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:L/E:A/CR:L/IR:H/AR:H/MAV:X/MAC:X/MAT:P/MPR:X/MUI:N/MVC:H/MVI:N/MVA:L/MSC:N/MSI:N/MSA:L", // val
        111201, // exp mv
        Score(44), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:L/SC:N/SI:L/SA:L/E:P/CR:H/IR:M/AR:H/MAV:L/MAC:X/MAT:P/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:X/MSI:H/MSA:N", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:H/E:A/CR:X/IR:X/AR:H/MAV:X/MAC:L/MAT:P/MPR:H/MUI:X/MVC:H/MVI:L/MVA:X/MSC:N/MSI:L/MSA:S", // val
        211000, // exp mv
        Score(70), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/VC:N/VI:L/VA:L/SC:H/SI:L/SA:H/E:A/CR:M/IR:H/AR:X/MAV:L/MAC:H/MAT:N/MPR:H/MUI:X/MVC:H/MVI:H/MVA:L/MSC:L/MSI:N/MSA:N", // val
        210200, // exp mv
        Score(53), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:L/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:H/MAV:P/MAC:X/MAT:P/MPR:H/MUI:X/MVC:L/MVI:N/MVA:L/MSC:X/MSI:L/MSA:X", // val
        212201, // exp mv
        Score(10), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:L/SC:H/SI:L/SA:N/E:U/CR:H/IR:M/AR:X/MAV:P/MAC:H/MAT:N/MPR:H/MUI:A/MVC:H/MVI:X/MVA:N/MSC:L/MSI:H/MSA:H", // val
        211120, // exp mv
        Score(16), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L/E:U/CR:M/IR:L/AR:H/MAV:L/MAC:X/MAT:N/MPR:X/MUI:X/MVC:H/MVI:X/MVA:H/MSC:H/MSI:H/MSA:X", // val
        110120, // exp mv
        Score(56), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:N/VI:H/VA:L/SC:L/SI:N/SA:L/E:X/CR:M/IR:H/AR:L/MAV:L/MAC:L/MAT:N/MPR:X/MUI:A/MVC:H/MVI:X/MVA:X/MSC:X/MSI:X/MSA:L", // val
        200200, // exp mv
        Score(67), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:H/SI:L/SA:N/E:X/CR:L/IR:H/AR:X/MAV:X/MAC:X/MAT:N/MPR:H/MUI:A/MVC:N/MVI:H/MVA:X/MSC:L/MSI:S/MSA:N", // val
        211000, // exp mv
        Score(69), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:L/E:A/CR:X/IR:H/AR:M/MAV:A/MAC:X/MAT:N/MPR:L/MUI:X/MVC:H/MVI:N/MVA:L/MSC:X/MSI:S/MSA:S", // val
        211000, // exp mv
        Score(73), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N/E:X/CR:H/IR:L/AR:M/MAV:L/MAC:X/MAT:X/MPR:L/MUI:X/MVC:H/MVI:L/MVA:L/MSC:N/MSI:L/MSA:N", // val
        211200, // exp mv
        Score(39), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:L/VA:N/SC:N/SI:L/SA:L/E:X/CR:L/IR:H/AR:X/MAV:P/MAC:X/MAT:N/MPR:X/MUI:N/MVC:X/MVI:N/MVA:X/MSC:L/MSI:N/MSA:H", // val
        211101, // exp mv
        Score(41), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:N/VA:N/SC:H/SI:L/SA:H/E:P/CR:M/IR:M/AR:L/MAV:A/MAC:H/MAT:N/MPR:H/MUI:P/MVC:N/MVI:X/MVA:L/MSC:L/MSI:S/MSA:H", // val
        212011, // exp mv
        Score(22), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:H/SC:L/SI:L/SA:H/E:A/CR:X/IR:X/AR:L/MAV:P/MAC:X/MAT:N/MPR:N/MUI:N/MVC:H/MVI:N/MVA:X/MSC:X/MSI:S/MSA:X", // val
        211000, // exp mv
        Score(71), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:L/IR:H/AR:H/MAV:L/MAC:L/MAT:N/MPR:L/MUI:N/MVC:L/MVI:N/MVA:H/MSC:X/MSI:L/MSA:L", // val
        101200, // exp mv
        Score(68), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N/E:U/CR:X/IR:H/AR:M/MAV:L/MAC:L/MAT:P/MPR:N/MUI:A/MVC:N/MVI:H/MVA:H/MSC:N/MSI:H/MSA:S", // val
        111020, // exp mv
        Score(54), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:L/E:P/CR:X/IR:L/AR:H/MAV:A/MAC:L/MAT:P/MPR:L/MUI:P/MVC:X/MVI:X/MVA:L/MSC:N/MSI:N/MSA:X", // val
        211211, // exp mv
        Score(6), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:N/VI:L/VA:H/SC:N/SI:H/SA:N/E:U/CR:H/IR:L/AR:H/MAV:P/MAC:L/MAT:N/MPR:H/MUI:X/MVC:H/MVI:L/MVA:X/MSC:N/MSI:H/MSA:S", // val
        201020, // exp mv
        Score(58), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:N/VI:N/VA:L/SC:L/SI:L/SA:N/E:P/CR:X/IR:M/AR:M/MAV:L/MAC:L/MAT:N/MPR:X/MUI:N/MVC:L/MVI:X/MVA:L/MSC:X/MSI:S/MSA:H", // val
        102011, // exp mv
        Score(67), // exp score
      ), (
        "test 4.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:A/VC:H/VI:L/VA:L/SC:H/SI:L/SA:H/E:P/CR:H/IR:H/AR:X/MAV:A/MAC:L/MAT:P/MPR:L/MUI:P/MVC:H/MVI:N/MVA:N/MSC:X/MSI:L/MSA:X", // val
        211110, // exp mv
        Score(42), // exp score
      ), (
        "test 9.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:A/VC:H/VI:L/VA:L/SC:H/SI:L/SA:N/E:A/CR:M/IR:M/AR:M/MAV:N/MAC:L/MAT:P/MPR:N/MUI:N/MVC:H/MVI:X/MVA:N/MSC:X/MSI:S/MSA:L", // val
        011001, // exp mv
        Score(91), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:A/VC:L/VI:H/VA:L/SC:L/SI:N/SA:N/E:A/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:X/MPR:L/MUI:X/MVC:L/MVI:X/MVA:H/MSC:H/MSI:L/MSA:L", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 3.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:H/SC:H/SI:L/SA:L/E:U/CR:H/IR:X/AR:M/MAV:L/MAC:H/MAT:P/MPR:H/MUI:P/MVC:H/MVI:X/MVA:X/MSC:L/MSI:N/MSA:S", // val
        211020, // exp mv
        Score(32), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:H/SI:H/SA:L/E:U/CR:L/IR:H/AR:X/MAV:X/MAC:X/MAT:P/MPR:N/MUI:P/MVC:X/MVI:N/MVA:N/MSC:H/MSI:N/MSA:L", // val
        112121, // exp mv
        Score(11), // exp score
      ), (
        "test 3.5", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:L/E:U/CR:M/IR:X/AR:X/MAV:L/MAC:X/MAT:N/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:X/MSI:H/MSA:X", // val
        210120, // exp mv
        Score(35), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N/E:U/CR:X/IR:X/AR:L/MAV:L/MAC:X/MAT:X/MPR:L/MUI:P/MVC:L/MVI:X/MVA:H/MSC:H/MSI:L/MSA:S", // val
        211021, // exp mv
        Score(19), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:H/SC:L/SI:H/SA:N/E:X/CR:M/IR:M/AR:H/MAV:X/MAC:X/MAT:X/MPR:N/MUI:P/MVC:N/MVI:X/MVA:H/MSC:N/MSI:H/MSA:S", // val
        111000, // exp mv
        Score(85), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:H/SA:L/E:A/CR:L/IR:M/AR:H/MAV:L/MAC:X/MAT:P/MPR:H/MUI:X/MVC:X/MVI:L/MVA:N/MSC:H/MSI:X/MSA:H", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:L/SC:H/SI:N/SA:N/E:X/CR:H/IR:L/AR:X/MAV:N/MAC:X/MAT:X/MPR:N/MUI:N/MVC:N/MVI:N/MVA:L/MSC:X/MSI:H/MSA:X", // val
        012101, // exp mv
        Score(70), // exp score
      ), (
        "test 7.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:L/E:A/CR:M/IR:L/AR:M/MAV:N/MAC:H/MAT:P/MPR:H/MUI:X/MVC:X/MVI:H/MVA:H/MSC:L/MSI:L/MSA:H", // val
        110101, // exp mv
        Score(74), // exp score
      ), (
        "test 4.2", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:H/SA:L/E:X/CR:L/IR:M/AR:L/MAV:P/MAC:X/MAT:P/MPR:X/MUI:X/MVC:N/MVI:X/MVA:H/MSC:H/MSI:L/MSA:X", // val
        211101, // exp mv
        Score(42), // exp score
      ), (
        "test 2.5", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:H/SC:L/SI:H/SA:H/E:P/CR:M/IR:L/AR:H/MAV:N/MAC:X/MAT:P/MPR:X/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:N/MSA:N", // val
        111211, // exp mv
        Score(25), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:L/SA:N/E:X/CR:L/IR:M/AR:L/MAV:L/MAC:H/MAT:X/MPR:N/MUI:P/MVC:H/MVI:N/MVA:N/MSC:H/MSI:L/MSA:H", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:H/E:X/CR:M/IR:X/AR:H/MAV:P/MAC:X/MAT:X/MPR:H/MUI:A/MVC:L/MVI:N/MVA:H/MSC:X/MSI:X/MSA:N", // val
        211200, // exp mv
        Score(41), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:L/E:X/CR:L/IR:X/AR:H/MAV:L/MAC:X/MAT:N/MPR:N/MUI:X/MVC:L/MVI:H/MVA:X/MSC:H/MSI:X/MSA:H", // val
        111100, // exp mv
        Score(71), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:H/SC:H/SI:N/SA:H/E:A/CR:L/IR:M/AR:L/MAV:N/MAC:H/MAT:P/MPR:X/MUI:P/MVC:X/MVI:X/MVA:N/MSC:N/MSI:L/MSA:X", // val
        112101, // exp mv
        Score(51), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:L/SA:N/E:P/CR:M/IR:H/AR:M/MAV:X/MAC:L/MAT:X/MPR:L/MUI:P/MVC:N/MVI:N/MVA:L/MSC:X/MSI:N/MSA:S", // val
        212011, // exp mv
        Score(19), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:H/SC:N/SI:L/SA:H/E:U/CR:H/IR:X/AR:H/MAV:X/MAC:X/MAT:P/MPR:H/MUI:N/MVC:H/MVI:L/MVA:H/MSC:L/MSI:X/MSA:H", // val
        111120, // exp mv
        Score(39), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:L/SC:L/SI:L/SA:H/E:P/CR:X/IR:M/AR:M/MAV:P/MAC:L/MAT:P/MPR:L/MUI:N/MVC:H/MVI:H/MVA:N/MSC:N/MSI:S/MSA:H", // val
        210010, // exp mv
        Score(68), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:L/SI:H/SA:N/E:P/CR:X/IR:H/AR:M/MAV:N/MAC:H/MAT:P/MPR:N/MUI:X/MVC:X/MVI:N/MVA:X/MSC:H/MSI:H/MSA:N", // val
        112111, // exp mv
        Score(24), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:L/IR:M/AR:M/MAV:X/MAC:L/MAT:N/MPR:X/MUI:N/MVC:X/MVI:X/MVA:H/MSC:X/MSI:L/MSA:S", // val
        100011, // exp mv
        Score(83), // exp score
      ), (
        "test 3.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:H/VI:H/VA:L/SC:N/SI:H/SA:H/E:P/CR:X/IR:H/AR:M/MAV:P/MAC:X/MAT:X/MPR:L/MUI:X/MVC:L/MVI:L/MVA:H/MSC:X/MSI:L/MSA:X", // val
        201111, // exp mv
        Score(38), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:H/VI:L/VA:H/SC:N/SI:L/SA:H/E:U/CR:M/IR:M/AR:H/MAV:L/MAC:H/MAT:X/MPR:H/MUI:P/MVC:X/MVI:H/MVA:N/MSC:X/MSI:L/MSA:L", // val
        210221, // exp mv
        Score(10), // exp score
      ), (
        "test 0.4", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:H/VI:N/VA:H/SC:N/SI:L/SA:H/E:U/CR:X/IR:M/AR:M/MAV:L/MAC:L/MAT:X/MPR:L/MUI:P/MVC:L/MVI:N/MVA:L/MSC:X/MSI:L/MSA:N", // val
        202221, // exp mv
        Score(4), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:H/VI:N/VA:L/SC:N/SI:H/SA:H/E:A/CR:X/IR:L/AR:X/MAV:P/MAC:H/MAT:N/MPR:H/MUI:A/MVC:N/MVI:X/MVA:N/MSC:X/MSI:S/MSA:S", // val
        212001, // exp mv
        Score(48), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:L/VI:L/VA:H/SC:L/SI:L/SA:N/E:X/CR:H/IR:H/AR:L/MAV:L/MAC:X/MAT:P/MPR:X/MUI:X/MVC:H/MVI:N/MVA:N/MSC:L/MSI:L/MSA:X", // val
        211200, // exp mv
        Score(37), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:H/E:A/CR:H/IR:H/AR:M/MAV:P/MAC:L/MAT:X/MPR:N/MUI:P/MVC:N/MVI:X/MVA:N/MSC:L/MSI:X/MSA:N", // val
        202201, // exp mv
        Score(24), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:N/VI:L/VA:H/SC:N/SI:N/SA:L/E:U/CR:X/IR:H/AR:M/MAV:X/MAC:X/MAT:P/MPR:N/MUI:P/MVC:L/MVI:H/MVA:H/MSC:L/MSI:H/MSA:X", // val
        111120, // exp mv
        Score(41), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:H/SC:H/SI:H/SA:N/E:A/CR:H/IR:H/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVC:X/MVI:L/MVA:L/MSC:N/MSI:N/MSA:L", // val
        102201, // exp mv
        Score(51), // exp score
      ), (
        "test 3.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:L/VI:N/VA:N/SC:L/SI:L/SA:H/E:U/CR:L/IR:L/AR:L/MAV:L/MAC:H/MAT:N/MPR:N/MUI:P/MVC:H/MVI:N/MVA:N/MSC:X/MSI:L/MSA:S", // val
        111021, // exp mv
        Score(38), // exp score
      ), (
        "test 3", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:N/VI:L/VA:L/SC:H/SI:H/SA:L/E:U/CR:M/IR:H/AR:H/MAV:P/MAC:H/MAT:N/MPR:H/MUI:X/MVC:H/MVI:H/MVA:N/MSC:L/MSI:N/MSA:H", // val
        210120, // exp mv
        Score(30), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:N/VI:L/VA:N/SC:L/SI:N/SA:L/E:A/CR:H/IR:L/AR:L/MAV:P/MAC:H/MAT:N/MPR:H/MUI:P/MVC:X/MVI:L/MVA:H/MSC:L/MSI:N/MSA:H", // val
        211101, // exp mv
        Score(40), // exp score
      ), (
        "test 0.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:L/SC:L/SI:L/SA:N/E:U/CR:H/IR:M/AR:L/MAV:P/MAC:H/MAT:P/MPR:X/MUI:A/MVC:N/MVI:N/MVA:L/MSC:N/MSI:H/MSA:H", // val
        212121, // exp mv
        Score(3), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:H/VI:N/VA:N/SC:L/SI:H/SA:N/E:U/CR:M/IR:M/AR:M/MAV:N/MAC:X/MAT:P/MPR:N/MUI:X/MVC:H/MVI:N/MVA:N/MSC:H/MSI:L/MSA:L", // val
        111121, // exp mv
        Score(21), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:L/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:H/AR:H/MAV:N/MAC:H/MAT:X/MPR:X/MUI:P/MVC:N/MVI:X/MVA:L/MSC:H/MSI:L/MSA:H", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 1.4", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:H/SC:L/SI:N/SA:N/E:U/CR:H/IR:X/AR:L/MAV:L/MAC:H/MAT:P/MPR:X/MUI:P/MVC:N/MVI:H/MVA:N/MSC:H/MSI:N/MSA:H", // val
        211120, // exp mv
        Score(14), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:N/E:A/CR:X/IR:M/AR:X/MAV:N/MAC:X/MAT:P/MPR:H/MUI:P/MVC:H/MVI:X/MVA:L/MSC:L/MSI:L/MSA:L", // val
        111200, // exp mv
        Score(58), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:N/SC:N/SI:L/SA:N/E:X/CR:H/IR:X/AR:H/MAV:P/MAC:L/MAT:P/MPR:N/MUI:N/MVC:X/MVI:L/MVA:N/MSC:H/MSI:L/MSA:X", // val
        212101, // exp mv
        Score(20), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:L/VI:N/VA:H/SC:L/SI:L/SA:N/E:P/CR:L/IR:M/AR:X/MAV:L/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:H/MSC:X/MSI:S/MSA:S", // val
        211010, // exp mv
        Score(54), // exp score
      ), (
        "test 8.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:N/VI:L/VA:H/SC:H/SI:N/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:P/MPR:N/MUI:N/MVC:X/MVI:N/MVA:X/MSC:N/MSI:N/MSA:L", // val
        011200, // exp mv
        Score(82), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:A/VC:H/VI:L/VA:L/SC:L/SI:H/SA:L/E:U/CR:L/IR:L/AR:H/MAV:X/MAC:H/MAT:N/MPR:L/MUI:X/MVC:X/MVI:X/MVA:L/MSC:L/MSI:L/MSA:S", // val
        211021, // exp mv
        Score(17), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:H/E:X/CR:H/IR:L/AR:L/MAV:A/MAC:H/MAT:X/MPR:H/MUI:X/MVC:N/MVI:L/MVA:L/MSC:N/MSI:S/MSA:X", // val
        212001, // exp mv
        Score(46), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:A/VC:L/VI:N/VA:N/SC:L/SI:L/SA:L/E:U/CR:M/IR:H/AR:L/MAV:N/MAC:L/MAT:X/MPR:L/MUI:P/MVC:X/MVI:X/MVA:H/MSC:L/MSI:L/MSA:N", // val
        101221, // exp mv
        Score(22), // exp score
      ), (
        "test 9.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:A/VC:N/VI:L/VA:L/SC:N/SI:H/SA:N/E:A/CR:H/IR:X/AR:X/MAV:L/MAC:L/MAT:N/MPR:L/MUI:N/MVC:H/MVI:N/MVA:L/MSC:H/MSI:H/MSA:S", // val
        101000, // exp mv
        Score(93), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:L/E:U/CR:H/IR:M/AR:H/MAV:A/MAC:L/MAT:X/MPR:N/MUI:A/MVC:L/MVI:L/MVA:L/MSC:X/MSI:L/MSA:X", // val
        102221, // exp mv
        Score(11), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:H/SC:H/SI:L/SA:H/E:X/CR:H/IR:X/AR:X/MAV:L/MAC:H/MAT:X/MPR:L/MUI:N/MVC:N/MVI:L/MVA:H/MSC:N/MSI:H/MSA:X", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 9.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:H/SI:N/SA:H/E:X/CR:M/IR:H/AR:X/MAV:N/MAC:L/MAT:N/MPR:H/MUI:N/MVC:H/MVI:H/MVA:N/MSC:L/MSI:L/MSA:S", // val
        100000, // exp mv
        Score(97), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:P/CR:X/IR:X/AR:M/MAV:P/MAC:L/MAT:X/MPR:H/MUI:P/MVC:N/MVI:N/MVA:X/MSC:X/MSI:X/MSA:H", // val
        202111, // exp mv
        Score(18), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/E:A/CR:X/IR:X/AR:H/MAV:L/MAC:X/MAT:P/MPR:N/MUI:X/MVC:N/MVI:N/MVA:X/MSC:H/MSI:X/MSA:X", // val
        112101, // exp mv
        Score(51), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:H/SA:N/E:A/CR:H/IR:H/AR:H/MAV:X/MAC:L/MAT:N/MPR:X/MUI:A/MVC:X/MVI:L/MVA:X/MSC:N/MSI:H/MSA:S", // val
        201000, // exp mv
        Score(83), // exp score
      ), (
        "test 6", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:L/SA:L/E:X/CR:L/IR:M/AR:X/MAV:A/MAC:L/MAT:X/MPR:L/MUI:A/MVC:L/MVI:L/MVA:X/MSC:L/MSI:S/MSA:N", // val
        202001, // exp mv
        Score(60), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:H/VA:H/SC:N/SI:H/SA:H/E:A/CR:M/IR:M/AR:L/MAV:A/MAC:X/MAT:N/MPR:X/MUI:A/MVC:L/MVI:X/MVA:L/MSC:X/MSI:X/MSA:X", // val
        201101, // exp mv
        Score(54), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:H/SA:L/E:U/CR:M/IR:M/AR:L/MAV:P/MAC:L/MAT:N/MPR:L/MUI:P/MVC:N/MVI:N/MVA:L/MSC:L/MSI:X/MSA:H", // val
        202121, // exp mv
        Score(10), // exp score
      ), (
        "test 3.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:H/SA:L/E:P/CR:X/IR:L/AR:H/MAV:A/MAC:L/MAT:X/MPR:H/MUI:P/MVC:L/MVI:N/MVA:H/MSC:N/MSI:L/MSA:X", // val
        201210, // exp mv
        Score(32), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:H/SI:L/SA:H/E:P/CR:X/IR:M/AR:X/MAV:L/MAC:L/MAT:X/MPR:X/MUI:X/MVC:N/MVI:L/MVA:X/MSC:H/MSI:X/MSA:N", // val
        201110, // exp mv
        Score(51), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:H/SI:N/SA:H/E:U/CR:X/IR:H/AR:L/MAV:N/MAC:L/MAT:N/MPR:X/MUI:X/MVC:X/MVI:N/MVA:L/MSC:L/MSI:N/MSA:H", // val
        102121, // exp mv
        Score(22), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:N/VI:L/VA:H/SC:N/SI:N/SA:H/E:U/CR:M/IR:X/AR:L/MAV:A/MAC:H/MAT:P/MPR:N/MUI:A/MVC:N/MVI:X/MVA:X/MSC:H/MSI:N/MSA:X", // val
        111121, // exp mv
        Score(19), // exp score
      ), (
        "test 6", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:L/E:A/CR:M/IR:L/AR:M/MAV:P/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:L/MVA:X/MSC:L/MSI:N/MSA:S", // val
        202001, // exp mv
        Score(60), // exp score
      ), (
        "test 6.6", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:X/CR:H/IR:M/AR:L/MAV:L/MAC:H/MAT:X/MPR:X/MUI:X/MVC:H/MVI:N/MVA:N/MSC:X/MSI:S/MSA:N", // val
        211000, // exp mv
        Score(66), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:L/SC:N/SI:H/SA:H/E:X/CR:M/IR:H/AR:X/MAV:L/MAC:L/MAT:X/MPR:L/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:H/MSA:S", // val
        201001, // exp mv
        Score(72), // exp score
      ), (
        "test 9.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:L/SC:H/SI:L/SA:N/E:P/CR:X/IR:X/AR:H/MAV:N/MAC:H/MAT:N/MPR:X/MUI:N/MVC:N/MVI:H/MVA:L/MSC:H/MSI:X/MSA:S", // val
        011010, // exp mv
        Score(91), // exp score
      ), (
        "test 0.5", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:H/SC:L/SI:N/SA:H/E:U/CR:M/IR:M/AR:M/MAV:N/MAC:H/MAT:X/MPR:H/MUI:N/MVC:N/MVI:X/MVA:N/MSC:X/MSI:N/MSA:L", // val
        112221, // exp mv
        Score(5), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:H/SC:H/SI:H/SA:N/E:P/CR:L/IR:M/AR:X/MAV:P/MAC:H/MAT:X/MPR:N/MUI:N/MVC:H/MVI:L/MVA:X/MSC:L/MSI:L/MSA:H", // val
        211110, // exp mv
        Score(40), // exp score
      ), (
        "test 1.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:H/SC:N/SI:H/SA:N/E:U/CR:H/IR:M/AR:L/MAV:X/MAC:X/MAT:X/MPR:X/MUI:N/MVC:X/MVI:L/MVA:N/MSC:L/MSI:L/MSA:X", // val
        102221, // exp mv
        Score(13), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L/E:X/CR:X/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:H/MUI:X/MVC:N/MVI:X/MVA:X/MSC:H/MSI:H/MSA:L", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:H/SC:N/SI:H/SA:L/E:U/CR:H/IR:H/AR:M/MAV:N/MAC:X/MAT:P/MPR:N/MUI:P/MVC:N/MVI:X/MVA:H/MSC:N/MSI:N/MSA:H", // val
        111121, // exp mv
        Score(21), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:L/SI:H/SA:N/E:A/CR:X/IR:M/AR:L/MAV:P/MAC:L/MAT:N/MPR:N/MUI:P/MVC:N/MVI:H/MVA:X/MSC:L/MSI:H/MSA:N", // val
        201101, // exp mv
        Score(53), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H/E:A/CR:X/IR:X/AR:H/MAV:P/MAC:H/MAT:N/MPR:N/MUI:N/MVC:H/MVI:N/MVA:N/MSC:L/MSI:S/MSA:H", // val
        211000, // exp mv
        Score(71), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:H/E:P/CR:L/IR:X/AR:H/MAV:P/MAC:L/MAT:N/MPR:X/MUI:P/MVC:N/MVI:L/MVA:L/MSC:H/MSI:H/MSA:X", // val
        202111, // exp mv
        Score(21), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:N/SI:L/SA:H/E:U/CR:X/IR:L/AR:M/MAV:N/MAC:X/MAT:X/MPR:H/MUI:A/MVC:X/MVI:H/MVA:N/MSC:L/MSI:X/MSA:X", // val
        100120, // exp mv
        Score(69), // exp score
      ), (
        "test 6.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:L/SA:L/E:P/CR:H/IR:M/AR:H/MAV:L/MAC:H/MAT:X/MPR:L/MUI:X/MVC:L/MVI:H/MVA:X/MSC:H/MSI:S/MSA:L", // val
        111011, // exp mv
        Score(63), // exp score
      ), (
        "test 9.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N/E:X/CR:M/IR:H/AR:M/MAV:N/MAC:X/MAT:N/MPR:N/MUI:P/MVC:X/MVI:X/MVA:L/MSC:N/MSI:S/MSA:L", // val
        100000, // exp mv
        Score(97), // exp score
      ), (
        "test 0.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:H/SC:H/SI:N/SA:N/E:U/CR:H/IR:X/AR:L/MAV:L/MAC:H/MAT:N/MPR:L/MUI:P/MVC:L/MVI:N/MVA:L/MSC:L/MSI:L/MSA:X", // val
        212221, // exp mv
        Score(1), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N/E:A/CR:L/IR:X/AR:M/MAV:L/MAC:H/MAT:X/MPR:H/MUI:N/MVC:N/MVI:H/MVA:X/MSC:N/MSI:N/MSA:X", // val
        111200, // exp mv
        Score(55), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:A/VC:H/VI:L/VA:H/SC:N/SI:L/SA:H/E:U/CR:H/IR:H/AR:H/MAV:N/MAC:H/MAT:N/MPR:X/MUI:P/MVC:L/MVI:H/MVA:H/MSC:L/MSI:L/MSA:H", // val
        111120, // exp mv
        Score(39), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:A/VC:H/VI:N/VA:H/SC:H/SI:L/SA:L/E:X/CR:M/IR:X/AR:X/MAV:L/MAC:H/MAT:X/MPR:L/MUI:P/MVC:N/MVI:N/MVA:H/MSC:L/MSI:L/MSA:L", // val
        211200, // exp mv
        Score(39), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:A/VC:H/VI:N/VA:N/SC:H/SI:H/SA:L/E:P/CR:M/IR:H/AR:M/MAV:X/MAC:H/MAT:P/MPR:X/MUI:X/MVC:N/MVI:L/MVA:N/MSC:H/MSI:S/MSA:X", // val
        212011, // exp mv
        Score(22), // exp score
      ), (
        "test 6", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:A/VC:N/VI:L/VA:N/SC:L/SI:H/SA:N/E:X/CR:H/IR:X/AR:X/MAV:X/MAC:L/MAT:N/MPR:H/MUI:X/MVC:X/MVI:L/MVA:N/MSC:L/MSI:S/MSA:N", // val
        202001, // exp mv
        Score(60), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:L/SI:H/SA:N/E:X/CR:M/IR:H/AR:M/MAV:L/MAC:X/MAT:P/MPR:L/MUI:X/MVC:H/MVI:L/MVA:X/MSC:L/MSI:H/MSA:H", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:N/VC:L/VI:L/VA:H/SC:L/SI:L/SA:H/E:U/CR:X/IR:L/AR:M/MAV:X/MAC:X/MAT:P/MPR:H/MUI:N/MVC:H/MVI:L/MVA:L/MSC:H/MSI:X/MSA:H", // val
        111120, // exp mv
        Score(37), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:H/E:U/CR:L/IR:X/AR:H/MAV:L/MAC:L/MAT:P/MPR:X/MUI:N/MVC:H/MVI:L/MVA:L/MSC:X/MSI:L/MSA:N", // val
        111221, // exp mv
        Score(10), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:L/SA:N/E:U/CR:L/IR:L/AR:M/MAV:P/MAC:H/MAT:X/MPR:N/MUI:P/MVC:H/MVI:N/MVA:L/MSC:L/MSI:L/MSA:H", // val
        211121, // exp mv
        Score(6), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:N/VC:N/VI:H/VA:N/SC:H/SI:L/SA:L/E:P/CR:L/IR:H/AR:H/MAV:L/MAC:L/MAT:N/MPR:X/MUI:N/MVC:L/MVI:X/MVA:X/MSC:X/MSI:L/MSA:N", // val
        101110, // exp mv
        Score(68), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:N/VC:N/VI:L/VA:H/SC:L/SI:N/SA:L/E:U/CR:L/IR:M/AR:X/MAV:X/MAC:X/MAT:X/MPR:L/MUI:N/MVC:L/MVI:H/MVA:X/MSC:X/MSI:X/MSA:L", // val
        111220, // exp mv
        Score(21), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:H/SA:L/E:P/CR:X/IR:L/AR:L/MAV:L/MAC:X/MAT:P/MPR:X/MUI:A/MVC:L/MVI:H/MVA:X/MSC:L/MSI:S/MSA:H", // val
        211011, // exp mv
        Score(40), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:L/E:P/CR:L/IR:X/AR:M/MAV:P/MAC:L/MAT:P/MPR:H/MUI:X/MVC:N/MVI:N/MVA:L/MSC:H/MSI:S/MSA:L", // val
        212011, // exp mv
        Score(22), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:P/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H/E:X/CR:X/IR:M/AR:X/MAV:A/MAC:H/MAT:P/MPR:H/MUI:X/MVC:H/MVI:L/MVA:L/MSC:N/MSI:L/MSA:H", // val
        211100, // exp mv
        Score(57), // exp score
      ), (
        "test 1.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:P/VC:H/VI:N/VA:L/SC:H/SI:N/SA:H/E:U/CR:X/IR:H/AR:X/MAV:A/MAC:X/MAT:P/MPR:X/MUI:A/MVC:N/MVI:N/MVA:X/MSC:L/MSI:S/MSA:S", // val
        212021, // exp mv
        Score(13), // exp score
      ), (
        "test 0.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:P/VC:L/VI:H/VA:H/SC:L/SI:L/SA:N/E:U/CR:M/IR:X/AR:L/MAV:P/MAC:L/MAT:X/MPR:H/MUI:N/MVC:L/MVI:N/MVA:L/MSC:L/MSI:N/MSA:X", // val
        212221, // exp mv
        Score(1), // exp score
      ), (
        "test 8.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:P/VC:L/VI:H/VA:N/SC:L/SI:H/SA:H/E:A/CR:X/IR:L/AR:H/MAV:N/MAC:H/MAT:N/MPR:N/MUI:N/MVC:L/MVI:H/MVA:N/MSC:L/MSI:X/MSA:H", // val
        011101, // exp mv
        Score(81), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:P/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:X/CR:L/IR:X/AR:M/MAV:P/MAC:X/MAT:P/MPR:H/MUI:X/MVC:X/MVI:N/MVA:X/MSC:X/MSI:H/MSA:N", // val
        212101, // exp mv
        Score(18), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:P/VC:N/VI:H/VA:H/SC:H/SI:L/SA:H/E:X/CR:L/IR:M/AR:M/MAV:L/MAC:H/MAT:P/MPR:L/MUI:X/MVC:X/MVI:N/MVA:X/MSC:H/MSI:H/MSA:L", // val
        211101, // exp mv
        Score(43), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N/E:P/CR:X/IR:L/AR:L/MAV:X/MAC:X/MAT:P/MPR:N/MUI:X/MVC:L/MVI:H/MVA:X/MSC:L/MSI:N/MSA:L", // val
        111211, // exp mv
        Score(24), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:L/SC:N/SI:L/SA:N/E:U/CR:H/IR:M/AR:M/MAV:X/MAC:L/MAT:N/MPR:X/MUI:A/MVC:L/MVI:N/MVA:H/MSC:X/MSI:N/MSA:H", // val
        201121, // exp mv
        Score(15), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:H/VI:L/VA:H/SC:L/SI:H/SA:N/E:P/CR:H/IR:M/AR:X/MAV:X/MAC:H/MAT:N/MPR:H/MUI:X/MVC:H/MVI:N/MVA:H/MSC:L/MSI:L/MSA:N", // val
        211210, // exp mv
        Score(16), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:H/VI:L/VA:N/SC:H/SI:L/SA:H/E:A/CR:X/IR:M/AR:L/MAV:A/MAC:X/MAT:X/MPR:N/MUI:X/MVC:L/MVI:X/MVA:L/MSC:L/MSI:H/MSA:N", // val
        112101, // exp mv
        Score(45), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:X/IR:L/AR:M/MAV:X/MAC:H/MAT:P/MPR:H/MUI:P/MVC:X/MVI:L/MVA:L/MSC:X/MSI:X/MSA:H", // val
        212101, // exp mv
        Score(18), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:L/VI:L/VA:N/SC:L/SI:H/SA:H/E:U/CR:X/IR:X/AR:M/MAV:L/MAC:X/MAT:N/MPR:N/MUI:P/MVC:N/MVI:X/MVA:L/MSC:L/MSI:L/MSA:S", // val
        102021, // exp mv
        Score(44), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:N/VI:L/VA:N/SC:H/SI:N/SA:N/E:X/CR:L/IR:X/AR:X/MAV:N/MAC:L/MAT:X/MPR:L/MUI:A/MVC:X/MVI:L/MVA:L/MSC:X/MSI:X/MSA:H", // val
        112101, // exp mv
        Score(48), // exp score
      ), (
        "test 4.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:N/VI:N/VA:L/SC:H/SI:L/SA:N/E:P/CR:L/IR:X/AR:H/MAV:A/MAC:L/MAT:X/MPR:H/MUI:X/MVC:H/MVI:N/MVA:X/MSC:H/MSI:H/MSA:S", // val
        211011, // exp mv
        Score(42), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:L/SA:L/E:P/CR:L/IR:L/AR:L/MAV:N/MAC:L/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:X/MSC:L/MSI:X/MSA:L", // val
        110211, // exp mv
        Score(45), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:L/E:A/CR:L/IR:H/AR:M/MAV:A/MAC:X/MAT:N/MPR:N/MUI:N/MVC:N/MVI:X/MVA:L/MSC:N/MSI:L/MSA:N", // val
        101200, // exp mv
        Score(70), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:L/E:X/CR:X/IR:L/AR:X/MAV:N/MAC:H/MAT:N/MPR:H/MUI:N/MVC:X/MVI:L/MVA:N/MSC:L/MSI:X/MSA:L", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        // FIXME: this vector is calculated as 0.7 in the official cvss
        // calculator and 0.6 in this score calculator because of floating
        // point rounding error.
        //
        // The final calculation in the official CVSS score calculator
        // is:
        //
        //   // DEBUG: { value: 1.4, mean_distance: 0.7499999999999999 }
        //   = 1.4 - 0.7499999999
        //
        // The final calculation in this score calculator is:
        //
        //   // DEBUG: sum=0.75, count=1
        //   // DEBUG: mv_score_f64=1.4 mean_pd=0.75
        //   = 1.4 - 0.75
        //
        // i suspect (but need to confirm) that this is a rounding error
        // in the official CVSS calculator:
        //
        //   >> (1.4 - 0.7499999999).round(1)
        //   => 0.7
        //   >> (1.4 - 0.75).round(1)
        //   => 0.6
        //
        "test 0.7 xyz (rounding error?)", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:L/SA:N/E:U/CR:H/IR:M/AR:M/MAV:P/MAC:X/MAT:P/MPR:N/MUI:X/MVC:X/MVI:X/MVA:L/MSC:N/MSI:N/MSA:S", // val
        212021, // exp mv
        Score(6), // exp score // FIXME: actual: Score(7)
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:H/SI:L/SA:H/E:X/CR:M/IR:M/AR:M/MAV:L/MAC:H/MAT:N/MPR:N/MUI:A/MVC:H/MVI:H/MVA:N/MSC:X/MSI:H/MSA:X", // val
        110101, // exp mv
        Score(71), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:L/SC:H/SI:N/SA:H/E:X/CR:L/IR:M/AR:H/MAV:L/MAC:X/MAT:P/MPR:N/MUI:A/MVC:N/MVI:X/MVA:L/MSC:H/MSI:H/MSA:H", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:X/CR:L/IR:X/AR:M/MAV:A/MAC:L/MAT:X/MPR:L/MUI:A/MVC:H/MVI:H/MVA:L/MSC:X/MSI:H/MSA:S", // val
        210000, // exp mv
        Score(83), // exp score
      ), (
        "test 1.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:L/SI:H/SA:N/E:U/CR:M/IR:X/AR:L/MAV:N/MAC:L/MAT:N/MPR:X/MUI:P/MVC:L/MVI:X/MVA:N/MSC:X/MSI:L/MSA:L", // val
        102221, // exp mv
        Score(12), // exp score
      ), (
        "test 4.2", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:N/SC:L/SI:H/SA:L/E:P/CR:M/IR:L/AR:M/MAV:P/MAC:X/MAT:X/MPR:L/MUI:N/MVC:L/MVI:H/MVA:H/MSC:L/MSI:S/MSA:S", // val
        211011, // exp mv
        Score(42), // exp score
      ), (
        "test 0.4", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:N/SC:L/SI:N/SA:L/E:U/CR:X/IR:M/AR:M/MAV:L/MAC:X/MAT:X/MPR:H/MUI:P/MVC:H/MVI:N/MVA:N/MSC:X/MSI:L/MSA:N", // val
        211220, // exp mv
        Score(4), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:H/VA:H/SC:N/SI:L/SA:L/E:U/CR:X/IR:M/AR:M/MAV:N/MAC:X/MAT:X/MPR:X/MUI:A/MVC:H/MVI:H/MVA:X/MSC:X/MSI:N/MSA:H", // val
        110120, // exp mv
        Score(55), // exp score
      ), (
        "test 7.4", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:L/SC:H/SI:L/SA:H/E:X/CR:H/IR:M/AR:L/MAV:N/MAC:H/MAT:X/MPR:L/MUI:P/MVC:X/MVI:H/MVA:H/MSC:X/MSI:N/MSA:S", // val
        111001, // exp mv
        Score(74), // exp score
      ), (
        "test 6.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:N/SA:H/E:X/CR:H/IR:H/AR:H/MAV:N/MAC:X/MAT:N/MPR:X/MUI:P/MVC:X/MVI:L/MVA:N/MSC:H/MSI:L/MSA:H", // val
        102101, // exp mv
        Score(63), // exp score
      ), (
        "test 2.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:L/SC:H/SI:L/SA:L/E:U/CR:L/IR:M/AR:X/MAV:A/MAC:H/MAT:P/MPR:X/MUI:N/MVC:H/MVI:X/MVA:N/MSC:L/MSI:L/MSA:X", // val
        110221, // exp mv
        Score(28), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:L/SC:H/SI:N/SA:L/E:A/CR:X/IR:L/AR:L/MAV:L/MAC:H/MAT:N/MPR:L/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:L/MSA:N", // val
        210100, // exp mv
        Score(67), // exp score
      ), (
        "test 7.5", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:L/SC:L/SI:N/SA:H/E:A/CR:X/IR:X/AR:X/MAV:N/MAC:H/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:L/MSA:N", // val
        110200, // exp mv
        Score(75), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:L/SC:N/SI:L/SA:N/E:U/CR:H/IR:L/AR:H/MAV:P/MAC:H/MAT:N/MPR:X/MUI:P/MVC:H/MVI:L/MVA:L/MSC:H/MSI:H/MSA:H", // val
        211120, // exp mv
        Score(18), // exp score
      ), (
        "test 5", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:H/SC:N/SI:N/SA:L/E:P/CR:M/IR:X/AR:H/MAV:X/MAC:H/MAT:N/MPR:N/MUI:N/MVC:H/MVI:X/MVA:L/MSC:N/MSI:H/MSA:N", // val
        111111, // exp mv
        Score(50), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:L/SI:N/SA:L/E:P/CR:H/IR:M/AR:L/MAV:P/MAC:L/MAT:N/MPR:X/MUI:A/MVC:L/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X", // val
        202211, // exp mv
        Score(9), // exp score
      ), (
        "test 1.4", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:L/SC:L/SI:N/SA:N/E:P/CR:X/IR:L/AR:L/MAV:X/MAC:H/MAT:X/MPR:L/MUI:X/MVC:H/MVI:N/MVA:H/MSC:X/MSI:N/MSA:L", // val
        211210, // exp mv
        Score(14), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:N/VI:N/VA:H/SC:H/SI:N/SA:H/E:P/CR:H/IR:M/AR:H/MAV:N/MAC:L/MAT:P/MPR:N/MUI:P/MVC:H/MVI:L/MVA:L/MSC:H/MSI:X/MSA:H", // val
        111110, // exp mv
        Score(57), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:N/VI:N/VA:H/SC:L/SI:L/SA:H/E:A/CR:M/IR:L/AR:M/MAV:P/MAC:X/MAT:X/MPR:H/MUI:A/MVC:X/MVI:X/MVA:H/MSC:X/MSI:H/MSA:X", // val
        211101, // exp mv
        Score(43), // exp score
      ), (
        "test 6", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:H/SC:L/SI:N/SA:N/E:A/CR:H/IR:L/AR:M/MAV:N/MAC:H/MAT:N/MPR:X/MUI:P/MVC:X/MVI:L/MVA:H/MSC:L/MSI:L/MSA:X", // val
        111200, // exp mv
        Score(60), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:L/SC:L/SI:L/SA:H/E:U/CR:L/IR:M/AR:H/MAV:N/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:N/MSC:N/MSI:S/MSA:S", // val
        011021, // exp mv
        Score(68), // exp score
      ), (
        "test 6.3", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:N/SA:N/E:P/CR:M/IR:L/AR:L/MAV:X/MAC:L/MAT:P/MPR:X/MUI:P/MVC:L/MVI:L/MVA:H/MSC:L/MSI:S/MSA:N", // val
        111011, // exp mv
        Score(63), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:H/SI:L/SA:H/E:U/CR:L/IR:H/AR:X/MAV:P/MAC:H/MAT:P/MPR:X/MUI:X/MVC:N/MVI:X/MVA:L/MSC:N/MSI:S/MSA:S", // val
        212021, // exp mv
        Score(11), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:L/SI:H/SA:H/E:A/CR:M/IR:M/AR:H/MAV:P/MAC:X/MAT:P/MPR:X/MUI:P/MVC:X/MVI:L/MVA:X/MSC:N/MSI:N/MSA:N", // val
        211201, // exp mv
        Score(17), // exp score
      ), (
        "test 0.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:N/E:U/CR:H/IR:H/AR:H/MAV:A/MAC:L/MAT:P/MPR:L/MUI:P/MVC:L/MVI:L/MVA:N/MSC:N/MSI:L/MSA:S", // val
        212021, // exp mv
        Score(8), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:L/VI:H/VA:N/SC:H/SI:N/SA:H/E:A/CR:L/IR:L/AR:X/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:N/MVI:H/MVA:X/MSC:N/MSI:H/MSA:X", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/SC:H/SI:L/SA:N/E:U/CR:L/IR:X/AR:H/MAV:P/MAC:L/MAT:P/MPR:X/MUI:A/MVC:X/MVI:H/MVA:H/MSC:L/MSI:X/MSA:L", // val
        211220, // exp mv
        Score(6), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N/E:A/CR:L/IR:L/AR:X/MAV:X/MAC:X/MAT:P/MPR:H/MUI:A/MVC:H/MVI:N/MVA:H/MSC:N/MSI:N/MSA:H", // val
        211100, // exp mv
        Score(55), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:H/VI:H/VA:N/SC:H/SI:L/SA:L/E:X/CR:L/IR:M/AR:M/MAV:P/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:N/MVA:H/MSC:N/MSI:H/MSA:N", // val
        211101, // exp mv
        Score(39), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N/E:U/CR:H/IR:L/AR:L/MAV:P/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:L/MVA:L/MSC:H/MSI:S/MSA:X", // val
        212021, // exp mv
        Score(10), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:H/VI:L/VA:N/SC:N/SI:L/SA:H/E:A/CR:X/IR:M/AR:X/MAV:P/MAC:X/MAT:X/MPR:L/MUI:N/MVC:L/MVI:H/MVA:H/MSC:N/MSI:S/MSA:N", // val
        211000, // exp mv
        Score(70), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:L/VI:H/VA:L/SC:L/SI:N/SA:N/E:A/CR:M/IR:X/AR:H/MAV:P/MAC:L/MAT:P/MPR:X/MUI:P/MVC:N/MVI:H/MVA:X/MSC:H/MSI:X/MSA:S", // val
        211000, // exp mv
        Score(70), // exp score
      ), (
        "test 5.2", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:L/VI:L/VA:H/SC:N/SI:N/SA:H/E:X/CR:X/IR:X/AR:X/MAV:P/MAC:L/MAT:X/MPR:N/MUI:X/MVC:H/MVI:N/MVA:X/MSC:N/MSI:X/MSA:L", // val
        201200, // exp mv
        Score(52), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:L/VI:N/VA:L/SC:H/SI:L/SA:L/E:A/CR:M/IR:L/AR:H/MAV:X/MAC:X/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:H/MSC:N/MSI:H/MSA:X", // val
        211100, // exp mv
        Score(56), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:N/VI:L/VA:L/SC:N/SI:N/SA:L/E:P/CR:X/IR:L/AR:H/MAV:A/MAC:L/MAT:N/MPR:L/MUI:X/MVC:H/MVI:H/MVA:N/MSC:H/MSI:H/MSA:N", // val
        200110, // exp mv
        Score(70), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:L/SA:N/E:A/CR:H/IR:M/AR:X/MAV:L/MAC:L/MAT:P/MPR:X/MUI:X/MVC:X/MVI:N/MVA:X/MSC:H/MSI:L/MSA:L", // val
        212101, // exp mv
        Score(21), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:L/SC:H/SI:L/SA:L/E:P/CR:M/IR:M/AR:M/MAV:P/MAC:H/MAT:N/MPR:H/MUI:A/MVC:N/MVI:X/MVA:L/MSC:L/MSI:H/MSA:L", // val
        211111, // exp mv
        Score(16), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:H/E:A/CR:M/IR:X/AR:M/MAV:N/MAC:L/MAT:P/MPR:H/MUI:X/MVC:H/MVI:N/MVA:L/MSC:L/MSI:X/MSA:X", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:H/VI:L/VA:H/SC:H/SI:N/SA:L/E:P/CR:X/IR:M/AR:H/MAV:X/MAC:H/MAT:X/MPR:N/MUI:N/MVC:L/MVI:X/MVA:L/MSC:L/MSI:L/MSA:S", // val
        112011, // exp mv
        Score(51), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:H/VI:L/VA:N/SC:H/SI:H/SA:N/E:P/CR:M/IR:L/AR:M/MAV:X/MAC:L/MAT:X/MPR:L/MUI:P/MVC:X/MVI:L/MVA:X/MSC:X/MSI:L/MSA:H", // val
        201111, // exp mv
        Score(37), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:L/VI:H/VA:L/SC:N/SI:L/SA:L/E:A/CR:L/IR:M/AR:M/MAV:P/MAC:L/MAT:X/MPR:H/MUI:A/MVC:N/MVI:L/MVA:L/MSC:H/MSI:N/MSA:N", // val
        202101, // exp mv
        Score(41), // exp score
      ), (
        "test 4.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:L/VI:N/VA:H/SC:H/SI:H/SA:N/E:A/CR:M/IR:M/AR:M/MAV:N/MAC:L/MAT:P/MPR:H/MUI:A/MVC:N/MVI:X/MVA:N/MSC:X/MSI:H/MSA:L", // val
        112101, // exp mv
        Score(47), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:L/VI:N/VA:L/SC:N/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:P/MAC:H/MAT:X/MPR:N/MUI:X/MVC:H/MVI:H/MVA:H/MSC:N/MSI:L/MSA:L", // val
        210200, // exp mv
        Score(54), // exp score
      ), (
        "test 6.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:N/VI:H/VA:L/SC:H/SI:L/SA:H/E:X/CR:M/IR:L/AR:M/MAV:N/MAC:L/MAT:X/MPR:X/MUI:N/MVC:N/MVI:N/MVA:X/MSC:L/MSI:H/MSA:L", // val
        102101, // exp mv
        Score(63), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:L/SI:L/SA:L/E:A/CR:M/IR:H/AR:X/MAV:A/MAC:H/MAT:N/MPR:L/MUI:A/MVC:X/MVI:X/MVA:L/MSC:H/MSI:H/MSA:X", // val
        211100, // exp mv
        Score(59), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:N/VI:L/VA:H/SC:N/SI:L/SA:N/E:A/CR:X/IR:H/AR:L/MAV:L/MAC:X/MAT:X/MPR:X/MUI:A/MVC:N/MVI:H/MVA:L/MSC:N/MSI:N/MSA:H", // val
        211100, // exp mv
        Score(55), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:L/SA:L/E:U/CR:X/IR:H/AR:M/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVC:L/MVI:X/MVA:N/MSC:L/MSI:N/MSA:S", // val
        102021, // exp mv
        Score(45), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:P/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:M/MAV:P/MAC:X/MAT:P/MPR:L/MUI:N/MVC:X/MVI:X/MVA:N/MSC:H/MSI:H/MSA:S", // val
        211010, // exp mv
        Score(55), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:P/VC:H/VI:L/VA:L/SC:L/SI:N/SA:N/E:P/CR:L/IR:L/AR:M/MAV:X/MAC:L/MAT:P/MPR:N/MUI:P/MVC:X/MVI:H/MVA:X/MSC:N/MSI:S/MSA:L", // val
        110011, // exp mv
        Score(70), // exp score
      ), (
        "test 6.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:P/VC:H/VI:N/VA:L/SC:H/SI:N/SA:N/E:A/CR:L/IR:X/AR:H/MAV:L/MAC:L/MAT:N/MPR:H/MUI:A/MVC:L/MVI:X/MVA:N/MSC:N/MSI:H/MSA:S", // val
        202001, // exp mv
        Score(61), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:P/VC:H/VI:N/VA:N/SC:N/SI:H/SA:H/E:A/CR:H/IR:X/AR:M/MAV:L/MAC:X/MAT:N/MPR:L/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:H/MSA:S", // val
        211000, // exp mv
        Score(69), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:P/VC:L/VI:L/VA:L/SC:L/SI:H/SA:H/E:P/CR:X/IR:X/AR:M/MAV:X/MAC:X/MAT:X/MPR:H/MUI:N/MVC:L/MVI:X/MVA:L/MSC:H/MSI:H/MSA:L", // val
        112111, // exp mv
        Score(22), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:P/VC:L/VI:L/VA:N/SC:N/SI:L/SA:H/E:X/CR:H/IR:X/AR:X/MAV:A/MAC:L/MAT:P/MPR:H/MUI:A/MVC:N/MVI:L/MVA:X/MSC:H/MSI:S/MSA:X", // val
        212001, // exp mv
        Score(51), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:P/VC:N/VI:H/VA:N/SC:L/SI:H/SA:H/E:P/CR:M/IR:H/AR:M/MAV:N/MAC:X/MAT:P/MPR:N/MUI:A/MVC:X/MVI:X/MVA:L/MSC:L/MSI:L/MSA:S", // val
        111010, // exp mv
        Score(71), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:P/VC:N/VI:N/VA:H/SC:L/SI:N/SA:H/E:P/CR:H/IR:X/AR:M/MAV:N/MAC:L/MAT:P/MPR:H/MUI:X/MVC:H/MVI:L/MVA:H/MSC:H/MSI:X/MSA:H", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:P/VC:N/VI:N/VA:L/SC:N/SI:L/SA:L/E:P/CR:H/IR:H/AR:H/MAV:X/MAC:X/MAT:N/MPR:X/MUI:X/MVC:L/MVI:X/MVA:N/MSC:N/MSI:S/MSA:L", // val
        212011, // exp mv
        Score(20), // exp score
      ), (
        "test 6.5", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:M/MAV:N/MAC:X/MAT:N/MPR:H/MUI:X/MVC:N/MVI:N/MVA:L/MSC:H/MSI:L/MSA:S", // val
        112001, // exp mv
        Score(65), // exp score
      ), (
        "test 8.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:H/VI:N/VA:H/SC:H/SI:L/SA:N/E:A/CR:M/IR:X/AR:X/MAV:N/MAC:L/MAT:P/MPR:L/MUI:N/MVC:N/MVI:H/MVA:L/MSC:L/MSI:H/MSA:S", // val
        111000, // exp mv
        Score(87), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:H/VI:N/VA:H/SC:L/SI:H/SA:N/E:X/CR:L/IR:X/AR:L/MAV:A/MAC:X/MAT:X/MPR:N/MUI:X/MVC:N/MVI:X/MVA:X/MSC:N/MSI:S/MSA:X", // val
        111001, // exp mv
        Score(70), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:H/VI:N/VA:N/SC:N/SI:H/SA:N/E:A/CR:X/IR:M/AR:L/MAV:X/MAC:H/MAT:N/MPR:H/MUI:N/MVC:X/MVI:X/MVA:L/MSC:X/MSI:N/MSA:X", // val
        111200, // exp mv
        Score(55), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:L/VI:H/VA:N/SC:H/SI:N/SA:L/E:P/CR:X/IR:L/AR:M/MAV:A/MAC:L/MAT:P/MPR:L/MUI:A/MVC:L/MVI:L/MVA:X/MSC:N/MSI:H/MSA:X", // val
        212111, // exp mv
        Score(9), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:N/VI:L/VA:N/SC:H/SI:L/SA:L/E:A/CR:M/IR:H/AR:M/MAV:L/MAC:X/MAT:X/MPR:H/MUI:X/MVC:H/MVI:N/MVA:L/MSC:L/MSI:L/MSA:L", // val
        211201, // exp mv
        Score(17), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:N/VI:L/VA:N/SC:N/SI:H/SA:H/E:X/CR:X/IR:M/AR:H/MAV:X/MAC:H/MAT:N/MPR:H/MUI:P/MVC:H/MVI:H/MVA:L/MSC:N/MSI:H/MSA:X", // val
        210100, // exp mv
        Score(69), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:N/SA:H/E:U/CR:X/IR:M/AR:M/MAV:P/MAC:X/MAT:N/MPR:H/MUI:N/MVC:H/MVI:X/MVA:X/MSC:L/MSI:S/MSA:H", // val
        210020, // exp mv
        Score(55), // exp score
      ), (
        "test 8.2", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:N/SA:H/E:X/CR:M/IR:L/AR:X/MAV:L/MAC:H/MAT:X/MPR:H/MUI:X/MVC:N/MVI:L/MVA:H/MSC:N/MSI:S/MSA:N", // val
        111000, // exp mv
        Score(82), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:L/SA:H/E:X/CR:M/IR:M/AR:M/MAV:N/MAC:X/MAT:P/MPR:L/MUI:P/MVC:X/MVI:N/MVA:X/MSC:H/MSI:H/MSA:L", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:L/SI:L/SA:N/E:P/CR:X/IR:X/AR:M/MAV:N/MAC:L/MAT:P/MPR:X/MUI:N/MVC:H/MVI:X/MVA:L/MSC:N/MSI:L/MSA:X", // val
        110210, // exp mv
        Score(67), // exp score
      ), (
        "test 6.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:L/VI:N/VA:H/SC:L/SI:N/SA:H/E:A/CR:H/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:X/MUI:A/MVC:X/MVI:L/MVA:N/MSC:H/MSI:X/MSA:S", // val
        112001, // exp mv
        Score(66), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:L/E:X/CR:M/IR:H/AR:H/MAV:P/MAC:H/MAT:N/MPR:N/MUI:A/MVC:L/MVI:H/MVA:L/MSC:N/MSI:X/MSA:H", // val
        211100, // exp mv
        Score(56), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:H/VI:N/VA:L/SC:H/SI:L/SA:H/E:X/CR:X/IR:M/AR:L/MAV:P/MAC:L/MAT:N/MPR:X/MUI:X/MVC:N/MVI:H/MVA:L/MSC:H/MSI:H/MSA:X", // val
        201101, // exp mv
        Score(56), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:H/VI:N/VA:L/SC:N/SI:H/SA:N/E:X/CR:X/IR:X/AR:M/MAV:P/MAC:H/MAT:N/MPR:N/MUI:A/MVC:L/MVI:L/MVA:N/MSC:H/MSI:L/MSA:X", // val
        212101, // exp mv
        Score(20), // exp score
      ), (
        "test 6.2", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:H/SC:H/SI:L/SA:L/E:A/CR:M/IR:M/AR:L/MAV:P/MAC:L/MAT:X/MPR:H/MUI:X/MVC:N/MVI:N/MVA:L/MSC:N/MSI:S/MSA:S", // val
        202001, // exp mv
        Score(62), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:X/MAV:N/MAC:H/MAT:P/MPR:L/MUI:X/MVC:N/MVI:X/MVA:H/MSC:N/MSI:S/MSA:S", // val
        111020, // exp mv
        Score(58), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:N/VI:L/VA:N/SC:L/SI:H/SA:H/E:U/CR:M/IR:X/AR:H/MAV:P/MAC:H/MAT:X/MPR:H/MUI:P/MVC:L/MVI:L/MVA:H/MSC:X/MSI:X/MSA:X", // val
        211120, // exp mv
        Score(17), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/E:X/CR:L/IR:H/AR:M/MAV:A/MAC:X/MAT:X/MPR:X/MUI:P/MVC:H/MVI:X/MVA:H/MSC:H/MSI:S/MSA:X", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:L/E:A/CR:X/IR:M/AR:L/MAV:X/MAC:X/MAT:N/MPR:X/MUI:X/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:L", // val
        111200, // exp mv
        Score(56), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:H/SI:L/SA:L/E:X/CR:L/IR:M/AR:H/MAV:X/MAC:X/MAT:P/MPR:H/MUI:N/MVC:H/MVI:X/MVA:N/MSC:X/MSI:X/MSA:X", // val
        110101, // exp mv
        Score(70), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:L/SC:H/SI:N/SA:N/E:P/CR:H/IR:L/AR:X/MAV:P/MAC:L/MAT:P/MPR:L/MUI:N/MVC:H/MVI:L/MVA:X/MSC:H/MSI:S/MSA:H", // val
        211010, // exp mv
        Score(56), // exp score
      ), (
        "test 0.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:L/SA:L/E:P/CR:H/IR:M/AR:H/MAV:X/MAC:H/MAT:X/MPR:H/MUI:A/MVC:L/MVI:N/MVA:L/MSC:X/MSI:N/MSA:X", // val
        212211, // exp mv
        Score(3), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:H/VI:N/VA:L/SC:H/SI:N/SA:L/E:X/CR:L/IR:M/AR:X/MAV:A/MAC:X/MAT:N/MPR:N/MUI:A/MVC:X/MVI:H/MVA:H/MSC:N/MSI:H/MSA:X", // val
        110100, // exp mv
        Score(85), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:H/SC:H/SI:N/SA:H/E:U/CR:M/IR:H/AR:M/MAV:A/MAC:L/MAT:P/MPR:X/MUI:P/MVC:X/MVI:H/MVA:H/MSC:H/MSI:N/MSA:S", // val
        111020, // exp mv
        Score(57), // exp score
      ), (
        "test 3.8", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:L/VA:L/SC:H/SI:H/SA:N/E:U/CR:X/IR:X/AR:L/MAV:L/MAC:H/MAT:X/MPR:H/MUI:N/MVC:H/MVI:L/MVA:H/MSC:H/MSI:X/MSA:H", // val
        111120, // exp mv
        Score(38), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:N/SA:L/E:X/CR:M/IR:M/AR:M/MAV:N/MAC:X/MAT:X/MPR:H/MUI:P/MVC:H/MVI:N/MVA:L/MSC:H/MSI:N/MSA:L", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:N/SA:H/E:P/CR:X/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:H/MUI:X/MVC:N/MVI:X/MVA:L/MSC:H/MSI:X/MSA:X", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 3.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:N/SA:L/E:P/CR:H/IR:X/AR:H/MAV:P/MAC:L/MAT:P/MPR:X/MUI:N/MVC:N/MVI:N/MVA:H/MSC:N/MSI:H/MSA:N", // val
        211110, // exp mv
        Score(36), // exp score
      ), (
        "test 6.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:L/VI:H/VA:L/SC:L/SI:N/SA:L/E:U/CR:M/IR:M/AR:X/MAV:N/MAC:X/MAT:P/MPR:L/MUI:P/MVC:H/MVI:H/MVA:X/MSC:H/MSI:X/MSA:S", // val
        110021, // exp mv
        Score(66), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:L/SA:N/E:P/CR:X/IR:H/AR:X/MAV:X/MAC:X/MAT:N/MPR:L/MUI:N/MVC:N/MVI:L/MVA:L/MSC:L/MSI:H/MSA:L", // val
        112111, // exp mv
        Score(22), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:L/SI:H/SA:L/E:P/CR:H/IR:H/AR:X/MAV:X/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:X/MVA:L/MSC:L/MSI:L/MSA:X", // val
        102211, // exp mv
        Score(20), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:L/SI:N/SA:N/E:U/CR:X/IR:H/AR:H/MAV:N/MAC:H/MAT:P/MPR:H/MUI:N/MVC:L/MVI:N/MVA:N/MSC:N/MSI:X/MSA:H", // val
        112121, // exp mv
        Score(10), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:L/AR:M/MAV:A/MAC:L/MAT:N/MPR:X/MUI:X/MVC:L/MVI:H/MVA:L/MSC:H/MSI:N/MSA:L", // val
        101111, // exp mv
        Score(56), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:N/E:A/CR:X/IR:X/AR:M/MAV:P/MAC:X/MAT:X/MPR:X/MUI:N/MVC:H/MVI:L/MVA:N/MSC:L/MSI:L/MSA:X", // val
        211200, // exp mv
        Score(41), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:H/VI:L/VA:L/SC:N/SI:N/SA:H/E:U/CR:L/IR:M/AR:H/MAV:P/MAC:H/MAT:X/MPR:L/MUI:P/MVC:N/MVI:L/MVA:N/MSC:N/MSI:S/MSA:S", // val
        212021, // exp mv
        Score(11), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H/E:X/CR:M/IR:L/AR:X/MAV:L/MAC:H/MAT:X/MPR:L/MUI:P/MVC:N/MVI:H/MVA:X/MSC:L/MSI:L/MSA:L", // val
        211200, // exp mv
        Score(39), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:H/SC:L/SI:N/SA:N/E:X/CR:X/IR:M/AR:H/MAV:L/MAC:X/MAT:P/MPR:H/MUI:N/MVC:X/MVI:N/MVA:L/MSC:X/MSI:N/MSA:L", // val
        111200, // exp mv
        Score(56), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:H/SC:N/SI:N/SA:L/E:P/CR:H/IR:H/AR:L/MAV:N/MAC:H/MAT:N/MPR:N/MUI:A/MVC:N/MVI:L/MVA:L/MSC:N/MSI:X/MSA:H", // val
        112111, // exp mv
        Score(21), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:N/SA:N/E:A/CR:X/IR:H/AR:H/MAV:P/MAC:H/MAT:X/MPR:H/MUI:P/MVC:X/MVI:X/MVA:N/MSC:N/MSI:H/MSA:N", // val
        212101, // exp mv
        Score(18), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:H/SI:H/SA:L/E:A/CR:H/IR:H/AR:X/MAV:X/MAC:X/MAT:P/MPR:X/MUI:N/MVC:H/MVI:H/MVA:N/MSC:N/MSI:H/MSA:N", // val
        110100, // exp mv
        Score(85), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:L/SC:N/SI:N/SA:H/E:P/CR:H/IR:M/AR:M/MAV:A/MAC:L/MAT:N/MPR:L/MUI:X/MVC:N/MVI:N/MVA:H/MSC:L/MSI:X/MSA:L", // val
        201211, // exp mv
        Score(18), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N/E:A/CR:H/IR:X/AR:L/MAV:N/MAC:X/MAT:N/MPR:N/MUI:N/MVC:X/MVI:N/MVA:L/MSC:N/MSI:N/MSA:H", // val
        012101, // exp mv
        Score(69), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:L/SC:L/SI:N/SA:L/E:P/CR:M/IR:M/AR:L/MAV:P/MAC:L/MAT:N/MPR:H/MUI:N/MVC:X/MVI:N/MVA:L/MSC:N/MSI:X/MSA:X", // val
        202211, // exp mv
        Score(9), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:H/SC:H/SI:L/SA:L/E:A/CR:H/IR:M/AR:M/MAV:P/MAC:L/MAT:P/MPR:L/MUI:P/MVC:L/MVI:L/MVA:X/MSC:H/MSI:L/MSA:X", // val
        211101, // exp mv
        Score(45), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:N/VI:H/VA:N/SC:N/SI:L/SA:N/E:U/CR:X/IR:L/AR:M/MAV:N/MAC:H/MAT:N/MPR:H/MUI:A/MVC:N/MVI:L/MVA:N/MSC:H/MSI:N/MSA:H", // val
        112121, // exp mv
        Score(9), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:X/AR:X/MAV:P/MAC:H/MAT:X/MPR:N/MUI:N/MVC:L/MVI:N/MVA:H/MSC:N/MSI:N/MSA:L", // val
        211200, // exp mv
        Score(43), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:H/E:X/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:N/MPR:H/MUI:N/MVC:H/MVI:L/MVA:L/MSC:X/MSI:X/MSA:S", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 6.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:H/VI:H/VA:L/SC:N/SI:H/SA:H/E:X/CR:M/IR:L/AR:H/MAV:X/MAC:H/MAT:N/MPR:X/MUI:X/MVC:L/MVI:L/MVA:L/MSC:N/MSI:S/MSA:N", // val
        112001, // exp mv
        Score(63), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:H/VI:N/VA:L/SC:H/SI:N/SA:N/E:P/CR:X/IR:X/AR:X/MAV:L/MAC:X/MAT:P/MPR:L/MUI:X/MVC:N/MVI:X/MVA:L/MSC:H/MSI:S/MSA:N", // val
        112011, // exp mv
        Score(48), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:H/VI:N/VA:L/SC:L/SI:H/SA:L/E:A/CR:L/IR:H/AR:X/MAV:P/MAC:X/MAT:X/MPR:H/MUI:N/MVC:L/MVI:X/MVA:N/MSC:N/MSI:L/MSA:H", // val
        212101, // exp mv
        Score(20), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:H/SC:H/SI:L/SA:N/E:A/CR:H/IR:H/AR:H/MAV:L/MAC:H/MAT:X/MPR:N/MUI:P/MVC:N/MVI:L/MVA:N/MSC:N/MSI:X/MSA:N", // val
        112201, // exp mv
        Score(20), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:L/SC:H/SI:H/SA:H/E:U/CR:L/IR:H/AR:M/MAV:N/MAC:H/MAT:X/MPR:L/MUI:N/MVC:X/MVI:H/MVA:L/MSC:N/MSI:H/MSA:X", // val
        111120, // exp mv
        Score(40), // exp score
      ), (
        "test 6.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:L/SC:H/SI:H/SA:L/E:P/CR:L/IR:X/AR:M/MAV:A/MAC:H/MAT:N/MPR:H/MUI:X/MVC:H/MVI:L/MVA:H/MSC:X/MSI:S/MSA:L", // val
        111011, // exp mv
        Score(63), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:L/SC:H/SI:H/SA:L/E:P/CR:M/IR:M/AR:H/MAV:L/MAC:H/MAT:X/MPR:H/MUI:N/MVC:X/MVI:X/MVA:N/MSC:N/MSI:H/MSA:N", // val
        112111, // exp mv
        Score(19), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:N/VI:N/VA:N/SC:N/SI:H/SA:L/E:P/CR:X/IR:X/AR:M/MAV:A/MAC:L/MAT:P/MPR:N/MUI:A/MVC:X/MVI:H/MVA:L/MSC:H/MSI:S/MSA:L", // val
        111010, // exp mv
        Score(71), // exp score
      ), (
        "test 0.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:P/VC:H/VI:L/VA:H/SC:H/SI:L/SA:L/E:U/CR:H/IR:M/AR:X/MAV:P/MAC:H/MAT:X/MPR:H/MUI:X/MVC:H/MVI:L/MVA:H/MSC:N/MSI:X/MSA:N", // val
        211220, // exp mv
        Score(7), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:P/VC:H/VI:N/VA:L/SC:N/SI:N/SA:L/E:A/CR:X/IR:L/AR:L/MAV:N/MAC:L/MAT:N/MPR:L/MUI:A/MVC:H/MVI:X/MVA:L/MSC:L/MSI:N/MSA:L", // val
        101200, // exp mv
        Score(67), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:P/VC:L/VI:H/VA:L/SC:L/SI:N/SA:N/E:X/CR:L/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:L/MUI:X/MVC:X/MVI:H/MVA:N/MSC:X/MSI:H/MSA:N", // val
        211100, // exp mv
        Score(56), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:P/VC:N/VI:H/VA:H/SC:H/SI:H/SA:N/E:P/CR:L/IR:L/AR:H/MAV:P/MAC:L/MAT:N/MPR:L/MUI:N/MVC:L/MVI:X/MVA:L/MSC:N/MSI:L/MSA:N", // val
        201211, // exp mv
        Score(18), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:P/VC:N/VI:L/VA:H/SC:H/SI:H/SA:L/E:X/CR:M/IR:M/AR:M/MAV:L/MAC:X/MAT:N/MPR:L/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:L/MSA:L", // val
        210101, // exp mv
        Score(53), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H/E:X/CR:M/IR:M/AR:L/MAV:A/MAC:X/MAT:P/MPR:X/MUI:A/MVC:X/MVI:L/MVA:N/MSC:N/MSI:L/MSA:X", // val
        211101, // exp mv
        Score(40), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:L/SC:H/SI:N/SA:H/E:U/CR:H/IR:X/AR:H/MAV:P/MAC:X/MAT:P/MPR:X/MUI:X/MVC:H/MVI:L/MVA:N/MSC:X/MSI:L/MSA:H", // val
        211120, // exp mv
        Score(17), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:L/VI:L/VA:L/SC:H/SI:H/SA:L/E:A/CR:L/IR:X/AR:M/MAV:A/MAC:X/MAT:X/MPR:X/MUI:A/MVC:H/MVI:N/MVA:L/MSC:X/MSI:L/MSA:X", // val
        211101, // exp mv
        Score(43), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:L/VI:L/VA:N/SC:H/SI:N/SA:N/E:X/CR:M/IR:H/AR:X/MAV:L/MAC:X/MAT:X/MPR:L/MUI:A/MVC:L/MVI:H/MVA:H/MSC:L/MSI:L/MSA:N", // val
        211200, // exp mv
        Score(44), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:N/VI:N/VA:L/SC:H/SI:N/SA:L/E:U/CR:L/IR:M/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:N/MVC:L/MVI:L/MVA:X/MSC:X/MSI:H/MSA:N", // val
        112121, // exp mv
        Score(11), // exp score
      ), (
        "test 3.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:N/VI:N/VA:L/SC:L/SI:L/SA:H/E:X/CR:X/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:X/MUI:N/MVC:H/MVI:N/MVA:X/MSC:N/MSI:X/MSA:L", // val
        211200, // exp mv
        Score(36), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:L/SA:H/E:X/CR:H/IR:X/AR:M/MAV:P/MAC:L/MAT:N/MPR:X/MUI:X/MVC:N/MVI:L/MVA:L/MSC:N/MSI:S/MSA:N", // val
        202001, // exp mv
        Score(59), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:L/SC:N/SI:L/SA:L/E:U/CR:L/IR:L/AR:H/MAV:A/MAC:L/MAT:P/MPR:X/MUI:A/MVC:L/MVI:X/MVA:X/MSC:X/MSI:S/MSA:H", // val
        212021, // exp mv
        Score(10), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:H/E:P/CR:M/IR:X/AR:X/MAV:P/MAC:H/MAT:N/MPR:N/MUI:A/MVC:H/MVI:N/MVA:L/MSC:H/MSI:X/MSA:H", // val
        211111, // exp mv
        Score(16), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:N/SI:H/SA:H/E:P/CR:L/IR:M/AR:X/MAV:L/MAC:L/MAT:X/MPR:N/MUI:A/MVC:H/MVI:X/MVA:N/MSC:N/MSI:L/MSA:X", // val
        111111, // exp mv
        Score(43), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:H/VI:L/VA:N/SC:L/SI:H/SA:N/E:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MAT:P/MPR:X/MUI:N/MVC:H/MVI:X/MVA:N/MSC:N/MSI:X/MSA:X", // val
        111121, // exp mv
        Score(19), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:H/SC:N/SI:L/SA:L/E:P/CR:H/IR:M/AR:X/MAV:N/MAC:L/MAT:N/MPR:H/MUI:X/MVC:L/MVI:H/MVA:N/MSC:L/MSI:S/MSA:X", // val
        101011, // exp mv
        Score(73), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:H/SI:H/SA:N/E:X/CR:H/IR:M/AR:H/MAV:N/MAC:X/MAT:N/MPR:H/MUI:X/MVC:X/MVI:X/MVA:N/MSC:H/MSI:S/MSA:L", // val
        112001, // exp mv
        Score(67), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:N/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:L/IR:M/AR:M/MAV:N/MAC:L/MAT:X/MPR:X/MUI:A/MVC:X/MVI:N/MVA:H/MSC:H/MSI:X/MSA:H", // val
        111121, // exp mv
        Score(19), // exp score
      ), (
        "test 3.8", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:N/VI:L/VA:H/SC:L/SI:H/SA:H/E:U/CR:X/IR:L/AR:X/MAV:P/MAC:L/MAT:N/MPR:N/MUI:X/MVC:H/MVI:L/MVA:N/MSC:N/MSI:X/MSA:H", // val
        201120, // exp mv
        Score(38), // exp score
      ), (
        "test 4.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:N/VI:L/VA:N/SC:H/SI:H/SA:L/E:P/CR:M/IR:X/AR:X/MAV:N/MAC:H/MAT:X/MPR:L/MUI:P/MVC:H/MVI:N/MVA:L/MSC:N/MSI:H/MSA:L", // val
        111111, // exp mv
        Score(49), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:A/VC:H/VI:L/VA:L/SC:N/SI:H/SA:L/E:A/CR:M/IR:L/AR:H/MAV:X/MAC:X/MAT:P/MPR:L/MUI:A/MVC:L/MVI:N/MVA:L/MSC:H/MSI:S/MSA:H", // val
        212001, // exp mv
        Score(51), // exp score
      ), (
        "test 0.2", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:A/VC:H/VI:N/VA:L/SC:H/SI:H/SA:L/E:U/CR:M/IR:M/AR:H/MAV:P/MAC:X/MAT:N/MPR:X/MUI:N/MVC:H/MVI:X/MVA:L/MSC:N/MSI:L/MSA:L", // val
        211221, // exp mv
        Score(2), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:A/VC:L/VI:H/VA:L/SC:N/SI:N/SA:L/E:A/CR:X/IR:L/AR:X/MAV:N/MAC:H/MAT:X/MPR:N/MUI:A/MVC:X/MVI:N/MVA:L/MSC:L/MSI:X/MSA:X", // val
        112201, // exp mv
        Score(21), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:L/SC:L/SI:N/SA:L/E:X/CR:H/IR:L/AR:H/MAV:P/MAC:X/MAT:P/MPR:X/MUI:X/MVC:N/MVI:N/MVA:H/MSC:H/MSI:N/MSA:H", // val
        211100, // exp mv
        Score(57), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:H/SC:N/SI:L/SA:L/E:X/CR:X/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:X/MUI:A/MVC:H/MVI:H/MVA:X/MSC:N/MSI:N/MSA:X", // val
        110200, // exp mv
        Score(73), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:L/SC:H/SI:N/SA:N/E:A/CR:L/IR:H/AR:X/MAV:L/MAC:X/MAT:X/MPR:L/MUI:P/MVC:H/MVI:H/MVA:X/MSC:L/MSI:S/MSA:H", // val
        210000, // exp mv
        Score(84), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:L/SA:L/E:P/CR:L/IR:X/AR:M/MAV:L/MAC:X/MAT:P/MPR:X/MUI:A/MVC:H/MVI:L/MVA:L/MSC:H/MSI:H/MSA:X", // val
        111111, // exp mv
        Score(46), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:L/SA:L/E:P/CR:H/IR:L/AR:X/MAV:N/MAC:X/MAT:X/MPR:H/MUI:P/MVC:X/MVI:N/MVA:L/MSC:N/MSI:L/MSA:H", // val
        112111, // exp mv
        Score(21), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:X/CR:M/IR:M/AR:L/MAV:L/MAC:X/MAT:N/MPR:H/MUI:A/MVC:X/MVI:H/MVA:L/MSC:N/MSI:S/MSA:S", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:N/VI:H/VA:L/SC:L/SI:H/SA:N/E:P/CR:X/IR:X/AR:X/MAV:L/MAC:X/MAT:N/MPR:L/MUI:A/MVC:H/MVI:L/MVA:L/MSC:H/MSI:S/MSA:S", // val
        211010, // exp mv
        Score(57), // exp score
      ), (
        "test 2.5", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:H/SA:N/E:U/CR:X/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:A/MVC:N/MVI:X/MVA:X/MSC:L/MSI:S/MSA:S", // val
        112021, // exp mv
        Score(25), // exp score
      ), (
        "test 6.3", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:H/VI:H/VA:L/SC:L/SI:H/SA:N/E:X/CR:H/IR:H/AR:H/MAV:L/MAC:H/MAT:P/MPR:X/MUI:A/MVC:L/MVI:L/MVA:N/MSC:N/MSI:N/MSA:S", // val
        112001, // exp mv
        Score(63), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:H/VI:L/VA:L/SC:N/SI:H/SA:H/E:P/CR:X/IR:X/AR:M/MAV:X/MAC:L/MAT:P/MPR:X/MUI:N/MVC:X/MVI:X/MVA:N/MSC:H/MSI:H/MSA:H", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:H/VI:N/VA:L/SC:N/SI:L/SA:N/E:X/CR:H/IR:H/AR:H/MAV:X/MAC:X/MAT:P/MPR:L/MUI:N/MVC:L/MVI:X/MVA:X/MSC:L/MSI:X/MSA:L", // val
        112201, // exp mv
        Score(20), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:L/VI:H/VA:N/SC:H/SI:N/SA:L/E:A/CR:L/IR:X/AR:L/MAV:L/MAC:L/MAT:P/MPR:H/MUI:N/MVC:H/MVI:N/MVA:L/MSC:H/MSI:H/MSA:S", // val
        111001, // exp mv
        Score(72), // exp score
      ), (
        "test 3.1", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:N/SI:L/SA:L/E:U/CR:X/IR:M/AR:H/MAV:P/MAC:L/MAT:P/MPR:H/MUI:A/MVC:X/MVI:L/MVA:H/MSC:X/MSI:S/MSA:X", // val
        211020, // exp mv
        Score(31), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:L/E:X/CR:X/IR:M/AR:L/MAV:P/MAC:H/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:L/MSI:H/MSA:L", // val
        210100, // exp mv
        Score(69), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:H/VI:H/VA:N/SC:N/SI:H/SA:N/E:U/CR:X/IR:X/AR:H/MAV:X/MAC:H/MAT:N/MPR:L/MUI:N/MVC:N/MVI:L/MVA:H/MSC:X/MSI:X/MSA:S", // val
        111020, // exp mv
        Score(56), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:H/VI:L/VA:H/SC:H/SI:H/SA:N/E:U/CR:H/IR:L/AR:M/MAV:L/MAC:L/MAT:N/MPR:N/MUI:A/MVC:H/MVI:X/MVA:H/MSC:L/MSI:X/MSA:H", // val
        101120, // exp mv
        Score(55), // exp score
      ), (
        "test 1.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:L/VI:L/VA:N/SC:H/SI:L/SA:H/E:P/CR:L/IR:L/AR:H/MAV:P/MAC:H/MAT:X/MPR:N/MUI:A/MVC:N/MVI:N/MVA:H/MSC:N/MSI:N/MSA:N", // val
        211210, // exp mv
        Score(13), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:N/VI:H/VA:N/SC:L/SI:H/SA:L/E:X/CR:M/IR:M/AR:M/MAV:N/MAC:L/MAT:N/MPR:H/MUI:X/MVC:L/MVI:L/MVA:H/MSC:X/MSI:X/MSA:L", // val
        101101, // exp mv
        Score(71), // exp score
      ), (
        "test 5", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:N/VI:L/VA:L/SC:N/SI:N/SA:H/E:P/CR:M/IR:H/AR:L/MAV:N/MAC:X/MAT:N/MPR:L/MUI:P/MVC:N/MVI:X/MVA:X/MSC:N/MSI:L/MSA:H", // val
        102111, // exp mv
        Score(50), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:H/E:P/CR:X/IR:X/AR:M/MAV:P/MAC:X/MAT:P/MPR:N/MUI:X/MVC:H/MVI:X/MVA:X/MSC:L/MSI:L/MSA:H", // val
        211110, // exp mv
        Score(40), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:N/VI:N/VA:H/SC:L/SI:L/SA:H/E:P/CR:X/IR:H/AR:H/MAV:A/MAC:H/MAT:N/MPR:L/MUI:P/MVC:N/MVI:H/MVA:L/MSC:N/MSI:S/MSA:X", // val
        211010, // exp mv
        Score(55), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:L/E:X/CR:H/IR:H/AR:M/MAV:A/MAC:H/MAT:N/MPR:L/MUI:A/MVC:X/MVI:X/MVA:L/MSC:L/MSI:S/MSA:L", // val
        210000, // exp mv
        Score(84), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:L/SC:L/SI:H/SA:L/E:X/CR:H/IR:M/AR:L/MAV:N/MAC:L/MAT:X/MPR:H/MUI:X/MVC:X/MVI:H/MVA:X/MSC:N/MSI:N/MSA:N", // val
        100200, // exp mv
        Score(84), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:L/VI:H/VA:L/SC:H/SI:N/SA:N/E:U/CR:L/IR:H/AR:X/MAV:X/MAC:L/MAT:P/MPR:H/MUI:X/MVC:L/MVI:X/MVA:L/MSC:L/MSI:S/MSA:X", // val
        111020, // exp mv
        Score(53), // exp score
      ), (
        "test 3.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:H/SI:L/SA:N/E:P/CR:M/IR:H/AR:L/MAV:P/MAC:X/MAT:P/MPR:X/MUI:X/MVC:X/MVI:H/MVA:H/MSC:X/MSI:X/MSA:X", // val
        211110, // exp mv
        Score(38), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N/E:X/CR:H/IR:L/AR:M/MAV:N/MAC:H/MAT:P/MPR:H/MUI:P/MVC:L/MVI:N/MVA:L/MSC:X/MSI:N/MSA:H", // val
        112101, // exp mv
        Score(45), // exp score
      ), (
        "test 8.2", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:L/VI:N/VA:L/SC:L/SI:H/SA:H/E:X/CR:X/IR:X/AR:H/MAV:X/MAC:L/MAT:N/MPR:L/MUI:N/MVC:H/MVI:X/MVA:N/MSC:N/MSI:N/MSA:H", // val
        101100, // exp mv
        Score(82), // exp score
      ), (
        "test 8.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:H/SA:N/E:X/CR:M/IR:X/AR:X/MAV:A/MAC:H/MAT:P/MPR:N/MUI:X/MVC:N/MVI:H/MVA:N/MSC:L/MSI:L/MSA:S", // val
        111000, // exp mv
        Score(86), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:L/E:X/CR:M/IR:X/AR:H/MAV:P/MAC:X/MAT:X/MPR:L/MUI:A/MVC:X/MVI:H/MVA:X/MSC:X/MSI:H/MSA:L", // val
        201100, // exp mv
        Score(69), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:A/CR:X/IR:L/AR:X/MAV:X/MAC:H/MAT:P/MPR:N/MUI:P/MVC:N/MVI:H/MVA:H/MSC:X/MSI:L/MSA:S", // val
        111000, // exp mv
        Score(84), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:L/SC:L/SI:L/SA:N/E:U/CR:H/IR:H/AR:L/MAV:P/MAC:X/MAT:P/MPR:X/MUI:X/MVC:H/MVI:H/MVA:N/MSC:X/MSI:X/MSA:L", // val
        210220, // exp mv
        Score(15), // exp score
      ), (
        "test 3.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/E:P/CR:H/IR:X/AR:H/MAV:X/MAC:L/MAT:X/MPR:H/MUI:A/MVC:L/MVI:H/MVA:N/MSC:N/MSI:L/MSA:X", // val
        201210, // exp mv
        Score(33), // exp score
      ), (
        "test 3.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:L/VI:H/VA:H/SC:L/SI:N/SA:H/E:U/CR:M/IR:H/AR:H/MAV:P/MAC:H/MAT:N/MPR:L/MUI:X/MVC:X/MVI:H/MVA:N/MSC:L/MSI:S/MSA:X", // val
        211020, // exp mv
        Score(33), // exp score
      ), (
        "test 9.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:N/VI:H/VA:L/SC:H/SI:H/SA:H/E:A/CR:X/IR:H/AR:X/MAV:N/MAC:X/MAT:X/MPR:N/MUI:N/MVC:N/MVI:H/MVA:H/MSC:X/MSI:L/MSA:H", // val
        001100, // exp mv
        Score(93), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:N/VI:L/VA:L/SC:L/SI:L/SA:N/E:X/CR:X/IR:L/AR:L/MAV:X/MAC:X/MAT:X/MPR:N/MUI:X/MVC:N/MVI:L/MVA:X/MSC:X/MSI:L/MSA:L", // val
        102201, // exp mv
        Score(48), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:N/VI:L/VA:N/SC:H/SI:N/SA:N/E:X/CR:M/IR:L/AR:H/MAV:X/MAC:L/MAT:N/MPR:X/MUI:P/MVC:X/MVI:X/MVA:L/MSC:N/MSI:X/MSA:S", // val
        202001, // exp mv
        Score(59), // exp score
      ), (
        "test 3.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:L/SC:N/SI:L/SA:L/E:P/CR:H/IR:M/AR:X/MAV:L/MAC:X/MAT:P/MPR:L/MUI:P/MVC:N/MVI:H/MVA:X/MSC:X/MSI:L/MSA:S", // val
        211011, // exp mv
        Score(38), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:H/VI:L/VA:H/SC:N/SI:L/SA:H/E:P/CR:X/IR:M/AR:X/MAV:X/MAC:X/MAT:P/MPR:X/MUI:X/MVC:H/MVI:N/MVA:X/MSC:N/MSI:H/MSA:L", // val
        211110, // exp mv
        Score(39), // exp score
      ), (
        "test 4.2", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:H/VA:N/SC:H/SI:L/SA:H/E:X/CR:M/IR:X/AR:H/MAV:X/MAC:X/MAT:N/MPR:L/MUI:A/MVC:N/MVI:L/MVA:N/MSC:N/MSI:X/MSA:H", // val
        202101, // exp mv
        Score(42), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:N/VI:L/VA:N/SC:H/SI:L/SA:H/E:A/CR:M/IR:H/AR:X/MAV:P/MAC:X/MAT:N/MPR:H/MUI:N/MVC:X/MVI:L/MVA:H/MSC:X/MSI:N/MSA:H", // val
        201100, // exp mv
        Score(69), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:H/SA:L/E:U/CR:H/IR:L/AR:X/MAV:L/MAC:H/MAT:N/MPR:L/MUI:A/MVC:N/MVI:N/MVA:X/MSC:N/MSI:X/MSA:S", // val
        212021, // exp mv
        Score(10), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:H/E:P/CR:L/IR:L/AR:X/MAV:A/MAC:H/MAT:N/MPR:H/MUI:A/MVC:L/MVI:H/MVA:H/MSC:L/MSI:N/MSA:N", // val
        211210, // exp mv
        Score(15), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H/E:U/CR:M/IR:X/AR:H/MAV:A/MAC:X/MAT:X/MPR:L/MUI:X/MVC:H/MVI:N/MVA:X/MSC:L/MSI:H/MSA:S", // val
        101020, // exp mv
        Score(73), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:L/SC:L/SI:L/SA:N/E:A/CR:H/IR:L/AR:H/MAV:X/MAC:X/MAT:P/MPR:H/MUI:A/MVC:H/MVI:L/MVA:H/MSC:L/MSI:L/MSA:H", // val
        211100, // exp mv
        Score(58), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:H/SI:N/SA:N/E:U/CR:M/IR:M/AR:L/MAV:A/MAC:L/MAT:P/MPR:L/MUI:N/MVC:H/MVI:X/MVA:H/MSC:X/MSI:S/MSA:H", // val
        110021, // exp mv
        Score(67), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:H/SA:L/E:P/CR:M/IR:H/AR:L/MAV:X/MAC:H/MAT:N/MPR:H/MUI:N/MVC:N/MVI:X/MVA:N/MSC:X/MSI:N/MSA:S", // val
        112011, // exp mv
        Score(41), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:L/SA:H/E:P/CR:L/IR:H/AR:M/MAV:N/MAC:X/MAT:P/MPR:L/MUI:N/MVC:X/MVI:N/MVA:H/MSC:H/MSI:H/MSA:H", // val
        111111, // exp mv
        Score(53), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:H/E:U/CR:M/IR:H/AR:L/MAV:X/MAC:X/MAT:N/MPR:X/MUI:X/MVC:N/MVI:N/MVA:X/MSC:N/MSI:S/MSA:S", // val
        202021, // exp mv
        Score(19), // exp score
      ), (
        "test 8.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:H/SC:N/SI:N/SA:L/E:P/CR:M/IR:X/AR:X/MAV:N/MAC:H/MAT:N/MPR:X/MUI:N/MVC:H/MVI:H/MVA:X/MSC:L/MSI:S/MSA:L", // val
        110010, // exp mv
        Score(86), // exp score
      ), (
        "test 0.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:L/VI:H/VA:N/SC:N/SI:N/SA:H/E:U/CR:H/IR:M/AR:L/MAV:P/MAC:X/MAT:P/MPR:X/MUI:X/MVC:L/MVI:N/MVA:N/MSC:H/MSI:X/MSA:L", // val
        212121, // exp mv
        Score(3), // exp score
      ), (
        "test 0.1", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:N/SI:L/SA:L/E:U/CR:M/IR:M/AR:M/MAV:X/MAC:H/MAT:X/MPR:L/MUI:A/MVC:L/MVI:X/MVA:X/MSC:N/MSI:N/MSA:X", // val
        212221, // exp mv
        Score(1), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:L/SC:N/SI:H/SA:H/E:X/CR:L/IR:L/AR:H/MAV:L/MAC:X/MAT:P/MPR:N/MUI:P/MVC:X/MVI:L/MVA:H/MSC:H/MSI:S/MSA:X", // val
        111000, // exp mv
        Score(85), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:L/SC:H/SI:H/SA:L/E:X/CR:X/IR:M/AR:H/MAV:L/MAC:H/MAT:X/MPR:L/MUI:X/MVC:X/MVI:N/MVA:N/MSC:X/MSI:L/MSA:H", // val
        211100, // exp mv
        Score(58), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:H/SC:L/SI:H/SA:L/E:P/CR:L/IR:M/AR:M/MAV:X/MAC:L/MAT:X/MPR:N/MUI:P/MVC:L/MVI:X/MVA:X/MSC:N/MSI:H/MSA:H", // val
        101111, // exp mv
        Score(56), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:L/SC:H/SI:H/SA:N/E:P/CR:H/IR:M/AR:X/MAV:N/MAC:X/MAT:X/MPR:L/MUI:P/MVC:X/MVI:X/MVA:L/MSC:N/MSI:S/MSA:X", // val
        101011, // exp mv
        Score(73), // exp score
      ), (
        "test 7.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:L/SA:N/E:X/CR:L/IR:H/AR:H/MAV:A/MAC:X/MAT:N/MPR:N/MUI:A/MVC:X/MVI:L/MVA:N/MSC:N/MSI:S/MSA:H", // val
        102001, // exp mv
        Score(78), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:A/CR:M/IR:L/AR:M/MAV:P/MAC:L/MAT:N/MPR:L/MUI:X/MVC:N/MVI:H/MVA:H/MSC:H/MSI:L/MSA:H", // val
        201101, // exp mv
        Score(55), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:H/SA:L/E:P/CR:M/IR:X/AR:X/MAV:A/MAC:X/MAT:X/MPR:X/MUI:A/MVC:N/MVI:N/MVA:L/MSC:L/MSI:L/MSA:N", // val
        102211, // exp mv
        Score(19), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:L/SA:L/E:P/CR:X/IR:H/AR:X/MAV:X/MAC:X/MAT:P/MPR:X/MUI:P/MVC:H/MVI:N/MVA:L/MSC:L/MSI:H/MSA:X", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:L/SA:N/E:P/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:X/MPR:X/MUI:A/MVC:X/MVI:N/MVA:X/MSC:H/MSI:L/MSA:H", // val
        102111, // exp mv
        Score(54), // exp score
      ), (
        "test 4.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:M/IR:M/AR:M/MAV:P/MAC:L/MAT:N/MPR:L/MUI:P/MVC:H/MVI:L/MVA:N/MSC:H/MSI:S/MSA:S", // val
        201021, // exp mv
        Score(47), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:H/SI:N/SA:N/E:P/CR:H/IR:M/AR:L/MAV:L/MAC:X/MAT:N/MPR:H/MUI:X/MVC:N/MVI:N/MVA:N/MSC:L/MSI:N/MSA:X", // val
        102211, // exp mv
        Score(18), // exp score
      ), (
        "test 6.2", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:L/SI:L/SA:N/E:X/CR:X/IR:L/AR:H/MAV:L/MAC:X/MAT:X/MPR:L/MUI:X/MVC:L/MVI:L/MVA:L/MSC:H/MSI:H/MSA:X", // val
        102101, // exp mv
        Score(62), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:H/SI:N/SA:N/E:X/CR:X/IR:M/AR:L/MAV:N/MAC:H/MAT:X/MPR:N/MUI:P/MVC:H/MVI:L/MVA:X/MSC:H/MSI:N/MSA:H", // val
        111100, // exp mv
        Score(71), // exp score
      ), (
        "test 5.2", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:H/SA:N/E:P/CR:L/IR:L/AR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:A/MVC:L/MVI:L/MVA:L/MSC:H/MSI:H/MSA:N", // val
        102111, // exp mv
        Score(52), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:L/SI:L/SA:L/E:A/CR:X/IR:M/AR:X/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:L/MVI:X/MVA:N/MSC:L/MSI:H/MSA:X", // val
        212101, // exp mv
        Score(21), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MAV:X/MAC:L/MAT:P/MPR:H/MUI:X/MVC:H/MVI:X/MVA:H/MSC:N/MSI:H/MSA:S", // val
        210010, // exp mv
        Score(71), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:L/SC:L/SI:H/SA:H/E:A/CR:H/IR:H/AR:L/MAV:X/MAC:H/MAT:X/MPR:N/MUI:X/MVC:L/MVI:N/MVA:H/MSC:H/MSI:H/MSA:H", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 9.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:H/SI:L/SA:L/E:X/CR:X/IR:L/AR:L/MAV:N/MAC:X/MAT:X/MPR:X/MUI:P/MVC:H/MVI:H/MVA:H/MSC:H/MSI:X/MSA:S", // val
        100000, // exp mv
        Score(97), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:L/SI:H/SA:L/E:X/CR:X/IR:L/AR:M/MAV:X/MAC:X/MAT:N/MPR:X/MUI:N/MVC:H/MVI:X/MVA:N/MSC:X/MSI:N/MSA:L", // val
        101200, // exp mv
        Score(68), // exp score
      ), (
        "test 9.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:H/SC:H/SI:L/SA:N/E:A/CR:H/IR:X/AR:X/MAV:N/MAC:L/MAT:X/MPR:X/MUI:N/MVC:L/MVI:N/MVA:H/MSC:L/MSI:L/MSA:S", // val
        001000, // exp mv
        Score(97), // exp score
      ), (
        "test 7.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:L/SC:H/SI:N/SA:N/E:X/CR:L/IR:L/AR:L/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:N/MVI:X/MVA:X/MSC:N/MSI:X/MSA:S", // val
        102001, // exp mv
        Score(77), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:A/VC:L/VI:H/VA:H/SC:H/SI:L/SA:N/E:A/CR:M/IR:M/AR:L/MAV:A/MAC:L/MAT:P/MPR:H/MUI:A/MVC:X/MVI:L/MVA:H/MSC:H/MSI:S/MSA:N", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 2.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:H/SI:L/SA:N/E:U/CR:M/IR:X/AR:L/MAV:X/MAC:H/MAT:N/MPR:H/MUI:A/MVC:L/MVI:H/MVA:N/MSC:N/MSI:S/MSA:H", // val
        211020, // exp mv
        Score(29), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:A/VC:L/VI:N/VA:H/SC:H/SI:H/SA:H/E:X/CR:L/IR:H/AR:H/MAV:L/MAC:X/MAT:N/MPR:L/MUI:N/MVC:H/MVI:N/MVA:X/MSC:H/MSI:N/MSA:X", // val
        101100, // exp mv
        Score(83), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:A/VC:L/VI:N/VA:H/SC:L/SI:H/SA:H/E:X/CR:X/IR:M/AR:L/MAV:P/MAC:H/MAT:X/MPR:N/MUI:A/MVC:H/MVI:N/MVA:L/MSC:N/MSI:H/MSA:L", // val
        211100, // exp mv
        Score(56), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:A/VC:L/VI:N/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:L/AR:X/MAV:A/MAC:L/MAT:P/MPR:H/MUI:A/MVC:H/MVI:X/MVA:H/MSC:X/MSI:H/MSA:N", // val
        211100, // exp mv
        Score(57), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:N/SC:L/SI:H/SA:L/E:P/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:H/MUI:A/MVC:L/MVI:L/MVA:X/MSC:N/MSI:X/MSA:X", // val
        102111, // exp mv
        Score(46), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:M/AR:M/MAV:X/MAC:H/MAT:N/MPR:H/MUI:X/MVC:X/MVI:X/MVA:H/MSC:H/MSI:H/MSA:X", // val
        111100, // exp mv
        Score(69), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:L/E:X/CR:L/IR:H/AR:X/MAV:P/MAC:X/MAT:P/MPR:H/MUI:P/MVC:N/MVI:X/MVA:X/MSC:X/MSI:L/MSA:S", // val
        212001, // exp mv
        Score(48), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:L/E:X/CR:L/IR:L/AR:M/MAV:L/MAC:X/MAT:P/MPR:L/MUI:X/MVC:X/MVI:X/MVA:X/MSC:L/MSI:X/MSA:X", // val
        112101, // exp mv
        Score(48), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:N/VI:L/VA:N/SC:L/SI:N/SA:N/E:P/CR:M/IR:H/AR:X/MAV:A/MAC:L/MAT:N/MPR:H/MUI:A/MVC:X/MVI:L/MVA:N/MSC:N/MSI:S/MSA:L", // val
        202011, // exp mv
        Score(44), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:N/VI:N/VA:L/SC:L/SI:N/SA:N/E:X/CR:H/IR:M/AR:X/MAV:A/MAC:H/MAT:P/MPR:N/MUI:P/MVC:N/MVI:L/MVA:H/MSC:X/MSI:H/MSA:H", // val
        111100, // exp mv
        Score(71), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:N/VI:N/VA:L/SC:N/SI:L/SA:L/E:X/CR:M/IR:X/AR:L/MAV:L/MAC:L/MAT:N/MPR:X/MUI:X/MVC:H/MVI:N/MVA:L/MSC:X/MSI:S/MSA:H", // val
        101001, // exp mv
        Score(85), // exp score
      ), (
        "test 3", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H/E:U/CR:M/IR:H/AR:H/MAV:P/MAC:X/MAT:X/MPR:H/MUI:P/MVC:L/MVI:X/MVA:H/MSC:N/MSI:S/MSA:L", // val
        211020, // exp mv
        Score(30), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:P/VC:H/VI:H/VA:L/SC:L/SI:N/SA:H/E:U/CR:X/IR:H/AR:L/MAV:A/MAC:X/MAT:N/MPR:H/MUI:N/MVC:H/MVI:N/MVA:H/MSC:H/MSI:H/MSA:X", // val
        101120, // exp mv
        Score(57), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:P/VC:H/VI:L/VA:L/SC:L/SI:H/SA:H/E:X/CR:M/IR:X/AR:L/MAV:X/MAC:H/MAT:X/MPR:X/MUI:X/MVC:H/MVI:X/MVA:H/MSC:L/MSI:N/MSA:L", // val
        211201, // exp mv
        Score(18), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:P/VC:H/VI:L/VA:L/SC:L/SI:L/SA:L/E:X/CR:H/IR:H/AR:M/MAV:A/MAC:L/MAT:X/MPR:L/MUI:P/MVC:L/MVI:H/MVA:X/MSC:N/MSI:H/MSA:L", // val
        211100, // exp mv
        Score(57), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:P/VC:L/VI:H/VA:H/SC:N/SI:H/SA:L/E:U/CR:H/IR:H/AR:X/MAV:L/MAC:H/MAT:P/MPR:H/MUI:A/MVC:L/MVI:X/MVA:H/MSC:X/MSI:H/MSA:X", // val
        211120, // exp mv
        Score(16), // exp score
      ), (
        "test 5.2", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:P/VC:L/VI:N/VA:N/SC:N/SI:H/SA:H/E:P/CR:X/IR:M/AR:L/MAV:P/MAC:L/MAT:N/MPR:N/MUI:P/MVC:H/MVI:X/MVA:L/MSC:L/MSI:X/MSA:H", // val
        201110, // exp mv
        Score(52), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:P/VC:N/VI:L/VA:L/SC:H/SI:H/SA:L/E:P/CR:X/IR:M/AR:H/MAV:A/MAC:X/MAT:P/MPR:H/MUI:P/MVC:H/MVI:H/MVA:X/MSC:X/MSI:L/MSA:H", // val
        210110, // exp mv
        Score(57), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:H/E:U/CR:H/IR:X/AR:M/MAV:N/MAC:H/MAT:P/MPR:L/MUI:X/MVC:L/MVI:X/MVA:X/MSC:N/MSI:L/MSA:H", // val
        112121, // exp mv
        Score(10), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:N/VI:N/VA:H/SC:H/SI:L/SA:L/E:P/CR:M/IR:H/AR:H/MAV:P/MAC:X/MAT:P/MPR:N/MUI:A/MVC:H/MVI:H/MVA:N/MSC:L/MSI:N/MSA:L", // val
        210210, // exp mv
        Score(40), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/E:P/CR:M/IR:X/AR:L/MAV:A/MAC:L/MAT:P/MPR:N/MUI:A/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:N", // val
        111211, // exp mv
        Score(24), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:N/E:U/CR:L/IR:H/AR:M/MAV:X/MAC:H/MAT:P/MPR:H/MUI:N/MVC:H/MVI:H/MVA:L/MSC:L/MSI:L/MSA:H", // val
        110120, // exp mv
        Score(53), // exp score
      ), (
        "test 8.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:H/VA:N/SC:H/SI:N/SA:H/E:U/CR:L/IR:X/AR:M/MAV:N/MAC:X/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:X/MSI:N/MSA:H", // val
        000120, // exp mv
        Score(89), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:H/SA:H/E:P/CR:H/IR:H/AR:M/MAV:N/MAC:H/MAT:P/MPR:L/MUI:X/MVC:N/MVI:X/MVA:L/MSC:N/MSI:H/MSA:X", // val
        112111, // exp mv
        Score(24), // exp score
      ), (
        "test 0", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:X/CR:H/IR:M/AR:M/MAV:A/MAC:H/MAT:X/MPR:L/MUI:X/MVC:X/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N", // val
        112201, // exp mv
        Score(0), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:N/E:U/CR:L/IR:M/AR:L/MAV:P/MAC:H/MAT:P/MPR:X/MUI:N/MVC:X/MVI:H/MVA:L/MSC:H/MSI:N/MSA:L", // val
        210121, // exp mv
        Score(15), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H/E:A/CR:H/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:H/MUI:X/MVC:X/MVI:H/MVA:X/MSC:N/MSI:S/MSA:S", // val
        210000, // exp mv
        Score(85), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:H/SI:N/SA:N/E:P/CR:L/IR:X/AR:X/MAV:L/MAC:X/MAT:P/MPR:H/MUI:X/MVC:N/MVI:H/MVA:X/MSC:H/MSI:S/MSA:X", // val
        211010, // exp mv
        Score(54), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:L/VI:N/VA:L/SC:H/SI:H/SA:L/E:A/CR:L/IR:M/AR:M/MAV:L/MAC:L/MAT:P/MPR:N/MUI:A/MVC:X/MVI:X/MVA:N/MSC:L/MSI:L/MSA:N", // val
        112201, // exp mv
        Score(18), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:H/MAV:A/MAC:H/MAT:N/MPR:N/MUI:N/MVC:X/MVI:H/MVA:N/MSC:N/MSI:X/MSA:H", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:L/SI:L/SA:N/E:U/CR:L/IR:L/AR:M/MAV:N/MAC:X/MAT:N/MPR:L/MUI:P/MVC:X/MVI:N/MVA:H/MSC:L/MSI:N/MSA:X", // val
        101221, // exp mv
        Score(21), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:H/SC:H/SI:L/SA:L/E:P/CR:M/IR:X/AR:H/MAV:L/MAC:H/MAT:P/MPR:L/MUI:P/MVC:H/MVI:X/MVA:L/MSC:X/MSI:H/MSA:N", // val
        211111, // exp mv
        Score(17), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:H/SC:L/SI:H/SA:L/E:A/CR:H/IR:X/AR:L/MAV:L/MAC:H/MAT:P/MPR:X/MUI:X/MVC:L/MVI:L/MVA:L/MSC:N/MSI:S/MSA:H", // val
        212001, // exp mv
        Score(46), // exp score
      ), (
        "test 2.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:L/SC:N/SI:H/SA:L/E:U/CR:M/IR:L/AR:H/MAV:L/MAC:X/MAT:X/MPR:X/MUI:A/MVC:N/MVI:L/MVA:H/MSC:H/MSI:N/MSA:S", // val
        211020, // exp mv
        Score(29), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:N/VI:N/VA:H/SC:L/SI:H/SA:N/E:U/CR:H/IR:M/AR:L/MAV:L/MAC:X/MAT:P/MPR:X/MUI:N/MVC:L/MVI:H/MVA:X/MSC:L/MSI:X/MSA:H", // val
        111121, // exp mv
        Score(20), // exp score
      ), (
        "test 0.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:L/SA:L/E:P/CR:M/IR:M/AR:H/MAV:P/MAC:H/MAT:P/MPR:N/MUI:X/MVC:N/MVI:L/MVA:X/MSC:L/MSI:X/MSA:X", // val
        212211, // exp mv
        Score(3), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:L/VI:H/VA:H/SC:L/SI:L/SA:N/E:A/CR:X/IR:M/AR:X/MAV:P/MAC:H/MAT:N/MPR:X/MUI:X/MVC:N/MVI:H/MVA:L/MSC:L/MSI:L/MSA:L", // val
        211201, // exp mv
        Score(18), // exp score
      ), (
        "test 8.7", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:L/SC:L/SI:N/SA:L/E:P/CR:M/IR:H/AR:M/MAV:N/MAC:X/MAT:N/MPR:N/MUI:N/MVC:N/MVI:H/MVA:X/MSC:L/MSI:N/MSA:H", // val
        001110, // exp mv
        Score(87), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:H/SA:L/E:P/CR:L/IR:M/AR:H/MAV:N/MAC:X/MAT:X/MPR:L/MUI:A/MVC:H/MVI:H/MVA:N/MSC:X/MSI:H/MSA:H", // val
        110111, // exp mv
        Score(59), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:H/SA:H/E:P/CR:H/IR:X/AR:H/MAV:A/MAC:H/MAT:P/MPR:N/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:S/MSA:L", // val
        112011, // exp mv
        Score(46), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:N/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:L/IR:H/AR:M/MAV:N/MAC:H/MAT:P/MPR:L/MUI:X/MVC:N/MVI:X/MVA:H/MSC:X/MSI:H/MSA:S", // val
        111000, // exp mv
        Score(85), // exp score
      ), (
        "test 9.4", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:L/SA:H/E:X/CR:X/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:L/MUI:N/MVC:H/MVI:N/MVA:H/MSC:H/MSI:S/MSA:H", // val
        101000, // exp mv
        Score(94), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:X/IR:L/AR:X/MAV:X/MAC:X/MAT:X/MPR:L/MUI:P/MVC:L/MVI:X/MVA:L/MSC:H/MSI:H/MSA:N", // val
        211111, // exp mv
        Score(16), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:H/SA:H/E:U/CR:H/IR:L/AR:X/MAV:X/MAC:H/MAT:N/MPR:L/MUI:N/MVC:N/MVI:X/MVA:L/MSC:N/MSI:H/MSA:H", // val
        112121, // exp mv
        Score(11), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:H/SC:H/SI:H/SA:L/E:U/CR:L/IR:H/AR:H/MAV:X/MAC:H/MAT:X/MPR:H/MUI:P/MVC:L/MVI:L/MVA:N/MSC:X/MSI:S/MSA:X", // val
        212021, // exp mv
        Score(11), // exp score
      ), (
        "test 0.3", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:H/SC:H/SI:N/SA:N/E:U/CR:X/IR:H/AR:H/MAV:X/MAC:H/MAT:X/MPR:L/MUI:X/MVC:L/MVI:X/MVA:L/MSC:H/MSI:N/MSA:L", // val
        212121, // exp mv
        Score(3), // exp score
      ), (
        "test 5", // name
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:L/SA:L/E:P/CR:L/IR:X/AR:M/MAV:N/MAC:L/MAT:P/MPR:N/MUI:P/MVC:N/MVI:L/MVA:X/MSC:N/MSI:N/MSA:S", // val
        112011, // exp mv
        Score(50), // exp score
      ), (
        "test 9.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:A/VC:H/VI:N/VA:N/SC:L/SI:L/SA:L/E:X/CR:H/IR:H/AR:M/MAV:A/MAC:L/MAT:N/MPR:N/MUI:X/MVC:X/MVI:H/MVA:H/MSC:X/MSI:S/MSA:S", // val
        100000, // exp mv
        Score(97), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:A/VC:L/VI:N/VA:H/SC:N/SI:N/SA:H/E:X/CR:H/IR:H/AR:M/MAV:N/MAC:H/MAT:P/MPR:X/MUI:N/MVC:X/MVI:L/MVA:X/MSC:H/MSI:N/MSA:H", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:A/VC:L/VI:N/VA:N/SC:H/SI:H/SA:H/E:A/CR:H/IR:M/AR:L/MAV:A/MAC:L/MAT:N/MPR:L/MUI:X/MVC:L/MVI:L/MVA:X/MSC:X/MSI:N/MSA:N", // val
        202101, // exp mv
        Score(41), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:H/E:X/CR:H/IR:X/AR:M/MAV:X/MAC:H/MAT:X/MPR:H/MUI:N/MVC:X/MVI:X/MVA:N/MSC:H/MSI:N/MSA:N", // val
        112101, // exp mv
        Score(46), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:A/VC:N/VI:L/VA:N/SC:N/SI:H/SA:L/E:U/CR:H/IR:H/AR:M/MAV:P/MAC:L/MAT:X/MPR:N/MUI:P/MVC:X/MVI:X/MVA:L/MSC:L/MSI:H/MSA:X", // val
        202121, // exp mv
        Score(10), // exp score
      ), (
        "test 6.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:N/SC:H/SI:N/SA:L/E:P/CR:M/IR:L/AR:M/MAV:L/MAC:H/MAT:P/MPR:N/MUI:A/MVC:N/MVI:L/MVA:H/MSC:X/MSI:S/MSA:L", // val
        111011, // exp mv
        Score(61), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:H/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:M/AR:L/MAV:L/MAC:H/MAT:P/MPR:H/MUI:N/MVC:L/MVI:N/MVA:X/MSC:X/MSI:N/MSA:N", // val
        112101, // exp mv
        Score(40), // exp score
      ), (
        "test 9", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:A/CR:H/IR:X/AR:H/MAV:X/MAC:X/MAT:N/MPR:N/MUI:X/MVC:X/MVI:L/MVA:L/MSC:H/MSI:L/MSA:X", // val
        011100, // exp mv
        Score(90), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:H/VI:L/VA:L/SC:L/SI:N/SA:H/E:X/CR:L/IR:H/AR:M/MAV:L/MAC:X/MAT:N/MPR:X/MUI:X/MVC:X/MVI:L/MVA:L/MSC:N/MSI:N/MSA:S", // val
        111001, // exp mv
        Score(69), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:L/VI:H/VA:H/SC:H/SI:N/SA:H/E:X/CR:M/IR:M/AR:H/MAV:P/MAC:L/MAT:P/MPR:H/MUI:N/MVC:X/MVI:X/MVA:N/MSC:X/MSI:X/MSA:X", // val
        211101, // exp mv
        Score(44), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:L/SC:N/SI:H/SA:L/E:A/CR:X/IR:L/AR:L/MAV:P/MAC:L/MAT:P/MPR:X/MUI:N/MVC:N/MVI:X/MVA:X/MSC:L/MSI:L/MSA:S", // val
        212001, // exp mv
        Score(46), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:H/E:U/CR:M/IR:M/AR:L/MAV:A/MAC:L/MAT:N/MPR:N/MUI:X/MVC:L/MVI:X/MVA:H/MSC:N/MSI:X/MSA:N", // val
        101221, // exp mv
        Score(23), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:H/VI:H/VA:N/SC:L/SI:N/SA:N/E:P/CR:H/IR:M/AR:H/MAV:X/MAC:H/MAT:P/MPR:H/MUI:A/MVC:X/MVI:H/MVA:N/MSC:H/MSI:S/MSA:H", // val
        110010, // exp mv
        Score(83), // exp score
      ), (
        "test 8.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:H/VI:L/VA:N/SC:L/SI:L/SA:N/E:A/CR:H/IR:H/AR:H/MAV:A/MAC:X/MAT:P/MPR:X/MUI:N/MVC:X/MVI:L/MVA:H/MSC:X/MSI:S/MSA:H", // val
        111000, // exp mv
        Score(86), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:H/VI:N/VA:N/SC:N/SI:H/SA:L/E:A/CR:H/IR:M/AR:L/MAV:L/MAC:X/MAT:X/MPR:H/MUI:X/MVC:L/MVI:X/MVA:X/MSC:L/MSI:N/MSA:S", // val
        212001, // exp mv
        Score(43), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:X/IR:L/AR:M/MAV:A/MAC:L/MAT:P/MPR:H/MUI:N/MVC:N/MVI:N/MVA:L/MSC:L/MSI:N/MSA:L", // val
        112211, // exp mv
        Score(11), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:L/E:P/CR:H/IR:X/AR:L/MAV:L/MAC:H/MAT:P/MPR:H/MUI:N/MVC:X/MVI:N/MVA:X/MSC:X/MSI:L/MSA:X", // val
        112211, // exp mv
        Score(9), // exp score
      ), (
        "test 0.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:N/VI:L/VA:L/SC:H/SI:L/SA:L/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:X/MAT:X/MPR:L/MUI:N/MVC:N/MVI:L/MVA:N/MSC:L/MSI:H/MSA:L", // val
        212121, // exp mv
        Score(3), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:N/SC:N/SI:H/SA:H/E:A/CR:M/IR:L/AR:H/MAV:X/MAC:H/MAT:N/MPR:L/MUI:P/MVC:H/MVI:L/MVA:X/MSC:X/MSI:N/MSA:L", // val
        111201, // exp mv
        Score(46), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:H/VI:N/VA:H/SC:N/SI:N/SA:L/E:X/CR:M/IR:H/AR:L/MAV:P/MAC:L/MAT:N/MPR:X/MUI:N/MVC:X/MVI:L/MVA:X/MSC:L/MSI:X/MSA:S", // val
        201001, // exp mv
        Score(72), // exp score
      ), (
        "test 8.2", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:L/VI:H/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:M/AR:H/MAV:X/MAC:L/MAT:N/MPR:L/MUI:X/MVC:H/MVI:X/MVA:X/MSC:H/MSI:N/MSA:N", // val
        100110, // exp mv
        Score(82), // exp score
      ), (
        "test 8.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:L/VI:H/VA:N/SC:H/SI:N/SA:L/E:U/CR:H/IR:X/AR:H/MAV:A/MAC:L/MAT:X/MPR:N/MUI:P/MVC:H/MVI:H/MVA:N/MSC:H/MSI:S/MSA:S", // val
        100020, // exp mv
        Score(89), // exp score
      ), (
        "test 9.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:L/VI:H/VA:N/SC:N/SI:L/SA:N/E:X/CR:H/IR:X/AR:X/MAV:N/MAC:L/MAT:N/MPR:H/MUI:A/MVC:H/MVI:L/MVA:X/MSC:X/MSI:L/MSA:S", // val
        101000, // exp mv
        Score(91), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:L/VI:L/VA:L/SC:L/SI:H/SA:L/E:A/CR:L/IR:M/AR:H/MAV:N/MAC:H/MAT:P/MPR:X/MUI:N/MVC:L/MVI:N/MVA:H/MSC:H/MSI:H/MSA:N", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H/E:U/CR:H/IR:M/AR:H/MAV:L/MAC:X/MAT:N/MPR:X/MUI:X/MVC:N/MVI:N/MVA:L/MSC:X/MSI:L/MSA:S", // val
        212021, // exp mv
        Score(11), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:N/VI:N/VA:N/SC:H/SI:N/SA:H/E:A/CR:X/IR:M/AR:M/MAV:N/MAC:X/MAT:N/MPR:N/MUI:A/MVC:N/MVI:L/MVA:L/MSC:L/MSI:H/MSA:H", // val
        112101, // exp mv
        Score(53), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:L/SI:H/SA:N/E:X/CR:L/IR:H/AR:H/MAV:L/MAC:H/MAT:P/MPR:X/MUI:P/MVC:H/MVI:N/MVA:N/MSC:N/MSI:S/MSA:H", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:N/SA:L/E:U/CR:H/IR:X/AR:L/MAV:P/MAC:X/MAT:P/MPR:N/MUI:A/MVC:L/MVI:H/MVA:H/MSC:X/MSI:H/MSA:H", // val
        211120, // exp mv
        Score(17), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:L/SI:N/SA:H/E:X/CR:H/IR:H/AR:L/MAV:X/MAC:H/MAT:N/MPR:X/MUI:N/MVC:L/MVI:L/MVA:N/MSC:X/MSI:H/MSA:H", // val
        112101, // exp mv
        Score(56), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:H/VI:L/VA:N/SC:L/SI:N/SA:L/E:U/CR:M/IR:L/AR:M/MAV:N/MAC:H/MAT:P/MPR:N/MUI:X/MVC:H/MVI:L/MVA:N/MSC:X/MSI:N/MSA:H", // val
        111121, // exp mv
        Score(20), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:H/SI:L/SA:N/E:A/CR:M/IR:L/AR:M/MAV:N/MAC:H/MAT:P/MPR:X/MUI:N/MVC:N/MVI:N/MVA:L/MSC:H/MSI:L/MSA:N", // val
        112101, // exp mv
        Score(51), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:L/SI:H/SA:N/E:A/CR:L/IR:M/AR:M/MAV:N/MAC:L/MAT:X/MPR:H/MUI:N/MVC:N/MVI:H/MVA:X/MSC:L/MSI:N/MSA:N", // val
        101201, // exp mv
        Score(55), // exp score
      ), (
        "test 5", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:N/SC:N/SI:H/SA:L/E:P/CR:L/IR:X/AR:H/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:N/MVA:N/MSC:X/MSI:X/MSA:L", // val
        111111, // exp mv
        Score(50), // exp score
      ), (
        "test 6.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:H/SA:L/E:X/CR:X/IR:H/AR:H/MAV:L/MAC:L/MAT:N/MPR:H/MUI:N/MVC:L/MVI:N/MVA:N/MSC:H/MSI:H/MSA:X", // val
        102101, // exp mv
        Score(61), // exp score
      ), (
        "test 3.5", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:L/VI:N/VA:L/SC:L/SI:H/SA:L/E:U/CR:X/IR:H/AR:M/MAV:X/MAC:X/MAT:N/MPR:L/MUI:A/MVC:H/MVI:N/MVA:X/MSC:N/MSI:X/MSA:L", // val
        111120, // exp mv
        Score(35), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:L/VI:N/VA:N/SC:N/SI:L/SA:L/E:P/CR:M/IR:M/AR:H/MAV:L/MAC:H/MAT:N/MPR:H/MUI:X/MVC:X/MVI:N/MVA:L/MSC:X/MSI:S/MSA:S", // val
        212011, // exp mv
        Score(22), // exp score
      ), (
        "test 0.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:N/VI:H/VA:L/SC:H/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:L/MAC:H/MAT:N/MPR:L/MUI:P/MVC:L/MVI:N/MVA:N/MSC:X/MSI:X/MSA:H", // val
        212121, // exp mv
        Score(3), // exp score
      ), (
        "test 3.5", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:H/SI:N/SA:N/E:P/CR:L/IR:H/AR:L/MAV:P/MAC:H/MAT:X/MPR:H/MUI:P/MVC:N/MVI:X/MVA:N/MSC:L/MSI:H/MSA:L", // val
        211110, // exp mv
        Score(35), // exp score
      ), (
        "test 7.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:L/E:A/CR:M/IR:X/AR:H/MAV:X/MAC:L/MAT:X/MPR:L/MUI:X/MVC:N/MVI:L/MVA:L/MSC:N/MSI:S/MSA:N", // val
        102001, // exp mv
        Score(77), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:L/E:A/CR:H/IR:M/AR:M/MAV:X/MAC:L/MAT:X/MPR:X/MUI:P/MVC:X/MVI:L/MVA:H/MSC:N/MSI:L/MSA:N", // val
        101201, // exp mv
        Score(57), // exp score
      ), (
        "test 0.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:H/SC:H/SI:N/SA:L/E:P/CR:L/IR:H/AR:L/MAV:P/MAC:X/MAT:N/MPR:N/MUI:X/MVC:X/MVI:X/MVA:L/MSC:N/MSI:N/MSA:X", // val
        212211, // exp mv
        Score(3), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:H/E:P/CR:M/IR:L/AR:M/MAV:N/MAC:L/MAT:P/MPR:H/MUI:N/MVC:L/MVI:L/MVA:X/MSC:L/MSI:H/MSA:N", // val
        112111, // exp mv
        Score(22), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:L/SI:L/SA:H/E:P/CR:M/IR:L/AR:M/MAV:P/MAC:L/MAT:X/MPR:X/MUI:X/MVC:L/MVI:H/MVA:L/MSC:X/MSI:H/MSA:L", // val
        201111, // exp mv
        Score(37), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:L/SI:L/SA:H/E:A/CR:L/IR:M/AR:M/MAV:N/MAC:H/MAT:N/MPR:X/MUI:A/MVC:X/MVI:N/MVA:H/MSC:H/MSI:H/MSA:X", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:L/SC:N/SI:L/SA:H/E:P/CR:M/IR:H/AR:L/MAV:P/MAC:X/MAT:X/MPR:N/MUI:A/MVC:X/MVI:L/MVA:H/MSC:N/MSI:S/MSA:H", // val
        211011, // exp mv
        Score(39), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:H/SI:H/SA:L/E:P/CR:L/IR:M/AR:X/MAV:N/MAC:L/MAT:N/MPR:N/MUI:P/MVC:H/MVI:L/MVA:N/MSC:X/MSI:N/MSA:L", // val
        101111, // exp mv
        Score(57), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:L/SI:L/SA:N/E:X/CR:X/IR:H/AR:M/MAV:P/MAC:X/MAT:X/MPR:L/MUI:P/MVC:L/MVI:X/MVA:X/MSC:N/MSI:X/MSA:N", // val
        211200, // exp mv
        Score(43), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H/E:A/CR:H/IR:X/AR:M/MAV:P/MAC:L/MAT:P/MPR:N/MUI:P/MVC:X/MVI:N/MVA:L/MSC:L/MSI:H/MSA:S", // val
        212001, // exp mv
        Score(48), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:H/SA:L/E:P/CR:X/IR:M/AR:H/MAV:A/MAC:H/MAT:X/MPR:H/MUI:X/MVC:N/MVI:L/MVA:X/MSC:L/MSI:X/MSA:L", // val
        211110, // exp mv
        Score(40), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:H/SI:N/SA:N/E:X/CR:L/IR:M/AR:X/MAV:P/MAC:L/MAT:N/MPR:L/MUI:X/MVC:N/MVI:N/MVA:N/MSC:H/MSI:L/MSA:H", // val
        202101, // exp mv
        Score(45), // exp score
      ), (
        "test 2.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:L/SC:L/SI:L/SA:H/E:U/CR:L/IR:X/AR:X/MAV:X/MAC:X/MAT:N/MPR:L/MUI:P/MVC:L/MVI:L/MVA:X/MSC:H/MSI:L/MSA:S", // val
        112021, // exp mv
        Score(26), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:N/VI:H/VA:L/SC:N/SI:L/SA:H/E:P/CR:H/IR:X/AR:H/MAV:L/MAC:H/MAT:X/MPR:N/MUI:X/MVC:N/MVI:X/MVA:H/MSC:X/MSI:S/MSA:L", // val
        111010, // exp mv
        Score(70), // exp score
      ), (
        "test 8.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:L/SI:L/SA:L/E:X/CR:M/IR:M/AR:M/MAV:N/MAC:X/MAT:P/MPR:H/MUI:X/MVC:H/MVI:H/MVA:L/MSC:X/MSI:S/MSA:H", // val
        110001, // exp mv
        Score(87), // exp score
      ), (
        "test 4.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:H/SA:L/E:P/CR:H/IR:L/AR:M/MAV:A/MAC:X/MAT:X/MPR:N/MUI:N/MVC:N/MVI:N/MVA:X/MSC:N/MSI:H/MSA:X", // val
        111111, // exp mv
        Score(49), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:L/SA:L/E:U/CR:M/IR:X/AR:X/MAV:P/MAC:L/MAT:P/MPR:X/MUI:P/MVC:H/MVI:H/MVA:X/MSC:N/MSI:X/MSA:N", // val
        210220, // exp mv
        Score(19), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:L/E:U/CR:M/IR:L/AR:H/MAV:X/MAC:X/MAT:P/MPR:X/MUI:N/MVC:X/MVI:L/MVA:H/MSC:L/MSI:X/MSA:N", // val
        111220, // exp mv
        Score(21), // exp score
      ), (
        "test 9.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:L/VA:N/SC:H/SI:H/SA:H/E:X/CR:L/IR:X/AR:M/MAV:A/MAC:L/MAT:P/MPR:N/MUI:N/MVC:X/MVI:H/MVA:X/MSC:N/MSI:X/MSA:S", // val
        110000, // exp mv
        Score(93), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:N/VI:H/VA:H/SC:L/SI:N/SA:L/E:P/CR:M/IR:X/AR:H/MAV:L/MAC:L/MAT:N/MPR:H/MUI:A/MVC:N/MVI:X/MVA:X/MSC:H/MSI:L/MSA:N", // val
        201110, // exp mv
        Score(51), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:N/VI:H/VA:L/SC:L/SI:L/SA:L/E:P/CR:L/IR:X/AR:L/MAV:A/MAC:L/MAT:P/MPR:X/MUI:A/MVC:N/MVI:L/MVA:N/MSC:X/MSI:S/MSA:S", // val
        212011, // exp mv
        Score(23), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:N/VI:L/VA:N/SC:H/SI:H/SA:H/E:P/CR:M/IR:X/AR:M/MAV:A/MAC:X/MAT:P/MPR:X/MUI:A/MVC:H/MVI:L/MVA:X/MSC:N/MSI:L/MSA:S", // val
        211011, // exp mv
        Score(37), // exp score
      ), (
        "test 6.4", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:N/VI:L/VA:N/SC:L/SI:N/SA:N/E:A/CR:X/IR:M/AR:X/MAV:X/MAC:X/MAT:X/MPR:L/MUI:A/MVC:N/MVI:N/MVA:L/MSC:N/MSI:S/MSA:X", // val
        112001, // exp mv
        Score(64), // exp score
      ), (
        "test 6.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:N/VC:H/VI:L/VA:N/SC:H/SI:H/SA:H/E:A/CR:X/IR:L/AR:X/MAV:P/MAC:L/MAT:N/MPR:N/MUI:A/MVC:N/MVI:N/MVA:L/MSC:X/MSI:S/MSA:H", // val
        202001, // exp mv
        Score(63), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:L/E:P/CR:X/IR:M/AR:M/MAV:L/MAC:X/MAT:P/MPR:L/MUI:P/MVC:N/MVI:N/MVA:X/MSC:L/MSI:L/MSA:H", // val
        212111, // exp mv
        Score(10), // exp score
      ), (
        "test 4.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:L/SC:L/SI:H/SA:L/E:A/CR:M/IR:M/AR:X/MAV:A/MAC:H/MAT:X/MPR:H/MUI:A/MVC:X/MVI:H/MVA:N/MSC:H/MSI:X/MSA:X", // val
        211101, // exp mv
        Score(47), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:N/VC:N/VI:N/VA:H/SC:L/SI:H/SA:L/E:X/CR:M/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:N/MUI:A/MVC:X/MVI:X/MVA:L/MSC:N/MSI:X/MSA:L", // val
        212101, // exp mv
        Score(20), // exp score
      ), (
        "test 5.2", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:P/VC:H/VI:N/VA:L/SC:H/SI:H/SA:L/E:P/CR:X/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:L/MUI:X/MVC:L/MVI:N/MVA:N/MSC:H/MSI:H/MSA:N", // val
        102111, // exp mv
        Score(52), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:P/VC:H/VI:N/VA:L/SC:H/SI:N/SA:H/E:P/CR:X/IR:H/AR:H/MAV:X/MAC:H/MAT:N/MPR:H/MUI:P/MVC:X/MVI:N/MVA:X/MSC:H/MSI:X/MSA:S", // val
        111010, // exp mv
        Score(71), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:P/VC:L/VI:N/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:L/AR:L/MAV:L/MAC:L/MAT:P/MPR:N/MUI:X/MVC:X/MVI:N/MVA:H/MSC:H/MSI:N/MSA:L", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:H/SC:H/SI:H/SA:N/E:P/CR:H/IR:M/AR:L/MAV:L/MAC:L/MAT:P/MPR:L/MUI:N/MVC:H/MVI:L/MVA:X/MSC:N/MSI:H/MSA:H", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 6", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:H/VI:N/VA:H/SC:H/SI:H/SA:H/E:X/CR:H/IR:M/AR:X/MAV:P/MAC:X/MAT:X/MPR:X/MUI:X/MVC:H/MVI:N/MVA:L/MSC:X/MSI:H/MSA:H", // val
        211100, // exp mv
        Score(60), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:L/VI:H/VA:H/SC:L/SI:N/SA:H/E:A/CR:L/IR:M/AR:M/MAV:P/MAC:X/MAT:P/MPR:N/MUI:X/MVC:X/MVI:L/MVA:H/MSC:X/MSI:S/MSA:X", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:N/VI:H/VA:L/SC:N/SI:H/SA:H/E:A/CR:H/IR:M/AR:L/MAV:N/MAC:L/MAT:P/MPR:H/MUI:N/MVC:H/MVI:X/MVA:X/MSC:L/MSI:L/MSA:N", // val
        110200, // exp mv
        Score(73), // exp score
      ), (
        "test 6.5", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:N/VI:L/VA:L/SC:L/SI:N/SA:H/E:A/CR:X/IR:L/AR:X/MAV:L/MAC:H/MAT:N/MPR:N/MUI:P/MVC:L/MVI:N/MVA:L/MSC:N/MSI:S/MSA:L", // val
        112001, // exp mv
        Score(65), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H/E:U/CR:H/IR:H/AR:L/MAV:A/MAC:X/MAT:X/MPR:L/MUI:X/MVC:N/MVI:H/MVA:L/MSC:L/MSI:H/MSA:X", // val
        111120, // exp mv
        Score(39), // exp score
      ), (
        "test 6.2", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:N/SA:L/E:U/CR:L/IR:M/AR:L/MAV:A/MAC:H/MAT:N/MPR:H/MUI:N/MVC:X/MVI:H/MVA:N/MSC:L/MSI:S/MSA:H", // val
        110021, // exp mv
        Score(62), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:L/SI:H/SA:N/E:P/CR:H/IR:X/AR:H/MAV:A/MAC:H/MAT:P/MPR:X/MUI:X/MVC:L/MVI:H/MVA:X/MSC:H/MSI:N/MSA:X", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:H/SC:N/SI:H/SA:N/E:A/CR:X/IR:H/AR:X/MAV:X/MAC:X/MAT:P/MPR:X/MUI:X/MVC:L/MVI:L/MVA:L/MSC:N/MSI:S/MSA:L", // val
        112001, // exp mv
        Score(68), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:L/SC:L/SI:L/SA:H/E:P/CR:X/IR:H/AR:L/MAV:L/MAC:X/MAT:N/MPR:X/MUI:P/MVC:N/MVI:L/MVA:L/MSC:L/MSI:X/MSA:H", // val
        212111, // exp mv
        Score(10), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:H/VA:N/SC:H/SI:N/SA:L/E:P/CR:H/IR:X/AR:M/MAV:L/MAC:L/MAT:N/MPR:X/MUI:X/MVC:L/MVI:X/MVA:H/MSC:N/MSI:N/MSA:H", // val
        101110, // exp mv
        Score(69), // exp score
      ), (
        "test 3.5", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:H/SI:L/SA:H/E:P/CR:M/IR:M/AR:M/MAV:P/MAC:L/MAT:N/MPR:L/MUI:A/MVC:H/MVI:L/MVA:N/MSC:N/MSI:N/MSA:H", // val
        201111, // exp mv
        Score(35), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:L/SA:H/E:X/CR:H/IR:X/AR:M/MAV:X/MAC:H/MAT:N/MPR:H/MUI:A/MVC:H/MVI:N/MVA:L/MSC:H/MSI:L/MSA:N", // val
        111100, // exp mv
        Score(68), // exp score
      ), (
        "test 8.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:H/VA:L/SC:L/SI:N/SA:H/E:P/CR:M/IR:X/AR:L/MAV:X/MAC:X/MAT:X/MPR:N/MUI:N/MVC:H/MVI:X/MVA:X/MSC:H/MSI:L/MSA:X", // val
        010110, // exp mv
        Score(89), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:H/VA:N/SC:H/SI:L/SA:N/E:U/CR:H/IR:M/AR:M/MAV:L/MAC:H/MAT:N/MPR:H/MUI:N/MVC:H/MVI:H/MVA:X/MSC:H/MSI:H/MSA:N", // val
        110120, // exp mv
        Score(53), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:H/VA:N/SC:L/SI:H/SA:L/E:U/CR:L/IR:X/AR:H/MAV:X/MAC:X/MAT:P/MPR:H/MUI:X/MVC:L/MVI:H/MVA:L/MSC:L/MSI:S/MSA:H", // val
        111020, // exp mv
        Score(58), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H/E:P/CR:H/IR:L/AR:H/MAV:N/MAC:X/MAT:X/MPR:N/MUI:P/MVC:N/MVI:X/MVA:X/MSC:L/MSI:S/MSA:L", // val
        112011, // exp mv
        Score(54), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:L/SC:H/SI:N/SA:L/E:A/CR:X/IR:H/AR:X/MAV:N/MAC:X/MAT:P/MPR:N/MUI:X/MVC:L/MVI:L/MVA:H/MSC:H/MSI:H/MSA:X", // val
        111100, // exp mv
        Score(73), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:N/SC:L/SI:L/SA:L/E:X/CR:X/IR:L/AR:M/MAV:P/MAC:X/MAT:N/MPR:H/MUI:P/MVC:L/MVI:N/MVA:N/MSC:N/MSI:X/MSA:S", // val
        212001, // exp mv
        Score(43), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:H/VI:L/VA:N/SC:H/SI:N/SA:L/E:A/CR:H/IR:L/AR:X/MAV:X/MAC:X/MAT:P/MPR:H/MUI:X/MVC:X/MVI:L/MVA:X/MSC:X/MSI:X/MSA:H", // val
        111100, // exp mv
        Score(69), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:H/VI:N/VA:H/SC:H/SI:L/SA:L/E:X/CR:H/IR:L/AR:L/MAV:X/MAC:L/MAT:X/MPR:X/MUI:P/MVC:L/MVI:H/MVA:H/MSC:L/MSI:L/MSA:H", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:H/VI:N/VA:N/SC:L/SI:L/SA:H/E:P/CR:L/IR:X/AR:M/MAV:X/MAC:X/MAT:X/MPR:H/MUI:A/MVC:L/MVI:H/MVA:N/MSC:L/MSI:S/MSA:X", // val
        111010, // exp mv
        Score(70), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:H/SI:N/SA:H/E:X/CR:M/IR:H/AR:M/MAV:N/MAC:X/MAT:N/MPR:H/MUI:X/MVC:H/MVI:N/MVA:X/MSC:H/MSI:L/MSA:L", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:N/VI:H/VA:L/SC:L/SI:H/SA:H/E:A/CR:X/IR:H/AR:H/MAV:A/MAC:H/MAT:P/MPR:X/MUI:A/MVC:H/MVI:N/MVA:L/MSC:H/MSI:H/MSA:N", // val
        211100, // exp mv
        Score(58), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:N/VI:H/VA:L/SC:L/SI:L/SA:N/E:P/CR:H/IR:L/AR:H/MAV:A/MAC:H/MAT:N/MPR:X/MUI:X/MVC:H/MVI:H/MVA:N/MSC:H/MSI:H/MSA:X", // val
        210110, // exp mv
        Score(55), // exp score
      ), (
        "test 7.4", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:L/SI:L/SA:L/E:X/CR:M/IR:L/AR:H/MAV:N/MAC:X/MAT:X/MPR:N/MUI:A/MVC:H/MVI:H/MVA:X/MSC:H/MSI:L/MSA:H", // val
        110101, // exp mv
        Score(74), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:N/VI:L/VA:N/SC:N/SI:H/SA:H/E:A/CR:X/IR:X/AR:M/MAV:X/MAC:H/MAT:P/MPR:H/MUI:X/MVC:N/MVI:X/MVA:H/MSC:H/MSI:X/MSA:N", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:N/SA:L/E:P/CR:M/IR:L/AR:L/MAV:X/MAC:H/MAT:X/MPR:N/MUI:X/MVC:X/MVI:X/MVA:X/MSC:H/MSI:L/MSA:X", // val
        112111, // exp mv
        Score(24), // exp score
      ), (
        "test 8.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:L/SA:L/E:X/CR:H/IR:X/AR:X/MAV:P/MAC:X/MAT:P/MPR:X/MUI:A/MVC:H/MVI:H/MVA:H/MSC:H/MSI:L/MSA:S", // val
        210000, // exp mv
        Score(86), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:H/VA:L/SC:L/SI:H/SA:H/E:U/CR:M/IR:M/AR:X/MAV:N/MAC:X/MAT:P/MPR:X/MUI:X/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:N", // val
        111021, // exp mv
        Score(45), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:H/VA:L/SC:L/SI:H/SA:N/E:A/CR:H/IR:H/AR:L/MAV:L/MAC:X/MAT:N/MPR:N/MUI:A/MVC:H/MVI:H/MVA:L/MSC:X/MSI:X/MSA:X", // val
        110100, // exp mv
        Score(83), // exp score
      ), (
        "test 0.2", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:H/VA:L/SC:L/SI:N/SA:N/E:U/CR:M/IR:M/AR:M/MAV:P/MAC:X/MAT:X/MPR:H/MUI:P/MVC:L/MVI:H/MVA:N/MSC:N/MSI:X/MSA:X", // val
        211221, // exp mv
        Score(2), // exp score
      ), (
        "test 8.6", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:H/VA:N/SC:H/SI:H/SA:L/E:X/CR:X/IR:X/AR:M/MAV:N/MAC:X/MAT:P/MPR:L/MUI:X/MVC:X/MVI:H/MVA:H/MSC:L/MSI:H/MSA:S", // val
        111000, // exp mv
        Score(86), // exp score
      ), (
        "test 3.5", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:L/SI:L/SA:N/E:U/CR:M/IR:H/AR:L/MAV:P/MAC:L/MAT:N/MPR:N/MUI:A/MVC:L/MVI:H/MVA:N/MSC:L/MSI:H/MSA:X", // val
        201120, // exp mv
        Score(35), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:N/SA:H/E:U/CR:M/IR:L/AR:M/MAV:N/MAC:H/MAT:X/MPR:L/MUI:X/MVC:X/MVI:L/MVA:L/MSC:H/MSI:L/MSA:S", // val
        112021, // exp mv
        Score(24), // exp score
      ), (
        "test 5", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:N/SA:L/E:P/CR:H/IR:X/AR:X/MAV:N/MAC:X/MAT:N/MPR:L/MUI:X/MVC:N/MVI:L/MVA:X/MSC:L/MSI:H/MSA:S", // val
        112011, // exp mv
        Score(50), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:L/E:P/CR:L/IR:M/AR:X/MAV:L/MAC:H/MAT:P/MPR:N/MUI:P/MVC:H/MVI:H/MVA:L/MSC:N/MSI:L/MSA:L", // val
        110211, // exp mv
        Score(51), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:L/E:U/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:P/MPR:H/MUI:A/MVC:L/MVI:N/MVA:X/MSC:X/MSI:H/MSA:X", // val
        112121, // exp mv
        Score(9), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:L/E:X/CR:M/IR:H/AR:H/MAV:A/MAC:H/MAT:X/MPR:L/MUI:A/MVC:H/MVI:H/MVA:L/MSC:L/MSI:H/MSA:L", // val
        210100, // exp mv
        Score(69), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:H/SC:H/SI:L/SA:N/E:U/CR:H/IR:X/AR:L/MAV:P/MAC:H/MAT:P/MPR:N/MUI:A/MVC:N/MVI:N/MVA:H/MSC:X/MSI:L/MSA:S", // val
        211021, // exp mv
        Score(18), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:L/SA:L/E:A/CR:X/IR:X/AR:H/MAV:P/MAC:X/MAT:P/MPR:N/MUI:N/MVC:L/MVI:X/MVA:H/MSC:L/MSI:H/MSA:X", // val
        211100, // exp mv
        Score(58), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:H/E:P/CR:L/IR:L/AR:H/MAV:P/MAC:X/MAT:X/MPR:H/MUI:N/MVC:X/MVI:N/MVA:L/MSC:N/MSI:S/MSA:L", // val
        212011, // exp mv
        Score(20), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:N/SA:H/E:U/CR:M/IR:H/AR:L/MAV:L/MAC:H/MAT:P/MPR:X/MUI:A/MVC:H/MVI:L/MVA:L/MSC:N/MSI:L/MSA:L", // val
        111221, // exp mv
        Score(10), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:H/VI:L/VA:L/SC:N/SI:H/SA:L/E:A/CR:M/IR:H/AR:L/MAV:N/MAC:H/MAT:P/MPR:X/MUI:P/MVC:L/MVI:L/MVA:L/MSC:N/MSI:N/MSA:L", // val
        112201, // exp mv
        Score(23), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:H/VA:H/SC:L/SI:N/SA:L/E:U/CR:L/IR:M/AR:H/MAV:P/MAC:L/MAT:N/MPR:H/MUI:N/MVC:N/MVI:L/MVA:N/MSC:X/MSI:S/MSA:N", // val
        202021, // exp mv
        Score(17), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:H/VA:L/SC:H/SI:L/SA:H/E:U/CR:X/IR:L/AR:L/MAV:X/MAC:L/MAT:P/MPR:N/MUI:X/MVC:N/MVI:H/MVA:X/MSC:L/MSI:H/MSA:N", // val
        111121, // exp mv
        Score(20), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:L/E:U/CR:L/IR:H/AR:L/MAV:X/MAC:H/MAT:N/MPR:N/MUI:P/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:L", // val
        111020, // exp mv
        Score(59), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:N/VI:H/VA:N/SC:H/SI:H/SA:L/E:A/CR:X/IR:H/AR:L/MAV:A/MAC:L/MAT:X/MPR:N/MUI:X/MVC:L/MVI:L/MVA:H/MSC:L/MSI:N/MSA:L", // val
        111201, // exp mv
        Score(48), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:N/VI:N/VA:H/SC:L/SI:H/SA:N/E:A/CR:L/IR:X/AR:L/MAV:N/MAC:H/MAT:N/MPR:H/MUI:N/MVC:N/MVI:X/MVA:H/MSC:H/MSI:N/MSA:H", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/CR:M/IR:M/AR:L/MAV:A/MAC:H/MAT:X/MPR:X/MUI:P/MVC:H/MVI:H/MVA:X/MSC:X/MSI:H/MSA:H", // val
        210121, // exp mv
        Score(17), // exp score
      ), (
        "test 0.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:L/VI:H/VA:N/SC:N/SI:L/SA:N/E:U/CR:H/IR:M/AR:M/MAV:A/MAC:H/MAT:N/MPR:H/MUI:X/MVC:L/MVI:X/MVA:X/MSC:L/MSI:L/MSA:X", // val
        211221, // exp mv
        Score(2), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:L/VI:N/VA:H/SC:H/SI:L/SA:N/E:X/CR:M/IR:X/AR:H/MAV:X/MAC:L/MAT:P/MPR:H/MUI:N/MVC:L/MVI:N/MVA:X/MSC:L/MSI:X/MSA:X", // val
        111200, // exp mv
        Score(59), // exp score
      ), (
        "test 1.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:N/VI:H/VA:L/SC:L/SI:H/SA:N/E:U/CR:X/IR:X/AR:L/MAV:P/MAC:H/MAT:X/MPR:L/MUI:N/MVC:X/MVI:H/MVA:H/MSC:X/MSI:H/MSA:N", // val
        211120, // exp mv
        Score(14), // exp score
      ), (
        "test 9.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:N/VI:H/VA:N/SC:N/SI:H/SA:L/E:X/CR:L/IR:H/AR:L/MAV:X/MAC:X/MAT:P/MPR:N/MUI:N/MVC:H/MVI:L/MVA:X/MSC:L/MSI:S/MSA:H", // val
        011001, // exp mv
        Score(91), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:N/VI:L/VA:H/SC:L/SI:N/SA:N/E:P/CR:M/IR:H/AR:H/MAV:L/MAC:L/MAT:P/MPR:H/MUI:P/MVC:X/MVI:L/MVA:H/MSC:N/MSI:S/MSA:X", // val
        211010, // exp mv
        Score(54), // exp score
      ), (
        "test 9.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:N/VI:L/VA:L/SC:L/SI:N/SA:H/E:A/CR:X/IR:L/AR:L/MAV:N/MAC:L/MAT:X/MPR:N/MUI:N/MVC:L/MVI:L/MVA:H/MSC:X/MSI:S/MSA:L", // val
        001001, // exp mv
        Score(94), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:N/VI:N/VA:H/SC:N/SI:L/SA:N/E:A/CR:X/IR:M/AR:X/MAV:L/MAC:L/MAT:P/MPR:X/MUI:P/MVC:N/MVI:L/MVA:X/MSC:H/MSI:S/MSA:S", // val
        211000, // exp mv
        Score(73), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:H/SA:N/E:U/CR:L/IR:L/AR:L/MAV:L/MAC:X/MAT:P/MPR:N/MUI:N/MVC:N/MVI:N/MVA:L/MSC:N/MSI:S/MSA:L", // val
        112021, // exp mv
        Score(23), // exp score
      ), (
        "test 2.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:N/SA:H/E:P/CR:M/IR:L/AR:X/MAV:A/MAC:L/MAT:P/MPR:N/MUI:N/MVC:N/MVI:N/MVA:N/MSC:X/MSI:H/MSA:H", // val
        112111, // exp mv
        Score(26), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:L/E:A/CR:M/IR:X/AR:X/MAV:P/MAC:L/MAT:P/MPR:X/MUI:N/MVC:N/MVI:L/MVA:X/MSC:N/MSI:L/MSA:N", // val
        211200, // exp mv
        Score(41), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:L/SC:L/SI:H/SA:H/E:A/CR:X/IR:X/AR:M/MAV:A/MAC:H/MAT:N/MPR:H/MUI:N/MVC:X/MVI:N/MVA:N/MSC:L/MSI:H/MSA:N", // val
        111100, // exp mv
        Score(69), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:L/E:X/CR:M/IR:L/AR:L/MAV:P/MAC:L/MAT:P/MPR:H/MUI:X/MVC:X/MVI:N/MVA:X/MSC:N/MSI:H/MSA:H", // val
        211101, // exp mv
        Score(40), // exp score
      ), (
        "test 5", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:L/E:X/CR:M/IR:H/AR:X/MAV:L/MAC:H/MAT:P/MPR:N/MUI:P/MVC:X/MVI:L/MVA:L/MSC:X/MSI:H/MSA:H", // val
        112101, // exp mv
        Score(50), // exp score
      ), (
        "test 8.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:H/SA:H/E:A/CR:M/IR:M/AR:X/MAV:X/MAC:L/MAT:X/MPR:X/MUI:A/MVC:H/MVI:N/MVA:H/MSC:L/MSI:X/MSA:L", // val
        101100, // exp mv
        Score(82), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:L/E:P/CR:H/IR:H/AR:X/MAV:N/MAC:L/MAT:N/MPR:N/MUI:X/MVC:L/MVI:L/MVA:N/MSC:N/MSI:H/MSA:H", // val
        002111, // exp mv
        Score(68), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:H/E:U/CR:H/IR:H/AR:X/MAV:L/MAC:L/MAT:X/MPR:L/MUI:A/MVC:H/MVI:H/MVA:H/MSC:X/MSI:H/MSA:L", // val
        200120, // exp mv
        Score(53), // exp score
      ), (
        "test 8.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:H/VI:H/VA:N/SC:N/SI:L/SA:H/E:A/CR:H/IR:H/AR:X/MAV:A/MAC:X/MAT:N/MPR:L/MUI:X/MVC:N/MVI:N/MVA:H/MSC:L/MSI:S/MSA:N", // val
        201000, // exp mv
        Score(82), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:N/VI:N/VA:H/SC:L/SI:H/SA:H/E:A/CR:H/IR:X/AR:L/MAV:A/MAC:H/MAT:P/MPR:X/MUI:P/MVC:H/MVI:H/MVA:L/MSC:L/MSI:N/MSA:H", // val
        210100, // exp mv
        Score(67), // exp score
      ), (
        "test 5.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:N/SC:L/SI:N/SA:H/E:P/CR:X/IR:M/AR:X/MAV:N/MAC:H/MAT:X/MPR:L/MUI:P/MVC:L/MVI:X/MVA:N/MSC:H/MSI:H/MSA:L", // val
        111111, // exp mv
        Score(52), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:N/VA:H/SC:H/SI:H/SA:H/E:U/CR:X/IR:M/AR:L/MAV:N/MAC:H/MAT:P/MPR:L/MUI:P/MVC:X/MVI:X/MVA:X/MSC:X/MSI:H/MSA:S", // val
        111020, // exp mv
        Score(59), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:L/VI:H/VA:L/SC:L/SI:L/SA:H/E:P/CR:X/IR:M/AR:M/MAV:X/MAC:X/MAT:P/MPR:L/MUI:N/MVC:H/MVI:N/MVA:L/MSC:H/MSI:N/MSA:L", // val
        111110, // exp mv
        Score(57), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:H/SA:N/E:A/CR:L/IR:X/AR:H/MAV:P/MAC:L/MAT:N/MPR:H/MUI:N/MVC:X/MVI:N/MVA:L/MSC:X/MSI:X/MSA:X", // val
        202101, // exp mv
        Score(41), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:M/AR:X/MAV:A/MAC:L/MAT:P/MPR:X/MUI:A/MVC:H/MVI:X/MVA:N/MSC:L/MSI:S/MSA:H", // val
        211021, // exp mv
        Score(17), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:N/VI:L/VA:L/SC:H/SI:H/SA:N/E:X/CR:M/IR:L/AR:H/MAV:N/MAC:L/MAT:P/MPR:H/MUI:A/MVC:N/MVI:H/MVA:X/MSC:L/MSI:S/MSA:H", // val
        111001, // exp mv
        Score(71), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:N/VI:N/VA:H/SC:H/SI:N/SA:H/E:A/CR:M/IR:M/AR:X/MAV:N/MAC:H/MAT:N/MPR:L/MUI:X/MVC:L/MVI:X/MVA:N/MSC:X/MSI:L/MSA:N", // val
        112101, // exp mv
        Score(45), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:L/SI:H/SA:N/E:P/CR:H/IR:X/AR:H/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:N/MVI:X/MVA:N/MSC:N/MSI:L/MSA:H", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:L/SI:N/SA:N/E:A/CR:X/IR:X/AR:H/MAV:X/MAC:H/MAT:N/MPR:N/MUI:A/MVC:H/MVI:N/MVA:N/MSC:X/MSI:L/MSA:N", // val
        111200, // exp mv
        Score(59), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:H/SC:H/SI:H/SA:L/E:P/CR:X/IR:M/AR:M/MAV:L/MAC:H/MAT:N/MPR:L/MUI:A/MVC:L/MVI:L/MVA:H/MSC:N/MSI:X/MSA:L", // val
        211111, // exp mv
        Score(16), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:H/SC:N/SI:H/SA:H/E:X/CR:M/IR:L/AR:X/MAV:N/MAC:X/MAT:P/MPR:N/MUI:N/MVC:X/MVI:N/MVA:N/MSC:L/MSI:X/MSA:N", // val
        012101, // exp mv
        Score(69), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:H/SC:L/SI:N/SA:H/E:X/CR:H/IR:L/AR:M/MAV:P/MAC:H/MAT:N/MPR:H/MUI:X/MVC:X/MVI:L/MVA:X/MSC:H/MSI:H/MSA:N", // val
        211101, // exp mv
        Score(44), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:H/SC:L/SI:N/SA:L/E:X/CR:H/IR:X/AR:X/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:X/MVI:L/MVA:L/MSC:X/MSI:S/MSA:X", // val
        212001, // exp mv
        Score(46), // exp score
      ), (
        "test 6.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:L/SC:L/SI:H/SA:N/E:U/CR:X/IR:M/AR:M/MAV:A/MAC:X/MAT:N/MPR:X/MUI:X/MVC:L/MVI:L/MVA:H/MSC:H/MSI:S/MSA:L", // val
        101021, // exp mv
        Score(64), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:L/SI:H/SA:H/E:P/CR:H/IR:M/AR:H/MAV:X/MAC:H/MAT:P/MPR:N/MUI:P/MVC:N/MVI:X/MVA:X/MSC:X/MSI:S/MSA:L", // val
        112011, // exp mv
        Score(54), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:L/SI:H/SA:H/E:P/CR:M/IR:H/AR:X/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:X/MVA:N/MSC:X/MSI:N/MSA:L", // val
        002211, // exp mv
        Score(55), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:L/SI:L/SA:H/E:A/CR:L/IR:M/AR:L/MAV:N/MAC:L/MAT:P/MPR:X/MUI:X/MVC:H/MVI:X/MVA:L/MSC:N/MSI:S/MSA:N", // val
        110001, // exp mv
        Score(85), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:N/SI:N/SA:L/E:A/CR:L/IR:L/AR:M/MAV:A/MAC:H/MAT:N/MPR:L/MUI:X/MVC:L/MVI:X/MVA:X/MSC:H/MSI:S/MSA:N", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 5.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:H/SC:H/SI:H/SA:N/E:U/CR:H/IR:M/AR:M/MAV:P/MAC:L/MAT:N/MPR:X/MUI:A/MVC:X/MVI:H/MVA:N/MSC:N/MSI:H/MSA:H", // val
        200120, // exp mv
        Score(52), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:H/SI:L/SA:L/E:P/CR:L/IR:X/AR:H/MAV:X/MAC:L/MAT:X/MPR:X/MUI:P/MVC:H/MVI:N/MVA:H/MSC:H/MSI:H/MSA:L", // val
        101110, // exp mv
        Score(71), // exp score
      ), (
        "test 6.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:H/VA:N/SC:N/SI:H/SA:H/E:P/CR:H/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:X/MVC:L/MVI:L/MVA:H/MSC:L/MSI:H/MSA:S", // val
        111011, // exp mv
        Score(65), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:H/SC:N/SI:N/SA:H/E:U/CR:X/IR:M/AR:M/MAV:A/MAC:H/MAT:X/MPR:N/MUI:P/MVC:N/MVI:L/MVA:L/MSC:H/MSI:N/MSA:L", // val
        112121, // exp mv
        Score(11), // exp score
      ), (
        "test 4.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:L/VA:H/SC:H/SI:L/SA:N/E:P/CR:L/IR:L/AR:H/MAV:L/MAC:H/MAT:X/MPR:N/MUI:P/MVC:N/MVI:H/MVA:N/MSC:H/MSI:N/MSA:X", // val
        111111, // exp mv
        Score(42), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:H/SC:L/SI:H/SA:N/E:A/CR:H/IR:M/AR:H/MAV:N/MAC:H/MAT:X/MPR:N/MUI:A/MVC:H/MVI:X/MVA:H/MSC:N/MSI:L/MSA:H", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:L/SC:L/SI:H/SA:N/E:X/CR:H/IR:H/AR:L/MAV:A/MAC:L/MAT:X/MPR:L/MUI:P/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:L", // val
        201000, // exp mv
        Score(83), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:L/SC:L/SI:H/SA:N/E:A/CR:L/IR:L/AR:L/MAV:N/MAC:L/MAT:X/MPR:L/MUI:P/MVC:H/MVI:H/MVA:X/MSC:H/MSI:L/MSA:X", // val
        100101, // exp mv
        Score(85), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:H/SI:H/SA:L/E:X/CR:H/IR:H/AR:X/MAV:A/MAC:H/MAT:P/MPR:X/MUI:X/MVC:N/MVI:N/MVA:X/MSC:L/MSI:L/MSA:H", // val
        112101, // exp mv
        Score(48), // exp score
      ), (
        "test 8.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:H/SC:H/SI:N/SA:N/E:A/CR:H/IR:H/AR:X/MAV:X/MAC:X/MAT:N/MPR:N/MUI:X/MVC:X/MVI:N/MVA:N/MSC:H/MSI:H/MSA:S", // val
        102001, // exp mv
        Score(81), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:L/SC:H/SI:L/SA:N/E:P/CR:L/IR:M/AR:L/MAV:N/MAC:L/MAT:N/MPR:L/MUI:X/MVC:L/MVI:L/MVA:H/MSC:N/MSI:X/MSA:H", // val
        101111, // exp mv
        Score(56), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:L/SC:L/SI:L/SA:L/E:A/CR:X/IR:H/AR:L/MAV:P/MAC:H/MAT:P/MPR:N/MUI:N/MVC:X/MVI:H/MVA:H/MSC:H/MSI:H/MSA:S", // val
        211000, // exp mv
        Score(73), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:H/E:P/CR:H/IR:M/AR:L/MAV:N/MAC:L/MAT:P/MPR:H/MUI:A/MVC:H/MVI:N/MVA:L/MSC:X/MSI:X/MSA:S", // val
        111010, // exp mv
        Score(67), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:H/SC:N/SI:H/SA:L/E:U/CR:H/IR:X/AR:X/MAV:L/MAC:H/MAT:X/MPR:X/MUI:P/MVC:X/MVI:X/MVA:X/MSC:L/MSI:S/MSA:S", // val
        111020, // exp mv
        Score(57), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H/E:P/CR:M/IR:X/AR:M/MAV:N/MAC:H/MAT:P/MPR:L/MUI:A/MVC:L/MVI:H/MVA:X/MSC:N/MSI:L/MSA:N", // val
        111210, // exp mv
        Score(48), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:N/SA:N/E:P/CR:L/IR:M/AR:L/MAV:X/MAC:L/MAT:X/MPR:H/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:N/MSA:H", // val
        101111, // exp mv
        Score(55), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N/E:P/CR:X/IR:H/AR:H/MAV:L/MAC:L/MAT:X/MPR:L/MUI:X/MVC:L/MVI:L/MVA:L/MSC:N/MSI:H/MSA:X", // val
        102111, // exp mv
        Score(46), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:L/SA:N/E:X/CR:M/IR:M/AR:X/MAV:X/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:X/MSI:N/MSA:L", // val
        110200, // exp mv
        Score(70), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:H/SI:N/SA:N/E:P/CR:X/IR:X/AR:H/MAV:A/MAC:L/MAT:N/MPR:X/MUI:X/MVC:N/MVI:N/MVA:L/MSC:N/MSI:H/MSA:H", // val
        102111, // exp mv
        Score(54), // exp score
      ), (
        "test 7.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:L/SI:N/SA:L/E:P/CR:L/IR:M/AR:L/MAV:X/MAC:L/MAT:X/MPR:N/MUI:N/MVC:N/MVI:L/MVA:H/MSC:L/MSI:L/MSA:H", // val
        001111, // exp mv
        Score(79), // exp score
      ), (
        "test 6.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:L/SA:N/E:A/CR:X/IR:L/AR:M/MAV:A/MAC:H/MAT:N/MPR:H/MUI:N/MVC:L/MVI:N/MVA:L/MSC:X/MSI:X/MSA:S", // val
        112001, // exp mv
        Score(65), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:H/SA:N/E:U/CR:X/IR:L/AR:M/MAV:L/MAC:H/MAT:X/MPR:X/MUI:X/MVC:X/MVI:L/MVA:L/MSC:L/MSI:S/MSA:L", // val
        112021, // exp mv
        Score(24), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:L/SA:N/E:P/CR:H/IR:M/AR:H/MAV:N/MAC:H/MAT:N/MPR:N/MUI:A/MVC:H/MVI:X/MVA:X/MSC:H/MSI:X/MSA:H", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:H/SI:L/SA:L/E:P/CR:H/IR:M/AR:H/MAV:L/MAC:H/MAT:N/MPR:H/MUI:N/MVC:X/MVI:X/MVA:N/MSC:N/MSI:X/MSA:N", // val
        112211, // exp mv
        Score(9), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:H/SC:N/SI:H/SA:H/E:U/CR:H/IR:M/AR:L/MAV:P/MAC:L/MAT:N/MPR:N/MUI:X/MVC:L/MVI:H/MVA:X/MSC:H/MSI:N/MSA:X", // val
        201121, // exp mv
        Score(17), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:H/SC:H/SI:H/SA:L/E:X/CR:L/IR:L/AR:L/MAV:A/MAC:X/MAT:N/MPR:X/MUI:X/MVC:N/MVI:N/MVA:N/MSC:L/MSI:L/MSA:X", // val
        102201, // exp mv
        Score(51), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:L/SI:H/SA:N/E:U/CR:L/IR:H/AR:X/MAV:P/MAC:H/MAT:N/MPR:H/MUI:X/MVC:X/MVI:L/MVA:H/MSC:L/MSI:X/MSA:H", // val
        211120, // exp mv
        Score(17), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:A/VC:N/VI:H/VA:H/SC:H/SI:H/SA:N/E:A/CR:X/IR:X/AR:L/MAV:L/MAC:X/MAT:P/MPR:N/MUI:X/MVC:H/MVI:X/MVA:N/MSC:X/MSI:X/MSA:L", // val
        110100, // exp mv
        Score(84), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:A/VC:N/VI:H/VA:H/SC:L/SI:H/SA:N/E:U/CR:L/IR:X/AR:M/MAV:N/MAC:L/MAT:X/MPR:H/MUI:X/MVC:H/MVI:H/MVA:L/MSC:X/MSI:N/MSA:S", // val
        110020, // exp mv
        Score(68), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:A/VC:N/VI:N/VA:H/SC:H/SI:N/SA:H/E:X/CR:M/IR:L/AR:L/MAV:L/MAC:X/MAT:N/MPR:H/MUI:A/MVC:X/MVI:L/MVA:H/MSC:N/MSI:S/MSA:H", // val
        201001, // exp mv
        Score(71), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:P/CR:L/IR:H/AR:L/MAV:X/MAC:X/MAT:N/MPR:H/MUI:A/MVC:H/MVI:L/MVA:L/MSC:X/MSI:S/MSA:L", // val
        101011, // exp mv
        Score(71), // exp score
      ), (
        "test 9.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:H/VI:N/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:X/AR:X/MAV:P/MAC:X/MAT:N/MPR:H/MUI:A/MVC:H/MVI:H/MVA:H/MSC:X/MSI:L/MSA:S", // val
        200000, // exp mv
        Score(92), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:H/VI:N/VA:L/SC:H/SI:L/SA:L/E:X/CR:L/IR:X/AR:M/MAV:X/MAC:L/MAT:X/MPR:L/MUI:X/MVC:N/MVI:L/MVA:N/MSC:L/MSI:L/MSA:H", // val
        112101, // exp mv
        Score(53), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:L/SC:H/SI:N/SA:L/E:P/CR:M/IR:X/AR:L/MAV:X/MAC:X/MAT:P/MPR:X/MUI:P/MVC:L/MVI:X/MVA:L/MSC:H/MSI:H/MSA:X", // val
        112111, // exp mv
        Score(23), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:L/SC:N/SI:N/SA:H/E:P/CR:X/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:X/MUI:P/MVC:N/MVI:H/MVA:N/MSC:N/MSI:L/MSA:L", // val
        211211, // exp mv
        Score(6), // exp score
      ), (
        "test 3.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:L/E:U/CR:L/IR:X/AR:M/MAV:P/MAC:L/MAT:N/MPR:H/MUI:N/MVC:N/MVI:L/MVA:H/MSC:N/MSI:S/MSA:N", // val
        201021, // exp mv
        Score(38), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:N/SI:L/SA:H/E:X/CR:L/IR:L/AR:M/MAV:L/MAC:L/MAT:P/MPR:L/MUI:P/MVC:X/MVI:X/MVA:X/MSC:N/MSI:X/MSA:X", // val
        211101, // exp mv
        Score(40), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:N/VI:H/VA:L/SC:H/SI:H/SA:N/E:U/CR:X/IR:L/AR:X/MAV:L/MAC:H/MAT:X/MPR:L/MUI:X/MVC:H/MVI:X/MVA:X/MSC:H/MSI:L/MSA:S", // val
        110020, // exp mv
        Score(71), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:N/VI:H/VA:N/SC:L/SI:H/SA:N/E:P/CR:L/IR:H/AR:M/MAV:X/MAC:L/MAT:N/MPR:H/MUI:N/MVC:X/MVI:H/MVA:N/MSC:H/MSI:L/MSA:L", // val
        101110, // exp mv
        Score(69), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:N/VI:L/VA:L/SC:H/SI:L/SA:N/E:A/CR:X/IR:M/AR:M/MAV:P/MAC:X/MAT:X/MPR:L/MUI:N/MVC:X/MVI:X/MVA:L/MSC:H/MSI:N/MSA:H", // val
        212101, // exp mv
        Score(21), // exp score
      ), (
        "test 8.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:H/VI:L/VA:L/SC:H/SI:L/SA:H/E:A/CR:X/IR:M/AR:M/MAV:X/MAC:L/MAT:N/MPR:H/MUI:X/MVC:N/MVI:H/MVA:H/MSC:N/MSI:H/MSA:S", // val
        101001, // exp mv
        Score(86), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:H/VI:N/VA:H/SC:N/SI:L/SA:N/E:X/CR:H/IR:X/AR:L/MAV:N/MAC:L/MAT:N/MPR:H/MUI:P/MVC:H/MVI:X/MVA:N/MSC:N/MSI:N/MSA:L", // val
        101200, // exp mv
        Score(67), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:H/VI:N/VA:N/SC:H/SI:N/SA:L/E:X/CR:L/IR:X/AR:H/MAV:L/MAC:L/MAT:X/MPR:H/MUI:P/MVC:X/MVI:X/MVA:X/MSC:H/MSI:X/MSA:X", // val
        211101, // exp mv
        Score(41), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:H/VI:N/VA:N/SC:N/SI:L/SA:H/E:U/CR:X/IR:H/AR:H/MAV:N/MAC:X/MAT:P/MPR:X/MUI:N/MVC:L/MVI:X/MVA:L/MSC:N/MSI:S/MSA:H", // val
        112021, // exp mv
        Score(24), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:L/VI:H/VA:H/SC:H/SI:L/SA:L/E:P/CR:H/IR:X/AR:X/MAV:X/MAC:H/MAT:P/MPR:H/MUI:P/MVC:L/MVI:H/MVA:H/MSC:H/MSI:H/MSA:L", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 7.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:L/VI:H/VA:H/SC:L/SI:L/SA:H/E:P/CR:M/IR:M/AR:X/MAV:A/MAC:L/MAT:X/MPR:N/MUI:N/MVC:L/MVI:N/MVA:H/MSC:H/MSI:S/MSA:S", // val
        111010, // exp mv
        Score(75), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:A/CR:M/IR:M/AR:L/MAV:X/MAC:X/MAT:N/MPR:L/MUI:A/MVC:L/MVI:H/MVA:L/MSC:H/MSI:X/MSA:L", // val
        101101, // exp mv
        Score(71), // exp score
      ), (
        "test 4.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:N/VI:N/VA:L/SC:H/SI:N/SA:H/E:A/CR:M/IR:X/AR:M/MAV:A/MAC:L/MAT:N/MPR:X/MUI:P/MVC:X/MVI:L/MVA:X/MSC:N/MSI:H/MSA:L", // val
        202101, // exp mv
        Score(42), // exp score
      ), (
        "test 4.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:L/IR:H/AR:M/MAV:L/MAC:X/MAT:P/MPR:L/MUI:A/MVC:L/MVI:L/MVA:H/MSC:H/MSI:H/MSA:L", // val
        211101, // exp mv
        Score(47), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:L/SC:H/SI:L/SA:L/E:X/CR:L/IR:H/AR:M/MAV:A/MAC:L/MAT:P/MPR:L/MUI:N/MVC:N/MVI:H/MVA:H/MSC:L/MSI:L/MSA:L", // val
        111200, // exp mv
        Score(58), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:L/SC:L/SI:N/SA:N/E:X/CR:L/IR:X/AR:L/MAV:L/MAC:H/MAT:P/MPR:N/MUI:N/MVC:L/MVI:N/MVA:H/MSC:N/MSI:N/MSA:X", // val
        111201, // exp mv
        Score(44), // exp score
      ), (
        "test 7.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:N/SC:H/SI:N/SA:H/E:X/CR:L/IR:L/AR:M/MAV:X/MAC:X/MAT:P/MPR:N/MUI:N/MVC:X/MVI:N/MVA:L/MSC:X/MSI:N/MSA:N", // val
        011101, // exp mv
        Score(78), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:N/SC:L/SI:H/SA:N/E:X/CR:X/IR:L/AR:X/MAV:P/MAC:X/MAT:P/MPR:X/MUI:P/MVC:N/MVI:H/MVA:H/MSC:N/MSI:S/MSA:H", // val
        211000, // exp mv
        Score(70), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:H/VI:N/VA:H/SC:H/SI:H/SA:L/E:X/CR:H/IR:X/AR:H/MAV:P/MAC:X/MAT:P/MPR:X/MUI:A/MVC:L/MVI:L/MVA:H/MSC:L/MSI:S/MSA:S", // val
        211000, // exp mv
        Score(73), // exp score
      ), (
        "test 3.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:H/VI:N/VA:N/SC:L/SI:H/SA:H/E:P/CR:L/IR:X/AR:M/MAV:L/MAC:X/MAT:N/MPR:H/MUI:P/MVC:X/MVI:N/MVA:N/MSC:L/MSI:N/MSA:X", // val
        201111, // exp mv
        Score(35), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:L/VI:H/VA:N/SC:L/SI:L/SA:L/E:A/CR:H/IR:M/AR:H/MAV:A/MAC:H/MAT:N/MPR:N/MUI:X/MVC:X/MVI:H/MVA:H/MSC:X/MSI:X/MSA:N", // val
        111200, // exp mv
        Score(58), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:N/VI:L/VA:H/SC:H/SI:N/SA:H/E:A/CR:M/IR:L/AR:H/MAV:X/MAC:H/MAT:N/MPR:H/MUI:P/MVC:H/MVI:N/MVA:N/MSC:H/MSI:X/MSA:N", // val
        111101, // exp mv
        Score(56), // exp score
      ), (
        "test 0.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/CR:H/IR:L/AR:H/MAV:A/MAC:L/MAT:X/MPR:X/MUI:P/MVC:H/MVI:X/MVA:X/MSC:L/MSI:X/MSA:X", // val
        211220, // exp mv
        Score(4), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:H/SC:L/SI:N/SA:L/E:X/CR:L/IR:H/AR:L/MAV:A/MAC:X/MAT:X/MPR:H/MUI:X/MVC:H/MVI:X/MVA:H/MSC:L/MSI:S/MSA:X", // val
        111001, // exp mv
        Score(72), // exp score
      ), (
        "test 6.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:L/SA:L/E:X/CR:M/IR:H/AR:M/MAV:X/MAC:L/MAT:P/MPR:H/MUI:P/MVC:N/MVI:L/MVA:X/MSC:L/MSI:N/MSA:S", // val
        112001, // exp mv
        Score(65), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:H/SC:L/SI:N/SA:L/E:A/CR:M/IR:M/AR:X/MAV:P/MAC:H/MAT:N/MPR:H/MUI:N/MVC:N/MVI:H/MVA:L/MSC:L/MSI:X/MSA:X", // val
        211201, // exp mv
        Score(17), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:H/SI:L/SA:L/E:A/CR:M/IR:M/AR:M/MAV:A/MAC:L/MAT:P/MPR:L/MUI:X/MVC:L/MVI:X/MVA:N/MSC:H/MSI:H/MSA:S", // val
        112001, // exp mv
        Score(69), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:H/SC:H/SI:H/SA:L/E:U/CR:X/IR:L/AR:X/MAV:A/MAC:H/MAT:P/MPR:N/MUI:N/MVC:L/MVI:X/MVA:X/MSC:N/MSI:X/MSA:S", // val
        111020, // exp mv
        Score(59), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H/E:X/CR:M/IR:M/AR:H/MAV:X/MAC:X/MAT:P/MPR:N/MUI:N/MVC:L/MVI:H/MVA:H/MSC:N/MSI:X/MSA:N", // val
        011200, // exp mv
        Score(83), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:N/SC:H/SI:L/SA:L/E:P/CR:H/IR:M/AR:H/MAV:X/MAC:L/MAT:N/MPR:X/MUI:A/MVC:L/MVI:N/MVA:X/MSC:X/MSI:L/MSA:S", // val
        102011, // exp mv
        Score(67), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:L/E:P/CR:X/IR:L/AR:X/MAV:X/MAC:X/MAT:N/MPR:H/MUI:X/MVC:X/MVI:L/MVA:N/MSC:L/MSI:H/MSA:L", // val
        101110, // exp mv
        Score(69), // exp score
      ), (
        "test 3.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:N/SC:H/SI:H/SA:L/E:U/CR:M/IR:L/AR:H/MAV:P/MAC:H/MAT:X/MPR:X/MUI:N/MVC:H/MVI:H/MVA:X/MSC:N/MSI:S/MSA:L", // val
        210021, // exp mv
        Score(35), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:H/E:P/CR:M/IR:X/AR:L/MAV:L/MAC:H/MAT:P/MPR:L/MUI:P/MVC:H/MVI:H/MVA:H/MSC:N/MSI:H/MSA:N", // val
        210110, // exp mv
        Score(54), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:L/VI:H/VA:H/SC:N/SI:H/SA:L/E:U/CR:L/IR:H/AR:M/MAV:A/MAC:L/MAT:N/MPR:H/MUI:P/MVC:L/MVI:N/MVA:N/MSC:X/MSI:L/MSA:H", // val
        202121, // exp mv
        Score(9), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:L/VI:H/VA:L/SC:H/SI:H/SA:N/E:A/CR:H/IR:L/AR:X/MAV:P/MAC:L/MAT:P/MPR:H/MUI:P/MVC:X/MVI:X/MVA:N/MSC:H/MSI:L/MSA:L", // val
        211101, // exp mv
        Score(44), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:N/SA:L/E:U/CR:H/IR:X/AR:L/MAV:N/MAC:L/MAT:X/MPR:X/MUI:X/MVC:X/MVI:L/MVA:X/MSC:N/MSI:S/MSA:X", // val
        112021, // exp mv
        Score(23), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:L/VI:N/VA:H/SC:H/SI:H/SA:N/E:U/CR:X/IR:X/AR:M/MAV:X/MAC:L/MAT:P/MPR:N/MUI:P/MVC:L/MVI:X/MVA:N/MSC:N/MSI:N/MSA:N", // val
        112221, // exp mv
        Score(6), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H/E:A/CR:M/IR:H/AR:M/MAV:A/MAC:H/MAT:P/MPR:N/MUI:P/MVC:X/MVI:X/MVA:X/MSC:H/MSI:H/MSA:H", // val
        111100, // exp mv
        Score(72), // exp score
      ), (
        "test 7.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:N/SA:L/E:U/CR:X/IR:H/AR:M/MAV:X/MAC:L/MAT:N/MPR:L/MUI:N/MVC:H/MVI:X/MVA:X/MSC:H/MSI:L/MSA:L", // val
        100120, // exp mv
        Score(75), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:H/SC:L/SI:N/SA:L/E:U/CR:X/IR:H/AR:X/MAV:P/MAC:X/MAT:N/MPR:X/MUI:A/MVC:L/MVI:X/MVA:H/MSC:N/MSI:L/MSA:N", // val
        201220, // exp mv
        Score(18), // exp score
      ), (
        "test 7.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:N/VA:H/SC:L/SI:L/SA:L/E:A/CR:X/IR:M/AR:M/MAV:L/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:N/MVA:H/MSC:L/MSI:S/MSA:X", // val
        111001, // exp mv
        Score(74), // exp score
      ), (
        "test 9.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L/E:A/CR:H/IR:M/AR:M/MAV:X/MAC:L/MAT:N/MPR:H/MUI:P/MVC:H/MVI:H/MVA:X/MSC:N/MSI:H/MSA:H", // val
        100100, // exp mv
        Score(92), // exp score
      ), (
        "test 4.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:L/SC:H/SI:N/SA:L/E:U/CR:M/IR:M/AR:L/MAV:N/MAC:L/MAT:X/MPR:X/MUI:X/MVC:H/MVI:L/MVA:H/MSC:H/MSI:L/MSA:S", // val
        111021, // exp mv
        Score(49), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:L/SC:L/SI:H/SA:H/E:U/CR:H/IR:L/AR:L/MAV:A/MAC:L/MAT:X/MPR:L/MUI:N/MVC:X/MVI:L/MVA:N/MSC:L/MSI:S/MSA:N", // val
        111020, // exp mv
        Score(56), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/E:U/CR:X/IR:H/AR:L/MAV:A/MAC:X/MAT:X/MPR:N/MUI:X/MVC:H/MVI:X/MVA:H/MSC:N/MSI:X/MSA:S", // val
        110020, // exp mv
        Score(69), // exp score
      ), (
        "test 2.7", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:L/SC:L/SI:N/SA:L/E:U/CR:X/IR:H/AR:L/MAV:N/MAC:H/MAT:N/MPR:N/MUI:N/MVC:L/MVI:L/MVA:X/MSC:X/MSI:H/MSA:L", // val
        012121, // exp mv
        Score(27), // exp score
      ), (
        "test 4.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:N/SC:H/SI:H/SA:N/E:P/CR:M/IR:L/AR:M/MAV:A/MAC:L/MAT:X/MPR:L/MUI:N/MVC:X/MVI:L/MVA:X/MSC:H/MSI:X/MSA:L", // val
        111111, // exp mv
        Score(49), // exp score
      ), (
        "test 6.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:N/SC:L/SI:H/SA:L/E:X/CR:H/IR:X/AR:H/MAV:N/MAC:L/MAT:P/MPR:H/MUI:A/MVC:L/MVI:N/MVA:N/MSC:X/MSI:N/MSA:S", // val
        112001, // exp mv
        Score(64), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:L/SC:H/SI:L/SA:N/E:A/CR:M/IR:L/AR:X/MAV:P/MAC:X/MAT:X/MPR:H/MUI:X/MVC:X/MVI:N/MVA:N/MSC:X/MSI:L/MSA:H", // val
        211101, // exp mv
        Score(44), // exp score
      ), (
        "test 6.3", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:H/SI:L/SA:N/E:U/CR:M/IR:L/AR:X/MAV:X/MAC:H/MAT:N/MPR:X/MUI:X/MVC:X/MVI:H/MVA:N/MSC:N/MSI:S/MSA:L", // val
        110021, // exp mv
        Score(63), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:H/VA:L/SC:N/SI:L/SA:H/E:A/CR:X/IR:L/AR:H/MAV:L/MAC:H/MAT:X/MPR:H/MUI:P/MVC:H/MVI:X/MVA:H/MSC:H/MSI:X/MSA:N", // val
        210100, // exp mv
        Score(68), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:H/VA:L/SC:N/SI:N/SA:L/E:U/CR:H/IR:X/AR:H/MAV:P/MAC:L/MAT:N/MPR:H/MUI:N/MVC:N/MVI:H/MVA:H/MSC:N/MSI:S/MSA:H", // val
        201020, // exp mv
        Score(59), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:H/SC:N/SI:L/SA:H/E:P/CR:X/IR:M/AR:X/MAV:L/MAC:H/MAT:X/MPR:L/MUI:P/MVC:L/MVI:L/MVA:H/MSC:H/MSI:N/MSA:S", // val
        211010, // exp mv
        Score(55), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:H/VA:H/SC:L/SI:L/SA:N/E:P/CR:H/IR:L/AR:H/MAV:A/MAC:H/MAT:N/MPR:L/MUI:X/MVC:X/MVI:H/MVA:X/MSC:H/MSI:H/MSA:X", // val
        211110, // exp mv
        Score(40), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:H/SA:H/E:U/CR:L/IR:X/AR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:P/MVC:L/MVI:X/MVA:X/MSC:N/MSI:N/MSA:H", // val
        101120, // exp mv
        Score(56), // exp score
      ), (
        "test 8.1", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:H/E:X/CR:M/IR:H/AR:M/MAV:X/MAC:L/MAT:P/MPR:X/MUI:X/MVC:X/MVI:N/MVA:N/MSC:H/MSI:H/MSA:X", // val
        011101, // exp mv
        Score(81), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:L/SC:H/SI:L/SA:H/E:U/CR:H/IR:M/AR:H/MAV:P/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:N/MVA:N/MSC:X/MSI:S/MSA:N", // val
        201020, // exp mv
        Score(58), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N/E:A/CR:M/IR:X/AR:M/MAV:N/MAC:H/MAT:X/MPR:L/MUI:X/MVC:L/MVI:X/MVA:H/MSC:L/MSI:N/MSA:N", // val
        111200, // exp mv
        Score(59), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:L/SA:H/E:U/CR:X/IR:L/AR:M/MAV:P/MAC:X/MAT:N/MPR:N/MUI:P/MVC:X/MVI:X/MVA:H/MSC:N/MSI:S/MSA:H", // val
        201020, // exp mv
        Score(58), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:N/VA:H/SC:L/SI:L/SA:L/E:P/CR:X/IR:M/AR:M/MAV:N/MAC:L/MAT:P/MPR:H/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:X/MSA:S", // val
        110010, // exp mv
        Score(85), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:H/SC:L/SI:H/SA:H/E:X/CR:M/IR:X/AR:L/MAV:X/MAC:L/MAT:P/MPR:H/MUI:P/MVC:X/MVI:L/MVA:N/MSC:H/MSI:L/MSA:N", // val
        112101, // exp mv
        Score(45), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:A/CR:X/IR:M/AR:X/MAV:X/MAC:H/MAT:N/MPR:H/MUI:N/MVC:H/MVI:L/MVA:N/MSC:L/MSI:L/MSA:H", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:H/SA:L/E:P/CR:M/IR:H/AR:M/MAV:A/MAC:H/MAT:N/MPR:N/MUI:X/MVC:N/MVI:H/MVA:X/MSC:X/MSI:X/MSA:S", // val
        111010, // exp mv
        Score(72), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:H/SC:L/SI:H/SA:L/E:U/CR:X/IR:L/AR:H/MAV:P/MAC:L/MAT:P/MPR:X/MUI:X/MVC:L/MVI:L/MVA:N/MSC:L/MSI:S/MSA:X", // val
        212021, // exp mv
        Score(10), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:H/E:A/CR:L/IR:H/AR:M/MAV:N/MAC:X/MAT:X/MPR:H/MUI:N/MVC:X/MVI:N/MVA:X/MSC:H/MSI:S/MSA:X", // val
        112001, // exp mv
        Score(69), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N/E:U/CR:X/IR:M/AR:L/MAV:L/MAC:X/MAT:N/MPR:L/MUI:P/MVC:X/MVI:H/MVA:L/MSC:L/MSI:H/MSA:N", // val
        201121, // exp mv
        Score(16), // exp score
      ), (
        "test 3.2", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N/E:U/CR:H/IR:L/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:A/MVC:H/MVI:L/MVA:X/MSC:N/MSI:H/MSA:L", // val
        111120, // exp mv
        Score(32), // exp score
      ), (
        "test 4.9", // name
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:H/SA:L/E:X/CR:L/IR:H/AR:H/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:N/MSC:H/MSI:N/MSA:N", // val
        112101, // exp mv
        Score(49), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:H/VI:H/VA:N/SC:H/SI:L/SA:L/E:P/CR:X/IR:M/AR:M/MAV:A/MAC:H/MAT:X/MPR:X/MUI:X/MVC:L/MVI:H/MVA:L/MSC:N/MSI:N/MSA:S", // val
        211011, // exp mv
        Score(37), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:H/VI:L/VA:L/SC:L/SI:H/SA:L/E:U/CR:M/IR:M/AR:L/MAV:L/MAC:H/MAT:X/MPR:L/MUI:N/MVC:X/MVI:N/MVA:X/MSC:N/MSI:N/MSA:L", // val
        111221, // exp mv
        Score(10), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:L/IR:M/AR:M/MAV:L/MAC:H/MAT:N/MPR:X/MUI:A/MVC:H/MVI:X/MVA:X/MSC:X/MSI:S/MSA:N", // val
        210001, // exp mv
        Score(68), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:L/VI:N/VA:H/SC:N/SI:L/SA:L/E:A/CR:X/IR:X/AR:H/MAV:L/MAC:X/MAT:N/MPR:X/MUI:N/MVC:H/MVI:X/MVA:L/MSC:L/MSI:H/MSA:L", // val
        111100, // exp mv
        Score(69), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:L/VI:N/VA:N/SC:L/SI:L/SA:H/E:P/CR:X/IR:M/AR:X/MAV:P/MAC:H/MAT:N/MPR:N/MUI:A/MVC:N/MVI:X/MVA:H/MSC:H/MSI:L/MSA:N", // val
        211110, // exp mv
        Score(37), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:X/IR:H/AR:L/MAV:L/MAC:H/MAT:N/MPR:H/MUI:A/MVC:X/MVI:X/MVA:L/MSC:N/MSI:H/MSA:H", // val
        211100, // exp mv
        Score(57), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:N/VI:H/VA:L/SC:N/SI:L/SA:N/E:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:L/MVA:L/MSC:L/MSI:H/MSA:N", // val
        112101, // exp mv
        Score(48), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N/E:U/CR:H/IR:X/AR:X/MAV:N/MAC:X/MAT:X/MPR:L/MUI:A/MVC:H/MVI:L/MVA:N/MSC:L/MSI:X/MSA:H", // val
        111120, // exp mv
        Score(39), // exp score
      ), (
        "test 6.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:H/E:P/CR:M/IR:H/AR:X/MAV:N/MAC:H/MAT:X/MPR:L/MUI:P/MVC:X/MVI:L/MVA:X/MSC:H/MSI:X/MSA:S", // val
        111011, // exp mv
        Score(65), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:L/VI:H/VA:N/SC:H/SI:L/SA:H/E:U/CR:L/IR:H/AR:M/MAV:X/MAC:H/MAT:X/MPR:X/MUI:A/MVC:X/MVI:X/MVA:H/MSC:L/MSI:L/MSA:N", // val
        211220, // exp mv
        Score(6), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:L/VI:N/VA:L/SC:N/SI:H/SA:N/E:X/CR:M/IR:L/AR:L/MAV:P/MAC:H/MAT:X/MPR:H/MUI:P/MVC:N/MVI:N/MVA:H/MSC:L/MSI:S/MSA:N", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:H/E:P/CR:M/IR:L/AR:L/MAV:N/MAC:X/MAT:N/MPR:X/MUI:N/MVC:X/MVI:H/MVA:H/MSC:X/MSI:H/MSA:L", // val
        111111, // exp mv
        Score(46), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:L/SI:N/SA:L/E:A/CR:M/IR:L/AR:L/MAV:L/MAC:H/MAT:N/MPR:L/MUI:A/MVC:N/MVI:L/MVA:L/MSC:X/MSI:S/MSA:S", // val
        212001, // exp mv
        Score(51), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:X/CR:M/IR:H/AR:L/MAV:A/MAC:H/MAT:N/MPR:H/MUI:P/MVC:L/MVI:L/MVA:H/MSC:N/MSI:S/MSA:N", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 8.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:X/MAV:N/MAC:H/MAT:P/MPR:N/MUI:P/MVC:H/MVI:H/MVA:N/MSC:H/MSI:L/MSA:H", // val
        110100, // exp mv
        Score(88), // exp score
      ), (
        "test 0.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N/E:P/CR:X/IR:X/AR:X/MAV:X/MAC:L/MAT:P/MPR:L/MUI:P/MVC:L/MVI:X/MVA:N/MSC:X/MSI:H/MSA:X", // val
        212111, // exp mv
        Score(8), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:L/E:A/CR:L/IR:X/AR:H/MAV:P/MAC:L/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:X/MSC:N/MSI:N/MSA:S", // val
        201001, // exp mv
        Score(71), // exp score
      ), (
        "test 8", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N/E:X/CR:M/IR:H/AR:X/MAV:N/MAC:L/MAT:P/MPR:N/MUI:N/MVC:X/MVI:N/MVA:N/MSC:L/MSI:L/MSA:H", // val
        011101, // exp mv
        Score(80), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:N/SC:H/SI:L/SA:N/E:P/CR:X/IR:X/AR:M/MAV:P/MAC:X/MAT:P/MPR:X/MUI:A/MVC:X/MVI:X/MVA:N/MSC:L/MSI:X/MSA:N", // val
        210210, // exp mv
        Score(40), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:N/SC:L/SI:N/SA:L/E:X/CR:X/IR:X/AR:X/MAV:L/MAC:L/MAT:P/MPR:L/MUI:A/MVC:H/MVI:L/MVA:L/MSC:X/MSI:S/MSA:L", // val
        211000, // exp mv
        Score(72), // exp score
      ), (
        "test 3.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:L/VA:N/SC:H/SI:L/SA:H/E:X/CR:L/IR:X/AR:H/MAV:P/MAC:H/MAT:P/MPR:H/MUI:N/MVC:N/MVI:H/MVA:N/MSC:N/MSI:X/MSA:L", // val
        211200, // exp mv
        Score(37), // exp score
      ), (
        "test 7.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:N/VA:H/SC:N/SI:N/SA:L/E:X/CR:M/IR:M/AR:M/MAV:N/MAC:X/MAT:N/MPR:X/MUI:P/MVC:H/MVI:L/MVA:X/MSC:H/MSI:N/MSA:S", // val
        111001, // exp mv
        Score(74), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:N/VA:L/SC:L/SI:L/SA:H/E:X/CR:M/IR:X/AR:L/MAV:L/MAC:X/MAT:P/MPR:H/MUI:N/MVC:X/MVI:X/MVA:L/MSC:L/MSI:X/MSA:N", // val
        111201, // exp mv
        Score(40), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:L/VI:H/VA:H/SC:H/SI:H/SA:N/E:A/CR:L/IR:H/AR:H/MAV:P/MAC:L/MAT:P/MPR:L/MUI:N/MVC:H/MVI:N/MVA:X/MSC:H/MSI:H/MSA:X", // val
        211100, // exp mv
        Score(58), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:L/VI:H/VA:N/SC:L/SI:L/SA:H/E:X/CR:M/IR:L/AR:M/MAV:L/MAC:L/MAT:P/MPR:X/MUI:N/MVC:N/MVI:L/MVA:N/MSC:X/MSI:N/MSA:N", // val
        112201, // exp mv
        Score(20), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:L/VI:L/VA:L/SC:L/SI:N/SA:L/E:P/CR:M/IR:X/AR:L/MAV:P/MAC:L/MAT:P/MPR:H/MUI:P/MVC:H/MVI:X/MVA:H/MSC:X/MSI:S/MSA:S", // val
        211011, // exp mv
        Score(43), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:L/VI:N/VA:L/SC:L/SI:N/SA:H/E:X/CR:X/IR:M/AR:H/MAV:P/MAC:X/MAT:X/MPR:L/MUI:P/MVC:N/MVI:N/MVA:X/MSC:N/MSI:L/MSA:H", // val
        212101, // exp mv
        Score(20), // exp score
      ), (
        "test 0.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:L/VI:N/VA:N/SC:N/SI:L/SA:N/E:P/CR:L/IR:X/AR:H/MAV:L/MAC:H/MAT:P/MPR:H/MUI:X/MVC:L/MVI:N/MVA:L/MSC:L/MSI:L/MSA:X", // val
        212211, // exp mv
        Score(3), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:N/VI:H/VA:H/SC:N/SI:L/SA:H/E:X/CR:X/IR:X/AR:L/MAV:P/MAC:X/MAT:X/MPR:X/MUI:P/MVC:L/MVI:N/MVA:L/MSC:N/MSI:X/MSA:S", // val
        212001, // exp mv
        Score(43), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:N/VI:N/VA:N/SC:N/SI:H/SA:L/E:U/CR:X/IR:X/AR:X/MAV:L/MAC:L/MAT:N/MPR:H/MUI:P/MVC:N/MVI:H/MVA:X/MSC:H/MSI:L/MSA:X", // val
        201120, // exp mv
        Score(39), // exp score
      ), (
        "test 9.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:H/E:A/CR:H/IR:H/AR:X/MAV:N/MAC:L/MAT:X/MPR:N/MUI:N/MVC:N/MVI:H/MVA:L/MSC:H/MSI:S/MSA:N", // val
        001000, // exp mv
        Score(97), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:L/SA:H/E:X/CR:M/IR:L/AR:L/MAV:N/MAC:L/MAT:P/MPR:H/MUI:P/MVC:H/MVI:L/MVA:H/MSC:X/MSI:X/MSA:S", // val
        111001, // exp mv
        Score(71), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:L/SC:L/SI:L/SA:N/E:P/CR:H/IR:X/AR:M/MAV:X/MAC:H/MAT:X/MPR:X/MUI:P/MVC:H/MVI:H/MVA:H/MSC:L/MSI:N/MSA:X", // val
        210210, // exp mv
        Score(43), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:L/VI:H/VA:L/SC:L/SI:H/SA:N/E:X/CR:L/IR:M/AR:L/MAV:L/MAC:H/MAT:N/MPR:L/MUI:X/MVC:X/MVI:H/MVA:N/MSC:N/MSI:X/MSA:S", // val
        111001, // exp mv
        Score(72), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:L/VI:L/VA:H/SC:H/SI:N/SA:N/E:P/CR:X/IR:M/AR:H/MAV:A/MAC:H/MAT:N/MPR:X/MUI:X/MVC:L/MVI:X/MVA:H/MSC:N/MSI:S/MSA:L", // val
        111010, // exp mv
        Score(71), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:L/E:U/CR:M/IR:H/AR:L/MAV:L/MAC:L/MAT:P/MPR:N/MUI:N/MVC:H/MVI:X/MVA:L/MSC:X/MSI:H/MSA:H", // val
        111121, // exp mv
        Score(21), // exp score
      ), (
        "test 0.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:L/SI:L/SA:N/E:U/CR:H/IR:X/AR:X/MAV:L/MAC:X/MAT:P/MPR:L/MUI:A/MVC:X/MVI:H/MVA:X/MSC:N/MSI:N/MSA:X", // val
        211220, // exp mv
        Score(7), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:H/SI:L/SA:N/E:X/CR:L/IR:H/AR:X/MAV:X/MAC:H/MAT:P/MPR:L/MUI:P/MVC:X/MVI:N/MVA:L/MSC:N/MSI:S/MSA:X", // val
        212001, // exp mv
        Score(41), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:L/SI:H/SA:L/E:U/CR:X/IR:M/AR:L/MAV:X/MAC:L/MAT:X/MPR:X/MUI:N/MVC:X/MVI:H/MVA:H/MSC:L/MSI:H/MSA:L", // val
        201121, // exp mv
        Score(17), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:A/MVC:L/MVI:H/MVA:X/MSC:L/MSI:X/MSA:X", // val
        111121, // exp mv
        Score(20), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N/E:X/CR:X/IR:L/AR:X/MAV:P/MAC:H/MAT:N/MPR:N/MUI:X/MVC:L/MVI:X/MVA:H/MSC:L/MSI:H/MSA:N", // val
        211100, // exp mv
        Score(57), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:H/SA:N/E:A/CR:H/IR:X/AR:M/MAV:A/MAC:L/MAT:P/MPR:X/MUI:A/MVC:L/MVI:N/MVA:X/MSC:L/MSI:H/MSA:L", // val
        211101, // exp mv
        Score(45), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:H/SC:N/SI:H/SA:N/E:A/CR:X/IR:H/AR:L/MAV:N/MAC:H/MAT:P/MPR:L/MUI:N/MVC:N/MVI:H/MVA:X/MSC:L/MSI:H/MSA:H", // val
        111100, // exp mv
        Score(72), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:N/MPR:X/MUI:N/MVC:L/MVI:L/MVA:X/MSC:L/MSI:L/MSA:L", // val
        211211, // exp mv
        Score(6), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:N/SC:N/SI:N/SA:H/E:A/CR:H/IR:L/AR:H/MAV:P/MAC:L/MAT:P/MPR:X/MUI:A/MVC:H/MVI:H/MVA:X/MSC:L/MSI:H/MSA:S", // val
        210000, // exp mv
        Score(84), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:H/SC:H/SI:N/SA:N/E:P/CR:X/IR:L/AR:H/MAV:X/MAC:L/MAT:N/MPR:H/MUI:X/MVC:X/MVI:X/MVA:L/MSC:N/MSI:X/MSA:X", // val
        202211, // exp mv
        Score(9), // exp score
      ), (
        "test 3.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:H/SI:L/SA:L/E:U/CR:H/IR:M/AR:M/MAV:P/MAC:X/MAT:N/MPR:H/MUI:P/MVC:H/MVI:L/MVA:H/MSC:N/MSI:H/MSA:S", // val
        211020, // exp mv
        Score(33), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:N/VA:L/SC:L/SI:L/SA:L/E:A/CR:L/IR:H/AR:L/MAV:X/MAC:X/MAT:P/MPR:X/MUI:X/MVC:L/MVI:H/MVA:N/MSC:N/MSI:H/MSA:L", // val
        211100, // exp mv
        Score(56), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:N/VI:L/VA:N/SC:L/SI:N/SA:H/E:X/CR:L/IR:H/AR:L/MAV:X/MAC:L/MAT:N/MPR:H/MUI:P/MVC:H/MVI:H/MVA:H/MSC:L/MSI:H/MSA:L", // val
        200100, // exp mv
        Score(83), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:H/E:X/CR:M/IR:X/AR:M/MAV:X/MAC:H/MAT:N/MPR:N/MUI:X/MVC:X/MVI:L/MVA:N/MSC:L/MSI:H/MSA:N", // val
        212101, // exp mv
        Score(20), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:H/SI:N/SA:L/E:A/CR:L/IR:H/AR:L/MAV:L/MAC:H/MAT:P/MPR:N/MUI:N/MVC:X/MVI:X/MVA:X/MSC:N/MSI:L/MSA:X", // val
        110200, // exp mv
        Score(72), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:H/SC:N/SI:H/SA:L/E:U/CR:L/IR:H/AR:L/MAV:P/MAC:L/MAT:X/MPR:L/MUI:P/MVC:L/MVI:H/MVA:L/MSC:L/MSI:X/MSA:S", // val
        201020, // exp mv
        Score(58), // exp score
      ), (
        "test 7.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:A/VC:L/VI:N/VA:H/SC:H/SI:L/SA:H/E:X/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:X/MPR:N/MUI:P/MVC:H/MVI:L/MVA:H/MSC:X/MSI:S/MSA:N", // val
        111001, // exp mv
        Score(74), // exp score
      ), (
        "test 6.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:H/SI:N/SA:N/E:P/CR:L/IR:H/AR:L/MAV:A/MAC:L/MAT:X/MPR:N/MUI:X/MVC:L/MVI:X/MVA:L/MSC:L/MSI:X/MSA:S", // val
        102011, // exp mv
        Score(66), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H/E:X/CR:M/IR:L/AR:H/MAV:L/MAC:X/MAT:X/MPR:H/MUI:X/MVC:N/MVI:H/MVA:L/MSC:H/MSI:N/MSA:H", // val
        211101, // exp mv
        Score(43), // exp score
      ), (
        "test 1.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:H/SI:L/SA:N/E:P/CR:H/IR:H/AR:M/MAV:N/MAC:X/MAT:X/MPR:N/MUI:A/MVC:X/MVI:N/MVA:N/MSC:L/MSI:L/MSA:N", // val
        112211, // exp mv
        Score(12), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:L/AR:X/MAV:L/MAC:H/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:H/MSC:L/MSI:N/MSA:N", // val
        111220, // exp mv
        Score(21), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N/E:U/CR:X/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:H/MUI:N/MVC:N/MVI:X/MVA:N/MSC:L/MSI:X/MSA:X", // val
        102221, // exp mv
        Score(10), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:L/SC:H/SI:L/SA:N/E:P/CR:X/IR:L/AR:X/MAV:P/MAC:H/MAT:P/MPR:N/MUI:X/MVC:H/MVI:L/MVA:H/MSC:X/MSI:H/MSA:X", // val
        211110, // exp mv
        Score(41), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:H/SI:L/SA:L/E:X/CR:X/IR:X/AR:L/MAV:X/MAC:H/MAT:P/MPR:N/MUI:N/MVC:N/MVI:N/MVA:H/MSC:X/MSI:S/MSA:X", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:L/SI:L/SA:L/E:X/CR:M/IR:M/AR:X/MAV:X/MAC:L/MAT:X/MPR:N/MUI:N/MVC:H/MVI:X/MVA:H/MSC:H/MSI:H/MSA:X", // val
        201100, // exp mv
        Score(70), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:L/SI:H/SA:L/E:P/CR:M/IR:L/AR:H/MAV:L/MAC:L/MAT:X/MPR:H/MUI:N/MVC:L/MVI:X/MVA:H/MSC:X/MSI:N/MSA:S", // val
        101010, // exp mv
        Score(83), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N/E:P/CR:L/IR:M/AR:H/MAV:P/MAC:H/MAT:N/MPR:X/MUI:N/MVC:H/MVI:X/MVA:N/MSC:H/MSI:L/MSA:S", // val
        211011, // exp mv
        Score(39), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:L/E:U/CR:H/IR:L/AR:M/MAV:N/MAC:L/MAT:X/MPR:L/MUI:X/MVC:X/MVI:N/MVA:H/MSC:X/MSI:L/MSA:L", // val
        101221, // exp mv
        Score(23), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:L/SI:H/SA:N/E:U/CR:H/IR:L/AR:M/MAV:N/MAC:X/MAT:N/MPR:X/MUI:P/MVC:L/MVI:L/MVA:X/MSC:N/MSI:N/MSA:L", // val
        111221, // exp mv
        Score(15), // exp score
      ), (
        "test 7.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:L/SA:L/E:U/CR:L/IR:H/AR:L/MAV:N/MAC:H/MAT:P/MPR:N/MUI:A/MVC:H/MVI:H/MVA:X/MSC:H/MSI:S/MSA:H", // val
        110020, // exp mv
        Score(73), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:H/SC:L/SI:H/SA:N/E:P/CR:X/IR:L/AR:H/MAV:N/MAC:H/MAT:P/MPR:H/MUI:P/MVC:H/MVI:N/MVA:L/MSC:X/MSI:S/MSA:L", // val
        111010, // exp mv
        Score(70), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:L/SC:N/SI:L/SA:H/E:P/CR:X/IR:L/AR:M/MAV:X/MAC:X/MAT:P/MPR:H/MUI:N/MVC:L/MVI:H/MVA:X/MSC:L/MSI:N/MSA:X", // val
        211111, // exp mv
        Score(15), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:N/SA:L/E:X/CR:X/IR:M/AR:X/MAV:A/MAC:X/MAT:N/MPR:H/MUI:P/MVC:H/MVI:L/MVA:X/MSC:L/MSI:L/MSA:L", // val
        211200, // exp mv
        Score(44), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:L/VI:H/VA:L/SC:H/SI:L/SA:N/E:X/CR:M/IR:X/AR:H/MAV:N/MAC:X/MAT:N/MPR:H/MUI:P/MVC:H/MVI:L/MVA:N/MSC:X/MSI:L/MSA:X", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:L/VI:H/VA:L/SC:L/SI:H/SA:N/E:P/CR:M/IR:M/AR:L/MAV:L/MAC:L/MAT:N/MPR:H/MUI:N/MVC:N/MVI:N/MVA:N/MSC:X/MSI:N/MSA:H", // val
        102111, // exp mv
        Score(46), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:L/E:A/CR:M/IR:M/AR:X/MAV:L/MAC:X/MAT:P/MPR:X/MUI:P/MVC:H/MVI:L/MVA:X/MSC:L/MSI:X/MSA:N", // val
        111201, // exp mv
        Score(44), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:L/SC:L/SI:N/SA:L/E:U/CR:L/IR:L/AR:H/MAV:A/MAC:X/MAT:X/MPR:N/MUI:N/MVC:N/MVI:H/MVA:N/MSC:H/MSI:H/MSA:X", // val
        111121, // exp mv
        Score(21), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:H/SI:H/SA:N/E:A/CR:H/IR:M/AR:X/MAV:X/MAC:L/MAT:P/MPR:X/MUI:A/MVC:L/MVI:N/MVA:N/MSC:N/MSI:N/MSA:H", // val
        212101, // exp mv
        Score(18), // exp score
      ), (
        "test 6.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:H/SI:L/SA:L/E:P/CR:X/IR:M/AR:L/MAV:L/MAC:X/MAT:N/MPR:N/MUI:X/MVC:N/MVI:H/MVA:L/MSC:X/MSI:S/MSA:N", // val
        111011, // exp mv
        Score(62), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H/E:P/CR:X/IR:L/AR:M/MAV:P/MAC:L/MAT:P/MPR:H/MUI:X/MVC:X/MVI:L/MVA:L/MSC:X/MSI:S/MSA:X", // val
        212011, // exp mv
        Score(23), // exp score
      ), (
        "test 6.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:N/SC:N/SI:L/SA:L/E:X/CR:L/IR:X/AR:H/MAV:X/MAC:L/MAT:N/MPR:N/MUI:N/MVC:X/MVI:H/MVA:X/MSC:N/MSI:L/MSA:N", // val
        200200, // exp mv
        Score(67), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:N/VA:L/SC:L/SI:N/SA:H/E:X/CR:M/IR:M/AR:X/MAV:N/MAC:L/MAT:P/MPR:N/MUI:N/MVC:N/MVI:X/MVA:X/MSC:L/MSI:X/MSA:X", // val
        012101, // exp mv
        Score(69), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:L/SC:L/SI:H/SA:N/E:X/CR:M/IR:M/AR:H/MAV:X/MAC:H/MAT:X/MPR:H/MUI:P/MVC:N/MVI:L/MVA:L/MSC:L/MSI:H/MSA:S", // val
        212001, // exp mv
        Score(48), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:H/SI:N/SA:H/E:P/CR:M/IR:H/AR:M/MAV:X/MAC:H/MAT:X/MPR:X/MUI:P/MVC:X/MVI:H/MVA:H/MSC:H/MSI:S/MSA:H", // val
        211010, // exp mv
        Score(56), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:N/SI:L/SA:N/E:U/CR:X/IR:X/AR:M/MAV:N/MAC:X/MAT:P/MPR:L/MUI:A/MVC:H/MVI:X/MVA:N/MSC:H/MSI:X/MSA:N", // val
        110120, // exp mv
        Score(55), // exp score
      ), (
        "test 3.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N/E:A/CR:X/IR:L/AR:M/MAV:P/MAC:X/MAT:P/MPR:L/MUI:A/MVC:N/MVI:X/MVA:X/MSC:N/MSI:N/MSA:H", // val
        211101, // exp mv
        Score(38), // exp score
      ), (
        "test 0.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:H/SC:L/SI:N/SA:L/E:U/CR:L/IR:X/AR:H/MAV:X/MAC:L/MAT:N/MPR:N/MUI:N/MVC:N/MVI:L/MVA:N/MSC:X/MSI:N/MSA:L", // val
        202221, // exp mv
        Score(4), // exp score
      ), (
        "test 3.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:H/VA:L/SC:H/SI:N/SA:H/E:U/CR:H/IR:X/AR:M/MAV:L/MAC:L/MAT:X/MPR:L/MUI:A/MVC:H/MVI:X/MVA:H/MSC:H/MSI:L/MSA:N", // val
        210120, // exp mv
        Score(33), // exp score
      ), (
        "test 1.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:L/E:U/CR:L/IR:H/AR:M/MAV:X/MAC:H/MAT:P/MPR:H/MUI:X/MVC:X/MVI:H/MVA:H/MSC:L/MSI:N/MSA:H", // val
        211120, // exp mv
        Score(14), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:H/SI:L/SA:N/E:X/CR:M/IR:M/AR:X/MAV:A/MAC:L/MAT:N/MPR:X/MUI:P/MVC:H/MVI:N/MVA:X/MSC:H/MSI:S/MSA:N", // val
        201001, // exp mv
        Score(72), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:A/CR:H/IR:M/AR:M/MAV:A/MAC:H/MAT:X/MPR:H/MUI:X/MVC:X/MVI:H/MVA:X/MSC:N/MSI:S/MSA:S", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:H/VI:L/VA:H/SC:H/SI:N/SA:L/E:P/CR:L/IR:X/AR:X/MAV:N/MAC:X/MAT:P/MPR:X/MUI:A/MVC:X/MVI:X/MVA:H/MSC:N/MSI:X/MSA:L", // val
        111210, // exp mv
        Score(45), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:H/VI:L/VA:L/SC:N/SI:H/SA:H/E:P/CR:L/IR:M/AR:L/MAV:P/MAC:X/MAT:N/MPR:L/MUI:P/MVC:X/MVI:H/MVA:X/MSC:N/MSI:L/MSA:N", // val
        210211, // exp mv
        Score(18), // exp score
      ), (
        "test 0.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:L/MAC:X/MAT:P/MPR:L/MUI:P/MVC:X/MVI:N/MVA:X/MSC:N/MSI:X/MSA:X", // val
        211221, // exp mv
        Score(1), // exp score
      ), (
        "test 4.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:L/SC:H/SI:L/SA:N/E:P/CR:H/IR:M/AR:H/MAV:N/MAC:L/MAT:X/MPR:N/MUI:X/MVC:X/MVI:N/MVA:X/MSC:X/MSI:X/MSA:X", // val
        012111, // exp mv
        Score(47), // exp score
      ), (
        "test 0.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N/E:P/CR:L/IR:H/AR:X/MAV:X/MAC:H/MAT:N/MPR:L/MUI:N/MVC:N/MVI:L/MVA:N/MSC:N/MSI:X/MSA:H", // val
        212111, // exp mv
        Score(8), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:L/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:L/IR:H/AR:M/MAV:P/MAC:H/MAT:X/MPR:X/MUI:N/MVC:N/MVI:X/MVA:X/MSC:N/MSI:L/MSA:H", // val
        211100, // exp mv
        Score(56), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:L/VI:H/VA:N/SC:H/SI:N/SA:L/E:P/CR:H/IR:M/AR:X/MAV:L/MAC:H/MAT:P/MPR:H/MUI:X/MVC:H/MVI:H/MVA:H/MSC:X/MSI:N/MSA:L", // val
        210110, // exp mv
        Score(56), // exp score
      ), (
        "test 1.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:L/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:L/IR:H/AR:M/MAV:N/MAC:H/MAT:P/MPR:H/MUI:P/MVC:N/MVI:X/MVA:N/MSC:H/MSI:X/MSA:L", // val
        112121, // exp mv
        Score(12), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:L/VI:N/VA:L/SC:H/SI:H/SA:N/E:A/CR:L/IR:X/AR:L/MAV:A/MAC:L/MAT:X/MPR:N/MUI:N/MVC:L/MVI:L/MVA:N/MSC:H/MSI:L/MSA:N", // val
        112101, // exp mv
        Score(51), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:N/VI:H/VA:H/SC:H/SI:H/SA:H/E:X/CR:X/IR:H/AR:H/MAV:P/MAC:L/MAT:P/MPR:X/MUI:N/MVC:H/MVI:N/MVA:L/MSC:N/MSI:N/MSA:S", // val
        211000, // exp mv
        Score(69), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:N/VI:N/VA:L/SC:N/SI:H/SA:L/E:A/CR:X/IR:M/AR:L/MAV:L/MAC:H/MAT:P/MPR:H/MUI:N/MVC:X/MVI:N/MVA:L/MSC:H/MSI:L/MSA:X", // val
        112101, // exp mv
        Score(45), // exp score
      ), (
        "test 4.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:H/VI:H/VA:L/SC:L/SI:L/SA:H/E:X/CR:M/IR:M/AR:H/MAV:X/MAC:X/MAT:X/MPR:L/MUI:P/MVC:X/MVI:N/MVA:X/MSC:H/MSI:H/MSA:L", // val
        211101, // exp mv
        Score(47), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U/CR:X/IR:H/AR:X/MAV:X/MAC:H/MAT:N/MPR:L/MUI:A/MVC:X/MVI:X/MVA:X/MSC:X/MSI:S/MSA:S", // val
        210020, // exp mv
        Score(55), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:N/SC:H/SI:H/SA:N/E:X/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:N/MVC:X/MVI:L/MVA:N/MSC:H/MSI:N/MSA:L", // val
        111101, // exp mv
        Score(58), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N/E:P/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:X/MPR:N/MUI:X/MVC:L/MVI:L/MVA:H/MSC:L/MSI:X/MSA:X", // val
        211211, // exp mv
        Score(6), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:L/VI:H/VA:L/SC:H/SI:L/SA:H/E:P/CR:L/IR:X/AR:H/MAV:N/MAC:H/MAT:X/MPR:H/MUI:P/MVC:H/MVI:X/MVA:N/MSC:H/MSI:S/MSA:H", // val
        110010, // exp mv
        Score(84), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:L/VI:H/VA:N/SC:H/SI:N/SA:H/E:X/CR:M/IR:H/AR:L/MAV:X/MAC:H/MAT:N/MPR:L/MUI:X/MVC:N/MVI:X/MVA:H/MSC:L/MSI:N/MSA:S", // val
        211000, // exp mv
        Score(69), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:L/VI:L/VA:L/SC:N/SI:H/SA:L/E:A/CR:H/IR:M/AR:H/MAV:P/MAC:X/MAT:N/MPR:N/MUI:X/MVC:L/MVI:L/MVA:L/MSC:L/MSI:L/MSA:X", // val
        212201, // exp mv
        Score(10), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:L/VI:L/VA:L/SC:N/SI:H/SA:N/E:P/CR:M/IR:X/AR:M/MAV:N/MAC:L/MAT:P/MPR:L/MUI:P/MVC:L/MVI:H/MVA:X/MSC:H/MSI:H/MSA:L", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:L/VI:L/VA:L/SC:N/SI:N/SA:H/E:P/CR:H/IR:M/AR:X/MAV:L/MAC:L/MAT:P/MPR:H/MUI:X/MVC:N/MVI:X/MVA:L/MSC:H/MSI:X/MSA:S", // val
        212011, // exp mv
        Score(21), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:L/VI:N/VA:H/SC:L/SI:L/SA:H/E:X/CR:X/IR:L/AR:L/MAV:P/MAC:L/MAT:X/MPR:L/MUI:N/MVC:X/MVI:X/MVA:N/MSC:H/MSI:L/MSA:H", // val
        212101, // exp mv
        Score(23), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:N/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:X/IR:M/AR:H/MAV:A/MAC:L/MAT:P/MPR:X/MUI:A/MVC:N/MVI:H/MVA:H/MSC:X/MSI:X/MSA:X", // val
        211120, // exp mv
        Score(19), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:N/VI:H/VA:L/SC:L/SI:N/SA:N/E:P/CR:H/IR:M/AR:L/MAV:P/MAC:L/MAT:X/MPR:X/MUI:A/MVC:L/MVI:N/MVA:H/MSC:L/MSI:H/MSA:L", // val
        211111, // exp mv
        Score(16), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:H/SC:L/SI:H/SA:L/E:U/CR:H/IR:X/AR:H/MAV:A/MAC:X/MAT:N/MPR:H/MUI:N/MVC:N/MVI:L/MVA:X/MSC:H/MSI:H/MSA:H", // val
        111120, // exp mv
        Score(41), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:L/SC:L/SI:N/SA:L/E:X/CR:X/IR:X/AR:H/MAV:N/MAC:H/MAT:N/MPR:H/MUI:P/MVC:N/MVI:L/MVA:N/MSC:N/MSI:X/MSA:X", // val
        112201, // exp mv
        Score(20), // exp score
      ), (
        "test 5.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:L/SC:N/SI:N/SA:L/E:X/CR:M/IR:L/AR:L/MAV:L/MAC:X/MAT:X/MPR:H/MUI:A/MVC:N/MVI:L/MVA:L/MSC:H/MSI:S/MSA:H", // val
        212001, // exp mv
        Score(51), // exp score
      ), (
        "test 7.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:L/SA:N/E:X/CR:X/IR:L/AR:L/MAV:N/MAC:X/MAT:N/MPR:N/MUI:N/MVC:N/MVI:H/MVA:H/MSC:L/MSI:H/MSA:N", // val
        011101, // exp mv
        Score(79), // exp score
      ), (
        "test 6.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:H/VI:N/VA:H/SC:L/SI:H/SA:L/E:A/CR:M/IR:H/AR:L/MAV:A/MAC:X/MAT:P/MPR:L/MUI:N/MVC:L/MVI:N/MVA:L/MSC:N/MSI:S/MSA:N", // val
        112001, // exp mv
        Score(66), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:H/VI:N/VA:L/SC:L/SI:H/SA:N/E:U/CR:X/IR:X/AR:H/MAV:N/MAC:L/MAT:N/MPR:H/MUI:P/MVC:N/MVI:N/MVA:X/MSC:X/MSI:N/MSA:H", // val
        102121, // exp mv
        Score(21), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:H/SC:H/SI:N/SA:H/E:A/CR:X/IR:X/AR:M/MAV:X/MAC:H/MAT:N/MPR:N/MUI:P/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:N", // val
        211000, // exp mv
        Score(69), // exp score
      ), (
        "test 9.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:N/SC:H/SI:H/SA:H/E:X/CR:H/IR:X/AR:H/MAV:N/MAC:H/MAT:P/MPR:N/MUI:N/MVC:H/MVI:N/MVA:L/MSC:X/MSI:H/MSA:S", // val
        011000, // exp mv
        Score(95), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:L/VI:N/VA:N/SC:H/SI:N/SA:N/E:X/CR:H/IR:M/AR:L/MAV:N/MAC:X/MAT:X/MPR:H/MUI:X/MVC:H/MVI:H/MVA:H/MSC:L/MSI:H/MSA:N", // val
        110100, // exp mv
        Score(85), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:L/VI:N/VA:N/SC:L/SI:H/SA:H/E:P/CR:L/IR:H/AR:X/MAV:L/MAC:H/MAT:X/MPR:H/MUI:N/MVC:N/MVI:N/MVA:X/MSC:L/MSI:N/MSA:S", // val
        112011, // exp mv
        Score(43), // exp score
      ), (
        "test 6.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:H/SI:N/SA:N/E:P/CR:M/IR:M/AR:M/MAV:L/MAC:H/MAT:N/MPR:H/MUI:N/MVC:N/MVI:N/MVA:H/MSC:H/MSI:N/MSA:S", // val
        111011, // exp mv
        Score(61), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:N/VI:N/VA:L/SC:N/SI:L/SA:N/E:U/CR:M/IR:L/AR:M/MAV:A/MAC:H/MAT:P/MPR:N/MUI:N/MVC:N/MVI:L/MVA:N/MSC:X/MSI:L/MSA:X", // val
        112221, // exp mv
        Score(6), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:H/VI:H/VA:L/SC:H/SI:N/SA:L/E:A/CR:M/IR:M/AR:H/MAV:L/MAC:H/MAT:N/MPR:L/MUI:X/MVC:X/MVI:L/MVA:H/MSC:N/MSI:S/MSA:X", // val
        211000, // exp mv
        Score(70), // exp score
      ), (
        "test 7.4", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:H/VI:L/VA:H/SC:L/SI:N/SA:H/E:A/CR:M/IR:M/AR:L/MAV:A/MAC:X/MAT:X/MPR:X/MUI:N/MVC:L/MVI:N/MVA:X/MSC:L/MSI:S/MSA:N", // val
        111001, // exp mv
        Score(74), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:H/VI:N/VA:L/SC:H/SI:N/SA:L/E:A/CR:M/IR:M/AR:L/MAV:N/MAC:X/MAT:P/MPR:N/MUI:X/MVC:H/MVI:L/MVA:N/MSC:N/MSI:S/MSA:N", // val
        111001, // exp mv
        Score(72), // exp score
      ), (
        "test 5.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:H/SC:N/SI:H/SA:H/E:X/CR:L/IR:X/AR:M/MAV:A/MAC:H/MAT:N/MPR:X/MUI:X/MVC:L/MVI:X/MVA:L/MSC:H/MSI:H/MSA:H", // val
        112101, // exp mv
        Score(52), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:L/SC:L/SI:H/SA:L/E:P/CR:X/IR:M/AR:M/MAV:N/MAC:L/MAT:P/MPR:X/MUI:P/MVC:N/MVI:X/MVA:X/MSC:X/MSI:N/MSA:H", // val
        112111, // exp mv
        Score(23), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:L/SC:N/SI:H/SA:L/E:U/CR:X/IR:X/AR:H/MAV:P/MAC:H/MAT:X/MPR:X/MUI:X/MVC:N/MVI:N/MVA:N/MSC:H/MSI:S/MSA:L", // val
        212021, // exp mv
        Score(11), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:L/SC:N/SI:L/SA:L/E:X/CR:M/IR:X/AR:H/MAV:P/MAC:L/MAT:X/MPR:N/MUI:N/MVC:X/MVI:N/MVA:H/MSC:N/MSI:N/MSA:X", // val
        211200, // exp mv
        Score(39), // exp score
      ), (
        "test 0.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:N/VI:N/VA:H/SC:N/SI:H/SA:L/E:U/CR:M/IR:L/AR:L/MAV:P/MAC:X/MAT:N/MPR:H/MUI:N/MVC:X/MVI:L/MVA:L/MSC:H/MSI:N/MSA:X", // val
        212121, // exp mv
        Score(3), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:L/E:A/CR:X/IR:L/AR:M/MAV:X/MAC:L/MAT:N/MPR:N/MUI:X/MVC:N/MVI:X/MVA:H/MSC:H/MSI:N/MSA:X", // val
        201101, // exp mv
        Score(53), // exp score
      ), (
        "test 8.6", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:N/SI:L/SA:L/E:X/CR:H/IR:M/AR:H/MAV:L/MAC:H/MAT:X/MPR:N/MUI:X/MVC:N/MVI:L/MVA:X/MSC:L/MSI:H/MSA:S", // val
        111000, // exp mv
        Score(86), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:L/SI:H/SA:H/E:X/CR:M/IR:X/AR:X/MAV:X/MAC:L/MAT:X/MPR:L/MUI:X/MVC:H/MVI:H/MVA:L/MSC:X/MSI:H/MSA:L", // val
        210100, // exp mv
        Score(69), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:L/SI:N/SA:N/E:P/CR:X/IR:X/AR:M/MAV:P/MAC:X/MAT:P/MPR:N/MUI:A/MVC:X/MVI:X/MVA:N/MSC:N/MSI:X/MSA:N", // val
        211210, // exp mv
        Score(15), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N/E:P/CR:L/IR:H/AR:L/MAV:P/MAC:H/MAT:N/MPR:X/MUI:X/MVC:L/MVI:N/MVA:X/MSC:H/MSI:X/MSA:N", // val
        212111, // exp mv
        Score(10), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:L/SC:L/SI:H/SA:L/E:P/CR:X/IR:H/AR:X/MAV:A/MAC:H/MAT:P/MPR:N/MUI:N/MVC:X/MVI:H/MVA:H/MSC:N/MSI:L/MSA:X", // val
        111210, // exp mv
        Score(57), // exp score
      ), (
        "test 4.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:N/VI:H/VA:L/SC:H/SI:H/SA:H/E:X/CR:X/IR:L/AR:X/MAV:X/MAC:X/MAT:N/MPR:X/MUI:P/MVC:X/MVI:H/MVA:X/MSC:X/MSI:H/MSA:L", // val
        211101, // exp mv
        Score(47), // exp score
      ), (
        "test 4.1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:L/SC:L/SI:L/SA:N/E:P/CR:H/IR:H/AR:X/MAV:L/MAC:L/MAT:P/MPR:H/MUI:P/MVC:N/MVI:H/MVA:L/MSC:N/MSI:H/MSA:H", // val
        211110, // exp mv
        Score(41), // exp score
      ), (
        "test 3.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:H/SA:H/E:P/CR:M/IR:M/AR:H/MAV:P/MAC:H/MAT:P/MPR:X/MUI:A/MVC:N/MVI:X/MVA:X/MSC:N/MSI:H/MSA:N", // val
        211110, // exp mv
        Score(33), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:N/SA:N/E:X/CR:L/IR:L/AR:M/MAV:X/MAC:H/MAT:P/MPR:L/MUI:A/MVC:L/MVI:H/MVA:L/MSC:X/MSI:N/MSA:L", // val
        211101, // exp mv
        Score(40), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:X/MAV:X/MAC:L/MAT:X/MPR:L/MUI:N/MVC:L/MVI:N/MVA:X/MSC:H/MSI:L/MSA:L", // val
        212111, // exp mv
        Score(10), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:H/VI:L/VA:N/SC:L/SI:H/SA:N/E:U/CR:M/IR:H/AR:M/MAV:N/MAC:H/MAT:N/MPR:X/MUI:X/MVC:L/MVI:H/MVA:H/MSC:N/MSI:S/MSA:H", // val
        111020, // exp mv
        Score(59), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/SC:H/SI:H/SA:L/E:P/CR:X/IR:L/AR:M/MAV:N/MAC:X/MAT:N/MPR:N/MUI:X/MVC:X/MVI:H/MVA:N/MSC:H/MSI:H/MSA:L", // val
        110110, // exp mv
        Score(72), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:L/VI:H/VA:N/SC:L/SI:N/SA:N/E:P/CR:X/IR:M/AR:X/MAV:X/MAC:H/MAT:X/MPR:H/MUI:N/MVC:H/MVI:X/MVA:H/MSC:L/MSI:H/MSA:L", // val
        210110, // exp mv
        Score(57), // exp score
      ), (
        "test 2.2", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:H/AR:H/MAV:N/MAC:H/MAT:N/MPR:X/MUI:X/MVC:L/MVI:H/MVA:X/MSC:X/MSI:N/MSA:L", // val
        111220, // exp mv
        Score(22), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L/E:P/CR:M/IR:X/AR:L/MAV:L/MAC:L/MAT:X/MPR:H/MUI:X/MVC:L/MVI:L/MVA:X/MSC:H/MSI:S/MSA:H", // val
        212011, // exp mv
        Score(23), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:N/SA:N/E:X/CR:M/IR:M/AR:L/MAV:X/MAC:H/MAT:P/MPR:H/MUI:P/MVC:N/MVI:X/MVA:X/MSC:L/MSI:N/MSA:X", // val
        211201, // exp mv
        Score(17), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:A/VC:H/VI:L/VA:L/SC:N/SI:H/SA:L/E:A/CR:X/IR:X/AR:H/MAV:N/MAC:H/MAT:N/MPR:X/MUI:A/MVC:X/MVI:N/MVA:H/MSC:X/MSI:H/MSA:S", // val
        111000, // exp mv
        Score(84), // exp score
      ), (
        "test 8.2", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:A/VC:H/VI:N/VA:H/SC:L/SI:H/SA:H/E:A/CR:X/IR:L/AR:H/MAV:L/MAC:L/MAT:X/MPR:X/MUI:N/MVC:H/MVI:N/MVA:N/MSC:X/MSI:H/MSA:H", // val
        101100, // exp mv
        Score(82), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:A/VC:H/VI:N/VA:L/SC:N/SI:L/SA:N/E:A/CR:H/IR:X/AR:H/MAV:P/MAC:L/MAT:N/MPR:N/MUI:P/MVC:H/MVI:X/MVA:X/MSC:X/MSI:H/MSA:S", // val
        201000, // exp mv
        Score(83), // exp score
      ), (
        "test 8.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:A/VC:L/VI:N/VA:H/SC:H/SI:N/SA:N/E:U/CR:X/IR:L/AR:L/MAV:N/MAC:L/MAT:X/MPR:H/MUI:P/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:N", // val
        100020, // exp mv
        Score(86), // exp score
      ), (
        "test 8.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:A/VC:L/VI:N/VA:L/SC:N/SI:L/SA:N/E:A/CR:H/IR:X/AR:M/MAV:N/MAC:L/MAT:X/MPR:N/MUI:X/MVC:X/MVI:X/MVA:H/MSC:N/MSI:S/MSA:X", // val
        101001, // exp mv
        Score(86), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:A/VC:N/VI:H/VA:L/SC:N/SI:H/SA:L/E:X/CR:L/IR:H/AR:H/MAV:X/MAC:L/MAT:X/MPR:X/MUI:P/MVC:L/MVI:L/MVA:L/MSC:X/MSI:H/MSA:H", // val
        202101, // exp mv
        Score(44), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:A/VC:N/VI:L/VA:N/SC:L/SI:N/SA:H/E:A/CR:L/IR:X/AR:H/MAV:N/MAC:L/MAT:P/MPR:N/MUI:P/MVC:N/MVI:N/MVA:L/MSC:N/MSI:L/MSA:L", // val
        112201, // exp mv
        Score(23), // exp score
      ), (
        "test 8.2", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:L/SC:N/SI:H/SA:L/E:X/CR:L/IR:M/AR:X/MAV:P/MAC:X/MAT:N/MPR:X/MUI:P/MVC:L/MVI:N/MVA:H/MSC:N/MSI:H/MSA:S", // val
        201000, // exp mv
        Score(82), // exp score
      ), (
        "test 9.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:H/VI:L/VA:L/SC:L/SI:N/SA:L/E:X/CR:X/IR:M/AR:X/MAV:N/MAC:L/MAT:N/MPR:N/MUI:X/MVC:N/MVI:X/MVA:H/MSC:H/MSI:L/MSA:X", // val
        001100, // exp mv
        Score(93), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/E:P/CR:X/IR:M/AR:M/MAV:A/MAC:H/MAT:N/MPR:L/MUI:A/MVC:N/MVI:N/MVA:L/MSC:N/MSI:L/MSA:S", // val
        212011, // exp mv
        Score(20), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:H/VI:L/VA:N/SC:N/SI:H/SA:N/E:A/CR:M/IR:X/AR:X/MAV:P/MAC:X/MAT:X/MPR:H/MUI:P/MVC:N/MVI:N/MVA:L/MSC:X/MSI:L/MSA:N", // val
        202201, // exp mv
        Score(24), // exp score
      ), (
        "test 1.7", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:L/E:X/CR:M/IR:H/AR:L/MAV:X/MAC:L/MAT:P/MPR:H/MUI:A/MVC:L/MVI:L/MVA:H/MSC:X/MSI:L/MSA:X", // val
        211201, // exp mv
        Score(17), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:L/VI:N/VA:H/SC:H/SI:H/SA:L/E:X/CR:M/IR:L/AR:X/MAV:P/MAC:H/MAT:X/MPR:X/MUI:P/MVC:N/MVI:N/MVA:N/MSC:H/MSI:S/MSA:X", // val
        212001, // exp mv
        Score(48), // exp score
      ), (
        "test 0.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:L/SC:H/SI:N/SA:H/E:U/CR:H/IR:M/AR:X/MAV:P/MAC:H/MAT:N/MPR:L/MUI:N/MVC:L/MVI:H/MVA:X/MSC:H/MSI:H/MSA:N", // val
        211121, // exp mv
        Score(8), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H/E:X/CR:H/IR:X/AR:X/MAV:A/MAC:L/MAT:N/MPR:X/MUI:P/MVC:X/MVI:H/MVA:N/MSC:L/MSI:S/MSA:S", // val
        201000, // exp mv
        Score(84), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:P/VC:H/VI:H/VA:L/SC:L/SI:L/SA:N/E:A/CR:L/IR:X/AR:L/MAV:N/MAC:H/MAT:X/MPR:N/MUI:X/MVC:L/MVI:X/MVA:L/MSC:N/MSI:L/MSA:X", // val
        111200, // exp mv
        Score(59), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:P/VC:H/VI:N/VA:L/SC:H/SI:L/SA:H/E:A/CR:H/IR:L/AR:L/MAV:X/MAC:L/MAT:P/MPR:X/MUI:A/MVC:H/MVI:L/MVA:N/MSC:X/MSI:S/MSA:S", // val
        211000, // exp mv
        Score(70), // exp score
      ), (
        "test 3.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:P/VC:L/VI:N/VA:N/SC:L/SI:H/SA:N/E:U/CR:X/IR:X/AR:H/MAV:P/MAC:H/MAT:X/MPR:H/MUI:A/MVC:H/MVI:L/MVA:X/MSC:N/MSI:S/MSA:L", // val
        211020, // exp mv
        Score(31), // exp score
      ), (
        "test 7.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:P/VC:L/VI:N/VA:N/SC:L/SI:N/SA:H/E:X/CR:H/IR:M/AR:L/MAV:N/MAC:X/MAT:X/MPR:H/MUI:N/MVC:X/MVI:X/MVA:X/MSC:X/MSI:S/MSA:N", // val
        102001, // exp mv
        Score(79), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:P/VC:N/VI:H/VA:L/SC:H/SI:H/SA:H/E:X/CR:X/IR:H/AR:L/MAV:X/MAC:H/MAT:P/MPR:H/MUI:X/MVC:L/MVI:X/MVA:N/MSC:H/MSI:S/MSA:N", // val
        211000, // exp mv
        Score(69), // exp score
      ), (
        "test 2.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:P/VC:N/VI:H/VA:L/SC:L/SI:L/SA:N/E:U/CR:X/IR:M/AR:X/MAV:N/MAC:H/MAT:N/MPR:X/MUI:N/MVC:X/MVI:L/MVA:L/MSC:X/MSI:S/MSA:H", // val
        112021, // exp mv
        Score(26), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:H/VI:L/VA:L/SC:L/SI:L/SA:H/E:P/CR:H/IR:H/AR:H/MAV:N/MAC:H/MAT:N/MPR:N/MUI:X/MVC:H/MVI:X/MVA:N/MSC:X/MSI:H/MSA:N", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:H/VI:N/VA:H/SC:L/SI:N/SA:H/E:X/CR:L/IR:L/AR:L/MAV:P/MAC:L/MAT:N/MPR:N/MUI:A/MVC:N/MVI:L/MVA:H/MSC:N/MSI:S/MSA:N", // val
        201001, // exp mv
        Score(69), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:H/VI:N/VA:N/SC:H/SI:L/SA:H/E:A/CR:L/IR:L/AR:L/MAV:A/MAC:X/MAT:X/MPR:X/MUI:X/MVC:H/MVI:N/MVA:L/MSC:H/MSI:S/MSA:H", // val
        201001, // exp mv
        Score(72), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:X/CR:X/IR:H/AR:L/MAV:P/MAC:X/MAT:P/MPR:N/MUI:N/MVC:H/MVI:N/MVA:H/MSC:H/MSI:L/MSA:S", // val
        211000, // exp mv
        Score(71), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:H/E:A/CR:H/IR:M/AR:H/MAV:A/MAC:H/MAT:P/MPR:L/MUI:X/MVC:N/MVI:H/MVA:X/MSC:X/MSI:L/MSA:H", // val
        211101, // exp mv
        Score(44), // exp score
      ), (
        "test 7.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:L/VI:N/VA:H/SC:L/SI:N/SA:L/E:A/CR:L/IR:H/AR:L/MAV:N/MAC:X/MAT:X/MPR:N/MUI:N/MVC:X/MVI:X/MVA:L/MSC:H/MSI:H/MSA:L", // val
        002101, // exp mv
        Score(79), // exp score
      ), (
        "test 1.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:N/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:X/AR:X/MAV:L/MAC:H/MAT:P/MPR:L/MUI:X/MVC:X/MVI:N/MVA:H/MSC:H/MSI:N/MSA:H", // val
        211120, // exp mv
        Score(16), // exp score
      ), (
        "test 4.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:L/SA:L/E:U/CR:L/IR:X/AR:X/MAV:P/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:L/MVA:X/MSC:N/MSI:S/MSA:H", // val
        201021, // exp mv
        Score(44), // exp score
      ), (
        "test 2.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:L/SA:N/E:U/CR:M/IR:X/AR:L/MAV:A/MAC:H/MAT:P/MPR:L/MUI:N/MVC:L/MVI:L/MVA:N/MSC:H/MSI:S/MSA:L", // val
        112021, // exp mv
        Score(26), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:H/E:P/CR:H/IR:X/AR:L/MAV:N/MAC:X/MAT:X/MPR:L/MUI:A/MVC:X/MVI:X/MVA:N/MSC:L/MSI:L/MSA:X", // val
        101110, // exp mv
        Score(69), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:L/SC:H/SI:N/SA:L/E:X/CR:M/IR:H/AR:H/MAV:X/MAC:L/MAT:N/MPR:L/MUI:N/MVC:L/MVI:N/MVA:L/MSC:L/MSI:L/MSA:N", // val
        202201, // exp mv
        Score(24), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:H/SA:L/E:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MAT:P/MPR:N/MUI:A/MVC:H/MVI:H/MVA:X/MSC:N/MSI:H/MSA:N", // val
        210121, // exp mv
        Score(15), // exp score
      ), (
        "test 1.5", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:H/SC:L/SI:H/SA:L/E:U/CR:H/IR:M/AR:M/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:N/MVA:X/MSC:N/MSI:N/MSA:H", // val
        201121, // exp mv
        Score(15), // exp score
      ), (
        "test 9.2", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:N/SC:L/SI:N/SA:H/E:A/CR:H/IR:X/AR:H/MAV:L/MAC:L/MAT:N/MPR:N/MUI:A/MVC:H/MVI:H/MVA:L/MSC:H/MSI:N/MSA:H", // val
        100100, // exp mv
        Score(92), // exp score
      ), (
        "test 7.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:H/SC:L/SI:N/SA:L/E:A/CR:M/IR:X/AR:X/MAV:X/MAC:X/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:N/MSC:H/MSI:H/MSA:S", // val
        201001, // exp mv
        Score(74), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:H/E:P/CR:L/IR:M/AR:H/MAV:L/MAC:H/MAT:N/MPR:N/MUI:X/MVC:H/MVI:X/MVA:H/MSC:H/MSI:H/MSA:L", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 4.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:N/VI:L/VA:H/SC:L/SI:N/SA:H/E:P/CR:H/IR:H/AR:L/MAV:P/MAC:L/MAT:X/MPR:X/MUI:X/MVC:X/MVI:H/MVA:X/MSC:N/MSI:H/MSA:N", // val
        201110, // exp mv
        Score(49), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/E:U/CR:L/IR:X/AR:H/MAV:X/MAC:H/MAT:N/MPR:X/MUI:N/MVC:H/MVI:L/MVA:L/MSC:L/MSI:S/MSA:S", // val
        211021, // exp mv
        Score(20), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:L/SC:H/SI:N/SA:L/E:U/CR:X/IR:X/AR:X/MAV:A/MAC:X/MAT:N/MPR:H/MUI:N/MVC:H/MVI:L/MVA:N/MSC:N/MSI:S/MSA:L", // val
        101020, // exp mv
        Score(71), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:L/SC:N/SI:L/SA:N/E:X/CR:L/IR:H/AR:L/MAV:L/MAC:H/MAT:P/MPR:X/MUI:P/MVC:N/MVI:L/MVA:N/MSC:X/MSI:L/MSA:X", // val
        112201, // exp mv
        Score(20), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:H/SC:H/SI:N/SA:L/E:X/CR:L/IR:H/AR:H/MAV:P/MAC:H/MAT:P/MPR:X/MUI:A/MVC:L/MVI:N/MVA:N/MSC:H/MSI:X/MSA:L", // val
        212101, // exp mv
        Score(20), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:L/SC:H/SI:H/SA:H/E:A/CR:M/IR:X/AR:M/MAV:P/MAC:X/MAT:P/MPR:H/MUI:N/MVC:L/MVI:X/MVA:N/MSC:H/MSI:S/MSA:X", // val
        211000, // exp mv
        Score(71), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:H/SI:H/SA:L/E:X/CR:H/IR:X/AR:H/MAV:N/MAC:L/MAT:N/MPR:L/MUI:X/MVC:N/MVI:X/MVA:L/MSC:L/MSI:N/MSA:N", // val
        102201, // exp mv
        Score(48), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:H/SC:N/SI:N/SA:L/E:X/CR:X/IR:H/AR:X/MAV:X/MAC:L/MAT:P/MPR:X/MUI:X/MVC:L/MVI:L/MVA:L/MSC:X/MSI:L/MSA:S", // val
        212001, // exp mv
        Score(43), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N/E:P/CR:H/IR:H/AR:L/MAV:P/MAC:X/MAT:X/MPR:X/MUI:A/MVC:X/MVI:X/MVA:N/MSC:N/MSI:N/MSA:S", // val
        201010, // exp mv
        Score(68), // exp score
      ), (
        "test 2.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:L/SA:N/E:X/CR:X/IR:L/AR:X/MAV:P/MAC:X/MAT:N/MPR:L/MUI:N/MVC:N/MVI:X/MVA:X/MSC:L/MSI:X/MSA:N", // val
        202201, // exp mv
        Score(24), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:N/SA:L/E:P/CR:X/IR:H/AR:M/MAV:X/MAC:H/MAT:X/MPR:L/MUI:N/MVC:L/MVI:L/MVA:L/MSC:N/MSI:H/MSA:L", // val
        212111, // exp mv
        Score(9), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:L/SA:H/E:U/CR:X/IR:X/AR:H/MAV:A/MAC:X/MAT:P/MPR:L/MUI:X/MVC:N/MVI:X/MVA:H/MSC:N/MSI:H/MSA:X", // val
        111120, // exp mv
        Score(40), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:H/SA:H/E:A/CR:M/IR:X/AR:L/MAV:N/MAC:H/MAT:N/MPR:X/MUI:P/MVC:N/MVI:X/MVA:L/MSC:L/MSI:S/MSA:X", // val
        112001, // exp mv
        Score(70), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:L/SC:H/SI:N/SA:N/E:P/CR:X/IR:H/AR:L/MAV:A/MAC:L/MAT:X/MPR:N/MUI:P/MVC:X/MVI:L/MVA:L/MSC:N/MSI:H/MSA:X", // val
        102111, // exp mv
        Score(48), // exp score
      ), (
        "test 4", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L/E:U/CR:M/IR:L/AR:M/MAV:X/MAC:L/MAT:P/MPR:H/MUI:P/MVC:H/MVI:X/MVA:L/MSC:L/MSI:S/MSA:H", // val
        210021, // exp mv
        Score(40), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:L/E:U/CR:H/IR:X/AR:L/MAV:A/MAC:X/MAT:X/MPR:N/MUI:A/MVC:L/MVI:H/MVA:L/MSC:N/MSI:L/MSA:S", // val
        101020, // exp mv
        Score(71), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:N/E:A/CR:H/IR:H/AR:H/MAV:P/MAC:L/MAT:X/MPR:N/MUI:A/MVC:H/MVI:H/MVA:L/MSC:X/MSI:X/MSA:N", // val
        200200, // exp mv
        Score(69), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:H/SC:N/SI:N/SA:L/E:X/CR:H/IR:X/AR:L/MAV:L/MAC:X/MAT:P/MPR:N/MUI:N/MVC:X/MVI:N/MVA:N/MSC:X/MSI:L/MSA:H", // val
        111100, // exp mv
        Score(69), // exp score
      ), (
        "test 0.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:L/SC:N/SI:H/SA:H/E:U/CR:M/IR:H/AR:H/MAV:X/MAC:L/MAT:P/MPR:X/MUI:N/MVC:H/MVI:L/MVA:X/MSC:H/MSI:L/MSA:L", // val
        211121, // exp mv
        Score(8), // exp score
      ), (
        "test 5.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:L/SA:L/E:P/CR:L/IR:L/AR:H/MAV:P/MAC:L/MAT:N/MPR:L/MUI:N/MVC:L/MVI:X/MVA:N/MSC:H/MSI:X/MSA:S", // val
        201011, // exp mv
        Score(53), // exp score
      ), (
        "test 7.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H/E:U/CR:L/IR:H/AR:H/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:X/MVA:X/MSC:L/MSI:S/MSA:H", // val
        110020, // exp mv
        Score(74), // exp score
      ), (
        "test 4.7", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:A/VC:H/VI:H/VA:L/SC:N/SI:L/SA:H/E:X/CR:H/IR:H/AR:X/MAV:N/MAC:H/MAT:N/MPR:H/MUI:A/MVC:N/MVI:N/MVA:L/MSC:H/MSI:X/MSA:H", // val
        112101, // exp mv
        Score(47), // exp score
      ), (
        "test 8.2", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:A/VC:H/VI:N/VA:H/SC:L/SI:L/SA:N/E:A/CR:M/IR:M/AR:H/MAV:N/MAC:L/MAT:N/MPR:L/MUI:A/MVC:H/MVI:L/MVA:H/MSC:N/MSI:N/MSA:H", // val
        101100, // exp mv
        Score(82), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:L/SI:N/SA:L/E:A/CR:X/IR:L/AR:H/MAV:A/MAC:H/MAT:P/MPR:X/MUI:A/MVC:X/MVI:L/MVA:X/MSC:L/MSI:H/MSA:H", // val
        212101, // exp mv
        Score(23), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:U/CR:X/IR:H/AR:X/MAV:L/MAC:X/MAT:P/MPR:N/MUI:P/MVC:X/MVI:H/MVA:L/MSC:H/MSI:S/MSA:S", // val
        111020, // exp mv
        Score(58), // exp score
      ), (
        "test 0.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:A/VC:L/VI:N/VA:L/SC:N/SI:N/SA:L/E:U/CR:H/IR:X/AR:M/MAV:N/MAC:H/MAT:P/MPR:N/MUI:P/MVC:N/MVI:L/MVA:L/MSC:L/MSI:X/MSA:L", // val
        112221, // exp mv
        Score(6), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:H/SI:N/SA:H/E:A/CR:L/IR:M/AR:H/MAV:P/MAC:H/MAT:N/MPR:N/MUI:X/MVC:X/MVI:L/MVA:H/MSC:N/MSI:H/MSA:L", // val
        211100, // exp mv
        Score(56), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N/E:A/CR:M/IR:M/AR:X/MAV:L/MAC:L/MAT:P/MPR:X/MUI:X/MVC:L/MVI:H/MVA:H/MSC:X/MSI:L/MSA:N", // val
        111200, // exp mv
        Score(56), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:A/CR:M/IR:L/AR:L/MAV:X/MAC:X/MAT:P/MPR:L/MUI:P/MVC:H/MVI:L/MVA:L/MSC:N/MSI:N/MSA:S", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 1.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:H/VI:N/VA:H/SC:L/SI:L/SA:N/E:A/CR:M/IR:M/AR:L/MAV:X/MAC:L/MAT:X/MPR:N/MUI:N/MVC:N/MVI:X/MVA:N/MSC:N/MSI:H/MSA:N", // val
        212101, // exp mv
        Score(18), // exp score
      ), (
        "test 8.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:L/VI:H/VA:N/SC:N/SI:L/SA:N/E:A/CR:H/IR:H/AR:X/MAV:L/MAC:L/MAT:N/MPR:L/MUI:P/MVC:X/MVI:H/MVA:L/MSC:H/MSI:H/MSA:S", // val
        201000, // exp mv
        Score(84), // exp score
      ), (
        "test 3.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:L/SA:L/E:A/CR:L/IR:L/AR:M/MAV:P/MAC:H/MAT:X/MPR:H/MUI:P/MVC:N/MVI:H/MVA:H/MSC:X/MSI:N/MSA:H", // val
        211101, // exp mv
        Score(38), // exp score
      ), (
        "test 6", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:L/VI:L/VA:N/SC:H/SI:N/SA:L/E:U/CR:H/IR:H/AR:X/MAV:N/MAC:L/MAT:X/MPR:L/MUI:N/MVC:L/MVI:H/MVA:L/MSC:N/MSI:S/MSA:S", // val
        111020, // exp mv
        Score(60), // exp score
      ), (
        "test 4.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:L/SI:H/SA:N/E:A/CR:H/IR:M/AR:X/MAV:L/MAC:L/MAT:X/MPR:N/MUI:X/MVC:N/MVI:L/MVA:N/MSC:H/MSI:N/MSA:N", // val
        112101, // exp mv
        Score(46), // exp score
      ), (
        "test 4.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:N/VI:H/VA:L/SC:L/SI:H/SA:N/E:P/CR:L/IR:M/AR:X/MAV:A/MAC:H/MAT:P/MPR:L/MUI:X/MVC:X/MVI:X/MVA:H/MSC:X/MSI:N/MSA:L", // val
        111210, // exp mv
        Score(49), // exp score
      ), (
        "test 5.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:N/VI:H/VA:N/SC:L/SI:H/SA:N/E:P/CR:L/IR:H/AR:L/MAV:A/MAC:X/MAT:P/MPR:L/MUI:X/MVC:X/MVI:X/MVA:L/MSC:H/MSI:H/MSA:N", // val
        111110, // exp mv
        Score(56), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:N/VI:N/VA:L/SC:L/SI:L/SA:N/E:A/CR:X/IR:L/AR:M/MAV:X/MAC:L/MAT:X/MPR:X/MUI:X/MVC:X/MVI:N/MVA:N/MSC:X/MSI:S/MSA:H", // val
        212001, // exp mv
        Score(48), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N/E:A/CR:M/IR:M/AR:L/MAV:P/MAC:X/MAT:P/MPR:H/MUI:A/MVC:L/MVI:L/MVA:H/MSC:L/MSI:H/MSA:L", // val
        211101, // exp mv
        Score(43), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:H/E:P/CR:X/IR:H/AR:H/MAV:P/MAC:L/MAT:N/MPR:N/MUI:A/MVC:H/MVI:H/MVA:N/MSC:X/MSI:L/MSA:H", // val
        200110, // exp mv
        Score(70), // exp score
      ), (
        "test 1.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:H/VI:L/VA:H/SC:N/SI:N/SA:H/E:P/CR:M/IR:L/AR:X/MAV:P/MAC:X/MAT:P/MPR:N/MUI:A/MVC:N/MVI:N/MVA:L/MSC:L/MSI:H/MSA:X", // val
        212111, // exp mv
        Score(11), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N/E:X/CR:M/IR:X/AR:M/MAV:P/MAC:L/MAT:P/MPR:H/MUI:P/MVC:N/MVI:L/MVA:N/MSC:H/MSI:S/MSA:L", // val
        212001, // exp mv
        Score(48), // exp score
      ), (
        "test 4.5", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:L/VI:L/VA:N/SC:H/SI:H/SA:L/E:U/CR:H/IR:L/AR:L/MAV:N/MAC:X/MAT:P/MPR:H/MUI:X/MVC:X/MVI:H/MVA:N/MSC:L/MSI:S/MSA:S", // val
        111021, // exp mv
        Score(45), // exp score
      ), (
        "test 8.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:L/VI:L/VA:N/SC:N/SI:H/SA:L/E:A/CR:X/IR:H/AR:L/MAV:X/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:X/MVA:X/MSC:L/MSI:X/MSA:S", // val
        201000, // exp mv
        Score(83), // exp score
      ), (
        "test 5", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:L/VI:N/VA:H/SC:H/SI:N/SA:L/E:A/CR:L/IR:L/AR:M/MAV:A/MAC:X/MAT:P/MPR:N/MUI:A/MVC:L/MVI:N/MVA:N/MSC:L/MSI:H/MSA:H", // val
        112101, // exp mv
        Score(50), // exp score
      ), (
        "test 5.5", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:N/VI:L/VA:L/SC:H/SI:L/SA:N/E:P/CR:H/IR:X/AR:M/MAV:L/MAC:H/MAT:X/MPR:N/MUI:A/MVC:H/MVI:N/MVA:H/MSC:H/MSI:H/MSA:N", // val
        111110, // exp mv
        Score(55), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:M/MAV:L/MAC:L/MAT:P/MPR:X/MUI:P/MVC:N/MVI:H/MVA:L/MSC:H/MSI:L/MSA:L", // val
        211100, // exp mv
        Score(58), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:N/VI:N/VA:N/SC:N/SI:H/SA:L/E:X/CR:H/IR:M/AR:L/MAV:L/MAC:H/MAT:N/MPR:H/MUI:X/MVC:L/MVI:X/MVA:H/MSC:X/MSI:X/MSA:H", // val
        211101, // exp mv
        Score(43), // exp score
      ), (
        "test 3.2", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:A/VC:H/VI:N/VA:N/SC:N/SI:H/SA:H/E:U/CR:X/IR:M/AR:X/MAV:A/MAC:X/MAT:P/MPR:H/MUI:P/MVC:H/MVI:H/MVA:N/MSC:X/MSI:X/MSA:X", // val
        210120, // exp mv
        Score(32), // exp score
      ), (
        "test 8.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:A/VC:L/VI:H/VA:H/SC:L/SI:L/SA:N/E:A/CR:M/IR:M/AR:H/MAV:N/MAC:H/MAT:P/MPR:N/MUI:P/MVC:X/MVI:H/MVA:X/MSC:N/MSI:S/MSA:H", // val
        111000, // exp mv
        Score(86), // exp score
      ), (
        "test 5.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:A/VC:L/VI:N/VA:H/SC:N/SI:H/SA:L/E:X/CR:L/IR:X/AR:L/MAV:L/MAC:H/MAT:X/MPR:L/MUI:A/MVC:L/MVI:N/MVA:H/MSC:L/MSI:S/MSA:S", // val
        211001, // exp mv
        Score(54), // exp score
      ), (
        "test 7.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:A/VC:N/VI:H/VA:N/SC:L/SI:L/SA:L/E:X/CR:L/IR:L/AR:M/MAV:N/MAC:L/MAT:N/MPR:X/MUI:X/MVC:X/MVI:N/MVA:X/MSC:X/MSI:N/MSA:S", // val
        102001, // exp mv
        Score(78), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:A/VC:N/VI:H/VA:N/SC:N/SI:H/SA:H/E:X/CR:H/IR:X/AR:M/MAV:A/MAC:L/MAT:X/MPR:X/MUI:N/MVC:X/MVI:L/MVA:N/MSC:N/MSI:L/MSA:L", // val
        112201, // exp mv
        Score(21), // exp score
      ), (
        "test 1.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:A/VC:N/VI:N/VA:H/SC:H/SI:N/SA:H/E:U/CR:X/IR:X/AR:X/MAV:A/MAC:H/MAT:P/MPR:H/MUI:P/MVC:H/MVI:L/MVA:N/MSC:X/MSI:N/MSA:N", // val
        211120, // exp mv
        Score(14), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:H/E:X/CR:H/IR:X/AR:L/MAV:L/MAC:X/MAT:P/MPR:X/MUI:N/MVC:H/MVI:X/MVA:N/MSC:N/MSI:X/MSA:H", // val
        111100, // exp mv
        Score(68), // exp score
      ), (
        "test 7", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:H/SC:N/SI:L/SA:H/E:X/CR:X/IR:H/AR:M/MAV:N/MAC:X/MAT:P/MPR:L/MUI:P/MVC:H/MVI:X/MVA:L/MSC:N/MSI:L/MSA:H", // val
        111100, // exp mv
        Score(70), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N/E:A/CR:X/IR:L/AR:M/MAV:P/MAC:L/MAT:X/MPR:L/MUI:X/MVC:N/MVI:X/MVA:X/MSC:X/MSI:X/MSA:H", // val
        212101, // exp mv
        Score(21), // exp score
      ), (
        "test 8.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:N/E:X/CR:H/IR:H/AR:X/MAV:A/MAC:X/MAT:X/MPR:H/MUI:X/MVC:L/MVI:X/MVA:L/MSC:H/MSI:S/MSA:H", // val
        111000, // exp mv
        Score(86), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:H/SC:H/SI:N/SA:H/E:A/CR:H/IR:M/AR:M/MAV:A/MAC:X/MAT:N/MPR:L/MUI:P/MVC:H/MVI:L/MVA:X/MSC:X/MSI:H/MSA:H", // val
        201100, // exp mv
        Score(71), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:H/E:U/CR:M/IR:H/AR:H/MAV:N/MAC:H/MAT:X/MPR:X/MUI:N/MVC:N/MVI:H/MVA:H/MSC:L/MSI:S/MSA:L", // val
        111020, // exp mv
        Score(59), // exp score
      ), (
        "test 3.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:H/SA:N/E:P/CR:M/IR:X/AR:X/MAV:X/MAC:L/MAT:N/MPR:X/MUI:A/MVC:X/MVI:H/MVA:L/MSC:L/MSI:N/MSA:X", // val
        201210, // exp mv
        Score(33), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:L/VI:N/VA:H/SC:L/SI:L/SA:N/E:P/CR:M/IR:M/AR:X/MAV:X/MAC:L/MAT:X/MPR:N/MUI:X/MVC:N/MVI:N/MVA:N/MSC:H/MSI:L/MSA:L", // val
        212111, // exp mv
        Score(10), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:H/SC:L/SI:H/SA:N/E:X/CR:M/IR:L/AR:H/MAV:L/MAC:H/MAT:N/MPR:H/MUI:A/MVC:X/MVI:H/MVA:X/MSC:X/MSI:N/MSA:X", // val
        211200, // exp mv
        Score(39), // exp score
      ), (
        "test 3.2", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:L/MAV:L/MAC:H/MAT:N/MPR:L/MUI:P/MVC:X/MVI:X/MVA:N/MSC:X/MSI:S/MSA:S", // val
        211020, // exp mv
        Score(32), // exp score
      ), (
        "test 5.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:H/SC:H/SI:H/SA:L/E:X/CR:H/IR:M/AR:H/MAV:P/MAC:L/MAT:X/MPR:L/MUI:X/MVC:H/MVI:X/MVA:H/MSC:X/MSI:X/MSA:N", // val
        211100, // exp mv
        Score(59), // exp score
      ), (
        "test 3.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H/E:U/CR:X/IR:H/AR:H/MAV:X/MAC:X/MAT:N/MPR:N/MUI:X/MVC:H/MVI:H/MVA:L/MSC:L/MSI:X/MSA:N", // val
        200220, // exp mv
        Score(39), // exp score
      ), (
        "test 8.5", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/E:A/CR:L/IR:M/AR:H/MAV:A/MAC:L/MAT:N/MPR:X/MUI:X/MVC:X/MVI:N/MVA:N/MSC:N/MSI:N/MSA:S", // val
        101001, // exp mv
        Score(85), // exp score
      ), (
        "test 0.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:H/SC:L/SI:H/SA:L/E:P/CR:L/IR:H/AR:H/MAV:P/MAC:X/MAT:P/MPR:N/MUI:P/MVC:N/MVI:X/MVA:N/MSC:L/MSI:H/MSA:N", // val
        212111, // exp mv
        Score(9), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:H/SC:N/SI:H/SA:L/E:P/CR:L/IR:H/AR:M/MAV:P/MAC:L/MAT:N/MPR:X/MUI:N/MVC:L/MVI:X/MVA:N/MSC:L/MSI:H/MSA:N", // val
        202111, // exp mv
        Score(19), // exp score
      ), (
        "test 6.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:H/SC:N/SI:N/SA:H/E:P/CR:X/IR:L/AR:L/MAV:X/MAC:H/MAT:P/MPR:N/MUI:P/MVC:X/MVI:H/MVA:H/MSC:L/MSI:S/MSA:L", // val
        210010, // exp mv
        Score(68), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:L/SI:L/SA:H/E:A/CR:M/IR:H/AR:X/MAV:X/MAC:H/MAT:N/MPR:H/MUI:A/MVC:N/MVI:N/MVA:L/MSC:N/MSI:X/MSA:H", // val
        212101, // exp mv
        Score(20), // exp score
      ), (
        "test 3.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:L/VI:H/VA:L/SC:H/SI:L/SA:H/E:U/CR:L/IR:H/AR:H/MAV:X/MAC:L/MAT:X/MPR:X/MUI:A/MVC:X/MVI:X/MVA:X/MSC:L/MSI:S/MSA:X", // val
        211020, // exp mv
        Score(33), // exp score
      ), (
        "test 4.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:L/VI:H/VA:L/SC:N/SI:H/SA:H/E:X/CR:H/IR:H/AR:M/MAV:P/MAC:X/MAT:X/MPR:N/MUI:X/MVC:L/MVI:H/MVA:X/MSC:X/MSI:L/MSA:N", // val
        211200, // exp mv
        Score(43), // exp score
      ), (
        "test 4.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:L/SC:N/SI:H/SA:L/E:P/CR:L/IR:L/AR:M/MAV:A/MAC:L/MAT:N/MPR:X/MUI:X/MVC:L/MVI:N/MVA:X/MSC:N/MSI:L/MSA:H", // val
        102111, // exp mv
        Score(48), // exp score
      ), (
        "test 1", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:L/SI:H/SA:L/E:X/CR:X/IR:X/AR:X/MAV:A/MAC:H/MAT:N/MPR:L/MUI:P/MVC:L/MVI:X/MVA:X/MSC:L/MSI:L/MSA:L", // val
        212201, // exp mv
        Score(10), // exp score
      ), (
        "test 0.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:H/SI:H/SA:L/E:U/CR:M/IR:M/AR:X/MAV:X/MAC:H/MAT:N/MPR:N/MUI:A/MVC:L/MVI:X/MVA:X/MSC:L/MSI:N/MSA:H", // val
        212121, // exp mv
        Score(3), // exp score
      ), (
        "test 7.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:L/SA:H/E:P/CR:H/IR:M/AR:H/MAV:N/MAC:X/MAT:P/MPR:X/MUI:X/MVC:N/MVI:N/MVA:L/MSC:L/MSI:S/MSA:L", // val
        012011, // exp mv
        Score(71), // exp score
      ), (
        "test 6.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:L/SA:N/E:X/CR:M/IR:L/AR:H/MAV:N/MAC:L/MAT:X/MPR:N/MUI:X/MVC:L/MVI:N/MVA:X/MSC:X/MSI:N/MSA:N", // val
        012101, // exp mv
        Score(69), // exp score
      ), (
        "test 3.6", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:H/E:U/CR:X/IR:X/AR:L/MAV:A/MAC:H/MAT:P/MPR:X/MUI:A/MVC:X/MVI:L/MVA:H/MSC:L/MSI:X/MSA:X", // val
        111120, // exp mv
        Score(36), // exp score
      ), (
        "test 2.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:L/SI:L/SA:H/E:X/CR:M/IR:L/AR:M/MAV:A/MAC:X/MAT:X/MPR:N/MUI:N/MVC:L/MVI:N/MVA:L/MSC:N/MSI:N/MSA:L", // val
        112201, // exp mv
        Score(23), // exp score
      ), (
        "test 3.3", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:L/VI:H/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H/MAV:P/MAC:X/MAT:N/MPR:L/MUI:X/MVC:N/MVI:X/MVA:L/MSC:X/MSI:L/MSA:X", // val
        201210, // exp mv
        Score(33), // exp score
      ), (
        "test 0.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:L/SI:N/SA:L/E:U/CR:M/IR:M/AR:M/MAV:X/MAC:L/MAT:X/MPR:N/MUI:X/MVC:X/MVI:L/MVA:N/MSC:N/MSI:X/MSA:L", // val
        212221, // exp mv
        Score(1), // exp score
      ), (
        "test 2.1", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:N/SC:L/SI:L/SA:N/E:X/CR:X/IR:H/AR:X/MAV:A/MAC:H/MAT:X/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:H/MSI:L/MSA:L", // val
        212101, // exp mv
        Score(21), // exp score
      ), (
        "test 2", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:H/SA:H/E:P/CR:M/IR:L/AR:X/MAV:A/MAC:L/MAT:N/MPR:H/MUI:A/MVC:N/MVI:L/MVA:N/MSC:L/MSI:X/MSA:H", // val
        202111, // exp mv
        Score(20), // exp score
      ), (
        "test 5.8", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U/CR:L/IR:H/AR:L/MAV:N/MAC:L/MAT:P/MPR:X/MUI:P/MVC:H/MVI:H/MVA:X/MSC:H/MSI:X/MSA:H", // val
        110120, // exp mv
        Score(58), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:L/E:U/CR:X/IR:M/AR:X/MAV:P/MAC:X/MAT:N/MPR:X/MUI:A/MVC:H/MVI:L/MVA:N/MSC:X/MSI:S/MSA:X", // val
        201020, // exp mv
        Score(57), // exp score
      ), (
        "test 5.7", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:N/E:X/CR:M/IR:M/AR:M/MAV:L/MAC:L/MAT:X/MPR:N/MUI:X/MVC:L/MVI:L/MVA:X/MSC:H/MSI:N/MSA:X", // val
        111101, // exp mv
        Score(57), // exp score
      ), (
        "test 7.2", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:P/VC:H/VI:N/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:L/AR:X/MAV:A/MAC:L/MAT:X/MPR:N/MUI:P/MVC:X/MVI:X/MVA:X/MSC:X/MSI:S/MSA:H", // val
        111010, // exp mv
        Score(72), // exp score
      ), (
        "test 7.4", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:P/VC:N/VI:H/VA:L/SC:H/SI:L/SA:N/E:P/CR:M/IR:L/AR:H/MAV:A/MAC:L/MAT:N/MPR:N/MUI:A/MVC:L/MVI:H/MVA:L/MSC:X/MSI:H/MSA:S", // val
        101011, // exp mv
        Score(74), // exp score
      ), (
        "test 1.9", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:H/SC:H/SI:L/SA:L/E:P/CR:X/IR:X/AR:X/MAV:N/MAC:X/MAT:N/MPR:H/MUI:X/MVC:N/MVI:N/MVA:N/MSC:L/MSI:X/MSA:X", // val
        102211, // exp mv
        Score(19), // exp score
      ), (
        "test 7.5", // name
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:L/E:X/CR:M/IR:L/AR:L/MAV:N/MAC:H/MAT:P/MPR:N/MUI:A/MVC:H/MVI:L/MVA:X/MSC:L/MSI:S/MSA:S", // val
        111001, // exp mv
        Score(75), // exp score
      ));

      for (name, s, exp_mv, exp_score) in tests {
        let exp = Scores {
          macrovector: MacroVector::try_from(exp_mv).unwrap(),
          score: exp_score,
        };
        let got = Scores::from(s.parse::<Vector>().unwrap());
        assert_eq!(got, exp, "{name}");
      }
    }
  }
}
