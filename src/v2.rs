//! [CVSS v2][doc] parser and score calculator.
//!
//! # Examples
//!
//! Parse [vector string][vector-string] and get [`Metric`] by [`Name`]:
//!
//! ```
//! # use polycvss::{Err, v2::{AccessVector, Vector, Metric, Name}};
//! # fn main() -> Result<(), Err> {
//! // parse vector string
//! let v: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
//!
//! // get metric
//! let metric = v.get(Name::AccessVector);
//!
//! // check result
//! assert_eq!(metric, Metric::AccessVector(AccessVector::Network));
//! # Ok(())
//! # }
//! ```
//!
//! Build [`Vec`] of metric names:
//!
//! ```
//! # use polycvss::{Err, v2::{Name, Vector}};
//! # fn main() -> Result<(), Err> {
//! // parse vector string
//! let v: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
//!
//! // get metric names
//! let names: Vec<Name> = v.into_iter().map(Name::from).collect();
//!
//! // check result
//! assert_eq!(names, vec!(
//!   Name::AccessVector,
//!   Name::AccessComplexity,
//!   Name::Authentication,
//!   Name::Confidentiality,
//!   Name::Integrity,
//!   Name::Availability,
//! ));
//! # Ok(())
//! # }
//! ```
//!
//! Get [CVSS v2][doc] vector score:
//!
//! ```
//! # use polycvss::{Err, Score, v2::Vector};
//! # fn main() -> Result<(), Err> {
//! // parse CVSS v2 vector string
//! let v: Vector = "AV:N/AC:L/Au:N/C:N/I:N/A:C".parse()?;
//!
//! // get score
//! let score = Score::from(v);
//!
//! // check result
//! assert_eq!(score, Score::from(7.8));
//! # Ok(())
//! # }
//! ```
//!
//! [doc]: https://www.first.org/cvss/v2/guide
//!   "CVSS v2.0 Documentation"
//! [vector-string]: https://www.first.org/cvss/v2/guide#2-4-Base-Temporal-Environmental-Vectors
//!   "CVSS v2.0 Documentation, Section 2.4: Base, Temporal, Environmental Vectors"

#[cfg(feature="serde")]
use serde::{self,Deserialize,Serialize};
use super::{Err, Score, Version, encode::{EncodedVal, EncodedMetric}};

// TODO:
// - non-v2.3 vectors (e.g. Vector::new_with_version)

/// Round value to nearest 10th of a decimal.
///
/// Used by [CVSS v2][doc-v2] scoring functions.
///
/// [doc-v2]: https://www.first.org/cvss/v2/guide
///   "CVSS v2.0 Documentation"
pub fn round1(val: f64) -> f64 {
  (10.0 * val).round() / 10.0
}

/// [`Metric::AccessVector`][] (`AV`) values.
///
/// # Description
///
/// This metric reflects how the vulnerability is exploited. The more remote an attacker can be to attack a host, the greater the vulnerability score.
///
/// # Properties
///
/// - Metric Group: Base
/// - Documentation: [CVSS v2.0 Documentation, Section 2.1.1: Access Vector (`AV`)][doc]
///
/// # Examples
///
/// Parse string as metric and check it:
///
/// ```
/// # use polycvss::{Err, v2::{AccessVector, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "AV:N".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::AccessVector(AccessVector::Network));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v2::{AccessVector, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::AccessVector(AccessVector::AdjacentNetwork).to_string();
///
/// // check result
/// assert_eq!(s, "AV:A");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v2::{AccessVector, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AccessVector(AccessVector::Local));
///
/// // check result
/// assert_eq!(name, Name::AccessVector);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v2/guide#2-1-1-Access-Vector-AV
///   "CVSS v2.0 Documentation, Section 2.1.1: Access Vector (AV)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum AccessVector {
  /// Local (`L`)
  ///
  /// A vulnerability exploitable with only local access requires the attacker to have either physical access to the vulnerable system or a local (shell) account. Examples of locally exploitable vulnerabilities are peripheral attacks such as Firewire/USB DMA attacks, and local privilege escalations (e.g., sudo).
  Local, // (AV:L)

  /// Adjacent Network (`A`)
  ///
  /// A vulnerability exploitable with adjacent network access requires the attacker to have access to either the broadcast or collision domain of the vulnerable software.  Examples of local networks include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet segment.
  AdjacentNetwork, // (AV:A)

  /// Network (`N`)
  ///
  /// A vulnerability exploitable with network access means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access. Such a vulnerability is often termed "remotely exploitable". An example of a network attack is an RPC buffer overflow.
  Network, // (AV:N)
}

/// [`Metric::AccessComplexity`][] (`AC`) values.
///
/// # Description
///
/// This metric measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system. For example, consider a buffer overflow in an Internet service: once the target system is located, the attacker can launch an exploit at will.
///
/// Other vulnerabilities, however, may require additional steps in order to be exploited. For example, a vulnerability in an email client is only exploited after the user downloads and opens a tainted attachment. The possible values for this metric are listed in Table 2. The lower the required complexity, the higher the vulnerability score.
///
/// # Properties
///
/// - Metric Group: Base
/// - Documentation: [CVSS v2.0 Documentation, Section 2.1.2: Access Complexity (`AC`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v2::{AccessComplexity, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "AC:L".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::AccessComplexity(AccessComplexity::Low));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v2::{AccessComplexity, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::AccessComplexity(AccessComplexity::High).to_string();
///
/// // check result
/// assert_eq!(s, "AC:H");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v2::{AccessComplexity, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AccessComplexity(AccessComplexity::High));
///
/// // check result
/// assert_eq!(name, Name::AccessComplexity);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v2/guide#2-1-2-Access-Complexity-AC
///   "CVSS v2.0 Documentation, Section 2.1.2: Access Complexity (AC)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum AccessComplexity {
  /// High (`H`)
  ///
  /// Specialized access conditions exist. For example:
  ///
  /// - In most configurations, the attacking party must already have elevated privileges or spoof additional systems in addition to the attacking system (e.g., DNS hijacking).
  /// - The attack depends on social engineering methods that would be easily detected by knowledgeable people. For example, the victim must perform several suspicious or atypical actions.
  /// - The vulnerable configuration is seen very rarely in practice.
  /// - If a race condition exists, the window is very narrow.
  High, // (AC:H)

  /// Medium (`M`)
  ///
  /// The access conditions are somewhat specialized; the following are examples:
  ///
  /// - The attacking party is limited to a group of systems or users at some level of authorization, possibly untrusted.
  /// - Some information must be gathered before a successful attack can be launched.
  /// - The affected configuration is non-default, and is not commonly configured (e.g., a vulnerability present when a server performs user account authentication via a specific scheme, but not present for another authentication scheme).
  /// - The attack requires a small amount of social engineering that might occasionally fool cautious users (e.g., phishing attacks that modify a web browsers status bar to show a false link, having to be on someones buddy list before sending an IM exploit).
  Medium, // (AC:M)

  /// Low (`L`)
  ///
  /// Specialized access conditions or extenuating circumstances do not exist. The following are examples:
  /// - The affected product typically requires access to a wide range of systems and users, possibly anonymous and untrusted (e.g., Internet-facing web or mail server).
  /// - The affected configuration is default or ubiquitous.
  /// - The attack can be performed manually and requires little skill or additional information gathering.
  /// - The race condition is a lazy one (i.e., it is technically a race but easily winnable).
  Low, // (AC:L)
}

/// [`Metric::Authentication`][] (`Au`) values.
///
/// # Description
///
/// This metric measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability. This metric does not gauge the strength or complexity of the authentication process, only that an attacker is required to provide credentials before an exploit may occur.  The fewer authentication instances that are required, the higher the vulnerability score.
///
/// # Properties
///
/// - Metric Group: Base
/// - Documentation: [CVSS v2.0 Documentation, Section 2.1.3: Authentication (`Au`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v2::{Authentication, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "Au:M".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::Authentication(Authentication::Multiple));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v2::{Authentication, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::Authentication(Authentication::Single).to_string();
///
/// // check result
/// assert_eq!(s, "Au:S");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v2::{Authentication, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::Authentication(Authentication::None));
///
/// // check result
/// assert_eq!(name, Name::Authentication);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v2/guide#2-1-3-Authentication-Au
///   "CVSS v2.0 Documentation, Section 2.1.3: Authentication (Au)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum Authentication {
  /// Multiple (`M`)
  ///
  /// Exploiting the vulnerability requires that the attacker authenticate two or more times, even if the same credentials are used each time. An example is an attacker authenticating to an operating system in addition to providing credentials to access an application hosted on that system.
  Multiple, // (Au:M)

  /// Single (`S`)
  ///
  /// The vulnerability requires an attacker to be logged into the system (such as at a command line or via a desktop session or web interface).
  Single, // (Au:S)

  /// None (`N`)
  ///
  /// Authentication is not required to exploit the vulnerability.
  None, // (Au:N)
}

/// Impact metric (`C`, `I`, `A`) values.
///
/// # Impact Metrics
///
/// - [`Metric::Confidentiality`][] (`C`)
/// - [`Metric::Integrity`][] (`I`)
/// - [`Metric::Availability`][] (`A`)
///
/// # Properties
///
/// - Metric Group: Base
/// - Documentation:
///   - [CVSS v2.0 Documentation, Section 2.1.4: Confidentiality Impact (`C`)][c-doc]
///   - [CVSS v2.0 Documentation, Section 2.1.5: Integrity Impact (`I`)][i-doc]
///   - [CVSS v2.0 Documentation, Section 2.1.6: Availability Impact (`A`)][a-doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v2::{Impact, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "C:C".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::Confidentiality(Impact::Complete));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v2::{Impact, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::Integrity(Impact::Partial).to_string();
///
/// // check result
/// assert_eq!(s, "I:P");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v2::{Impact, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::Availability(Impact::None));
///
/// // check result
/// assert_eq!(name, Name::Availability);
/// # }
/// ```
///
/// [c-doc]: https://www.first.org/cvss/v2/guide#2-1-4-Confidentiality-Impact-C
///   "CVSS v2.0 Documentation, Section 2.1.4: Confidentiality Impact (C)"
/// [i-doc]: https://www.first.org/cvss/v2/guide#2-1-5-Integrity-Impact-I
///   "CVSS v2.0 Documentation, Section 2.1.5: Integrity Impact (I)"
/// [a-doc]: https://www.first.org/cvss/v2/guide#2-1-6-Availability-Impact-A
///   "CVSS v2.0 Documentation, Section 2.1.6: Availability Impact (A)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum Impact {
  /// None (`N`)
  ///
  /// | Metric | Description |
  /// | ------ | ----------- |
  /// | [`Metric::Confidentiality`][] | There is no impact to the confidentiality of the system. |
  /// | [`Metric::Integrity`][] | There is no impact to the integrity of the system. |
  /// | [`Metric::Availability`][] | There is no impact to the availability of the system. |
  None, // (N)

  /// Partial (`P`)
  ///
  /// | Metric | Description |
  /// | ------ | ----------- |
  /// | [`Metric::Confidentiality`][] | There is considerable informational disclosure. Access to some system files is possible, but the attacker does not have control over what is obtained, or the scope of the loss is constrained. An example is a vulnerability that divulges only certain tables in a database. |
  /// | [`Metric::Integrity`][] | Modification of some system files or information is possible, but the attacker does not have control over what can be modified, or the scope of what the attacker can affect is limited. For example, system or application files may be overwritten or modified, but either the attacker has no control over which files are affected or the attacker can modify files within only a limited context or scope. |
  /// | [`Metric::Availability`][] | There is reduced performance or interruptions in resource availability. An example is a network-based flood attack that permits a limited number of successful connections to an Internet service. |
  Partial, // (P)

  /// Complete (`C`)
  ///
  /// | Metric | Description |
  /// | ------ | ----------- |
  /// | [`Metric::Confidentiality`][] | There is total information disclosure, resulting in all system files being revealed. The attacker is able to read all of the system's data (memory, files, etc.) |
  /// | [`Metric::Integrity`][] | There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised. The attacker is able to modify any files on the target system. |
  /// | [`Metric::Availability`][] | There is a total shutdown of the affected resource. The attacker can render the resource completely unavailable. |
  Complete, // (C)
}

/// [`Metric::Exploitability`][] (`E`) values.
///
/// # Description
///
/// This metric measures the current state of exploit techniques or code availability. Public availability of easy-to-use exploit code increases the number of potential attackers by including those who are unskilled, thereby increasing the severity of the vulnerability.
///
/// Initially, real-world exploitation may only be theoretical. Publication of proof of concept code, functional exploit code, or sufficient technical details necessary to exploit the vulnerability may follow. Furthermore, the exploit code available may progress from a proof-of-concept demonstration to exploit code that is successful in exploiting the vulnerability consistently. In severe cases, it may be delivered as the payload of a network-based worm or virus.  The more easily a vulnerability can be exploited, the higher the vulnerability score.
///
/// # Properties
///
/// - Metric Group: Temporal
/// - Documentation: [CVSS v2.0 Documentation, Section 2.2.1: Exploitability (`E`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v2::{Exploitability, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "E:H".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::Exploitability(Exploitability::High));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v2::{Exploitability, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::Exploitability(Exploitability::Functional).to_string();
///
/// // check result
/// assert_eq!(s, "E:F");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v2::{Exploitability, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::Exploitability(Exploitability::ProofOfConcept));
///
/// // check result
/// assert_eq!(name, Name::Exploitability);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v2/guide#2-2-1-Exploitability-E
///   "CVSS v2.0 Documentation, Section 2.2.1: Exploitability (E)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum Exploitability {
  /// Not Defined (`ND`)
  ///
  /// Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.
  NotDefined, // (E:ND)

  /// Unproven (`U`)
  ///
  /// No exploit code is available, or an exploit is entirely theoretical.
  Unproven, // (E:U)

  /// Proof-of-Concept (`POC`)
  ///
  /// Proof-of-concept exploit code or an attack demonstration that is not practical for most systems is available. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.
  ProofOfConcept, // (E:POC)

  /// Functional (`F`)
  ///
  /// Functional exploit code is available. The code works in most situations where the vulnerability exists.
  Functional, // (E:F)

  /// High (`H`)
  ///
  /// Either the vulnerability is exploitable by functional mobile autonomous code, or no exploit is required (manual trigger) and details are widely available. The code works in every situation, or is actively being delivered via a mobile autonomous agent (such as a worm or virus).
  High, // (E:H)
}

/// [`Metric::RemediationLevel`][] (`RL`) values.
///
/// # Description
///
/// The remediation level of a vulnerability is an important factor for prioritization. The typical vulnerability is unpatched when initially published. Workarounds or hotfixes may offer interim remediation until an official patch or upgrade is issued. Each of these respective stages adjusts the temporal score downwards, reflecting the decreasing urgency as remediation becomes final. The less official and permanent a fix, the higher the vulnerability score is.
///
/// # Properties
///
/// - Metric Group: Temporal
/// - Documentation: [CVSS v2.0 Documentation, Section 2.2.2: Remediation Level (`RL`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v2::{RemediationLevel, Metric}};
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
/// # use polycvss::v2::{RemediationLevel, Metric};
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
/// # use polycvss::v2::{RemediationLevel, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::RemediationLevel(RemediationLevel::TemporaryFix));
///
/// // check result
/// assert_eq!(name, Name::RemediationLevel);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v2/guide#2-2-2-Remediation-Level-RL
///   "CVSS v2.0 Documentation, Section 2.2.2: Remediation Level (RL)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum RemediationLevel {
  /// Not Defined (`ND`)
  ///
  /// Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.
  NotDefined, // (RL:ND)

  /// Official Fix (`OF`)
  ///
  /// A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available.
  OfficialFix, // (RL:OF)

  /// Temporary Fix (`TF`)
  ///
  /// There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.
  TemporaryFix, // (RL:TF)

  /// Workaround (`W`)
  ///
  /// There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.
  Workaround, // (RL:W)

  /// Unavailable (`U`)
  ///
  /// There is either no solution available or it is impossible to apply.
  Unavailable, // (RL:U)
}

/// [`Metric::ReportConfidence`][] (`RC`) values.
///
/// # Description
///
/// This metric measures the degree of confidence in the existence of the vulnerability and the credibility of the known technical details. Sometimes, only the existence of vulnerabilities are publicized, but without specific details. The vulnerability may later be corroborated and then confirmed through acknowledgement by the author or vendor of the affected technology. The urgency of a vulnerability is higher when a vulnerability is known to exist with certainty. This metric also suggests the level of technical knowledge available to would-be attackers. The more a vulnerability is validated by the vendor or other reputable sources, the higher the score.
///
/// # Properties
///
/// - Metric Group: Temporal
/// - Documentation: [CVSS v2.0 Documentation, Section 2.2.3: Report Confidence (`RC`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v2::{ReportConfidence, Metric}};
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
/// # use polycvss::v2::{ReportConfidence, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::ReportConfidence(ReportConfidence::Uncorroborated).to_string();
///
/// // check result
/// assert_eq!(s, "RC:UR");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v2::{ReportConfidence, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::ReportConfidence(ReportConfidence::Unconfirmed));
///
/// // check result
/// assert_eq!(name, Name::ReportConfidence);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v2/guide#2-2-3-Report-Confidence-RC
///   "CVSS v2.0 Documentation, Section 2.2.3: Report Confidence (RC)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum ReportConfidence {
  /// Not Defined (`ND`)
  ///
  /// Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.
  NotDefined, // (RC:ND)

  /// Unconfirmed (`UC`)
  ///
  /// There is a single unconfirmed source or possibly multiple conflicting reports. There is little confidence in the validity of the reports. An example is a rumor that surfaces from the hacker underground.
  Unconfirmed, // (RC:UC)

  /// Uncorroborated (`UR`)
  ///
  /// There are multiple non-official sources, possibly including independent security companies or research organizations. At this point there may be conflicting technical details or some other lingering ambiguity.
  Uncorroborated, // (RC:UR)

  /// Confirmed (`C`)
  ///
  /// The vulnerability has been acknowledged by the vendor or author of the affected technology. The vulnerability may also be Confirmed when its existence is confirmed from an external event such as publication of functional or proof-of-concept exploit code or widespread exploitation.
  Confirmed, // (RC:C)
}

/// [`Metric::CollateralDamagePotential`][] (`CDP`) values.
///
/// # Description
///
/// This metric measures the potential for loss of life or physical assets through damage or theft of property or equipment.  The metric may also measure economic loss of productivity or revenue. Naturally, the greater the damage potential, the higher the vulnerability score.
///
/// # Properties
///
/// - Metric Group: Environmental
/// - Documentation: [CVSS v2.0 Documentation, Section 2.3.1: Collateral Damage Potential (`CDP`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v2::{CollateralDamagePotential, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "CDP:H".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::CollateralDamagePotential(CollateralDamagePotential::High));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v2::{CollateralDamagePotential, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::CollateralDamagePotential(CollateralDamagePotential::MediumHigh).to_string();
///
/// // check result
/// assert_eq!(s, "CDP:MH");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v2::{CollateralDamagePotential, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::CollateralDamagePotential(CollateralDamagePotential::LowMedium));
///
/// // check result
/// assert_eq!(name, Name::CollateralDamagePotential);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v2/guide#2-3-1-Collateral-Damage-Potential-CDP
///   "CVSS v2.0 Documentation, Section 2.3.1: Collateral Damage Potential (CDP)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum CollateralDamagePotential {
  /// Not Defined (`ND`)
  ///
  /// Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.
  NotDefined, // (CDP:ND)

  /// None (`N`)
  ///
  /// There is no potential for loss of life, physical assets, productivity or revenue.
  None, // (CDP:N)

  /// Low (`L`)
  ///
  /// A successful exploit of this vulnerability may result in slight physical or property damage. Or, there may be a slight loss of revenue or productivity to the organization.
  Low, // (CDP:L)

  /// Low-Medium (`LM`)
  ///
  /// A successful exploit of this vulnerability may result in moderate physical or property damage. Or, there may be a moderate loss of revenue or productivity to the organization.
  LowMedium, // (CDP:LM)

  /// Medium-High (`MH`)
  ///
  /// A successful exploit of this vulnerability may result in significant physical or property damage or loss. Or, there may be a significant loss of revenue or productivity.
  MediumHigh, // (CDP:MH)

  /// High (`H`)
  ///
  /// A successful exploit of this vulnerability may result in catastrophic physical or property damage and loss. Or, there may be a catastrophic loss of revenue or productivity.
  High, // (CDP:H)
}

/// [`Metric::TargetDistribution`][] (`TD`) values.
///
/// # Description
///
/// This metric measures the proportion of vulnerable systems. It is meant as an environment-specific indicator in order to approximate the percentage of systems that could be affected by the vulnerability. The greater the proportion of vulnerable systems, the higher the score.
///
/// # Properties
///
/// - Metric Group: Environmental
/// - Documentation: [CVSS v2.0 Documentation, Section 2.3.2: Target Distribution (`TD`)][doc]
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v2::{TargetDistribution, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "TD:H".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::TargetDistribution(TargetDistribution::High));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v2::{TargetDistribution, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::TargetDistribution(TargetDistribution::Medium).to_string();
///
/// // check result
/// assert_eq!(s, "TD:M");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v2::{TargetDistribution, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::TargetDistribution(TargetDistribution::Low));
///
/// // check result
/// assert_eq!(name, Name::TargetDistribution);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v2/guide#2-3-2-Target-Distribution-TD
///   "CVSS v2.0 Documentation, Section 2.3.2: Target Distribution (TD)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum TargetDistribution {
  /// Not Defined (`ND`)
  ///
  /// Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.
  NotDefined, // (TD:ND)

  /// None (`N`)
  ///
  /// No target systems exist, or targets are so highly specialized that they only exist in a laboratory setting. Effectively 0% of the environment is at risk.
  None, // (TD:N)

  /// Low (`L`)
  ///
  /// Targets exist inside the environment, but on a small scale. Between 1% - 25% of the total environment is at risk.
  Low, // (TD:L)

  /// Medium (`M`)
  ///
  /// Targets exist inside the environment, but on a medium scale. Between 26% - 75% of the total environment is at risk.
  Medium, // (TD:M)

  /// High (`H`)
  ///
  /// Targets exist inside the environment on a considerable scale. Between 76% - 100% of the total environment is considered at risk.
  High, // (TD:H)
}

/// Requirement metric (`CR`, `IR`, `AR`) values.
///
/// # Description
///
/// These metrics enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a users organization, measured in terms of confidentiality, integrity, and availability, That is, if an IT asset supports a business function for which availability is most important, the analyst can assign a greater value to availability, relative to confidentiality and integrity. Each security requirement has three possible values: low, medium, or high.
///
/// The full effect on the environmental score is determined by the corresponding base impact metrics (please note that the base confidentiality, integrity and availability impact metrics, themselves, are not changed). That is, these metrics modify the environmental score by reweighting the (base) confidentiality, integrity, and availability impact metrics. For example, the confidentiality impact (C) metric has increased weight if the confidentiality requirement (CR) is high. Likewise, the confidentiality impact metric has decreased weight if the confidentiality requirement is low. The confidentiality impact metric weighting is neutral if the confidentiality requirement is medium. This same logic is applied to the integrity and availability requirements.
///
/// Note that the confidentiality requirement will not affect the environmental score if the (base) confidentiality impact is set to none. Also, increasing the confidentiality requirement from medium to high will not change the environmental score when the (base) impact metrics are set to complete. This is because the impact sub score (part of the base score that calculates impact) is already at a maximum value of 10.
///
/// The possible values for the security requirements are listed in Table 12. For brevity, the same table is used for all three metrics. The greater the security requirement, the higher the score (remember that medium is considered the default). These metrics will modify the score as much as plus or minus 2.5.
///
/// # Properties
///
/// - Metric Group: Environmental
/// - Documentation: [CVSS v2.0 Documentation, Section 2.3.3: Security Requirements (`CR`, `IR`, `AR`)][doc]
///
/// # Requirement Metrics
///
/// - [`Metric::ConfidentialityRequirement`][] (`CR`)
/// - [`Metric::IntegrityRequirement`][] (`IR`)
/// - [`Metric::AvailabilityRequirement`][] (`AR`)
///
/// # Examples
///
/// Parse string as metric:
///
/// ```
/// # use polycvss::{Err, v2::{Requirement, Metric}};
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
/// # use polycvss::v2::{Requirement, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::IntegrityRequirement(Requirement::Medium).to_string();
///
/// // check result
/// assert_eq!(s, "IR:M");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v2::{Requirement, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AvailabilityRequirement(Requirement::Low));
///
/// // check result
/// assert_eq!(name, Name::AvailabilityRequirement);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v2/guide#2-3-3-Security-Requirements-CR-IR-AR
///   "CVSS v2.0 Documentation, Section 2.3.3: Security Requirements (CR, IR, AR)"
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
#[cfg_attr(feature="serde", serde(rename_all="UPPERCASE"))]
pub enum Requirement {
  /// Not Defined (`ND`)
  ///
  /// Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.
  NotDefined, // (ND)

  /// Low (`L`)
  ///
  /// Loss of [confidentiality / integrity / availability] is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).
  Low, // (L)

  /// Medium (`M`)
  ///
  /// Loss of [confidentiality / integrity / availability] is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).
  Medium, // (M)

  /// High (`H`)
  ///
  /// Loss of [confidentiality / integrity / availability] is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).
  High, // (H)
}

/// [`Metric`][] group.
///
/// See [CVSS v2.0 Documentation, Section 2: Metric Groups][doc].
///
/// # Example
///
/// Get metric group:
///
/// ```
/// # use polycvss::v2::{Group, Name};
/// # fn main() {
/// // get group
/// let group = Group::from(Name::AccessVector);
///
/// // check result
/// assert_eq!(group, Group::Base);
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v2/guide#Metric-Groups
///   "CVSS v2.0 Documentation, Section 2: Metric Groups"
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
      Name::AccessVector => Group::Base,
      Name::AccessComplexity => Group::Base,
      Name::Authentication => Group::Base,
      Name::Confidentiality => Group::Base,
      Name::Integrity => Group::Base,
      Name::Availability => Group::Base,
      Name::Exploitability => Group::Temporal,
      Name::RemediationLevel => Group::Temporal,
      Name::ReportConfidence => Group::Temporal,
      Name::CollateralDamagePotential => Group::Environmental,
      Name::TargetDistribution => Group::Environmental,
      Name::ConfidentialityRequirement => Group::Environmental,
      Name::IntegrityRequirement => Group::Environmental,
      Name::AvailabilityRequirement => Group::Environmental,
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
/// # use polycvss::v2::{AccessVector, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AccessVector(AccessVector::Local));
///
/// // check result
/// assert_eq!(name, Name::AccessVector);
/// # }
/// ```
///
/// Check if metric is mandatory:
///
/// ```
/// # use polycvss::v2::{AccessVector, Name};
/// # fn main() {
/// // check if metric is mandatory
/// assert_eq!(true, Name::AccessVector.is_mandatory());
/// # }
/// ```
#[derive(Clone,Copy,Debug,PartialEq)]
pub enum Name {
  /// Access Vector (`AV`) metric name.  See [`Metric::AccessVector`][].
  AccessVector,
  /// Access Complexity (`AC`) metric name.  See [`Metric::AccessComplexity`][].
  AccessComplexity,
  /// Authentication (`Au`) metric name.  See [`Metric::Authentication`][].
  Authentication,
  /// Confidentiality Impact (`C`) metric name.  See [`Metric::Confidentiality`][].
  Confidentiality,
  /// Integrity Impact (`I`) metric name.  See [`Metric::Integrity`][].
  Integrity,
  /// Availability Impact (`I`) metric name.  See [`Metric::Availability`][].
  Availability,
  /// Exploitability (`E`) metric name.  See [`Metric::Exploitability`][].
  Exploitability,
  /// Remediation Level (`RL`) metric name.  See [`Metric::RemediationLevel`][].
  RemediationLevel,
  /// Report Confidence (`RC`) metric name.  See [`Metric::ReportConfidence`][].
  ReportConfidence,
  /// Collateral Damage Potential (`CDP`) metric name.  See [`Metric::CollateralDamagePotential`][].
  CollateralDamagePotential,
  /// Target Distribution (`TD`) metric name.  See [`Metric::TargetDistribution`][].
  TargetDistribution,
  /// Confidentiality Requirement (`CR`) metric name.  See [`Metric::ConfidentialityRequirement`][].
  ConfidentialityRequirement,
  /// Integrity Requirement (`IR`) metric name.  See [`Metric::IntegrityRequirement`][].
  IntegrityRequirement,
  /// Availability Requirement (`AR`) metric name.  See [`Metric::AvailabilityRequirement`][].
  AvailabilityRequirement,
}

impl Name {
  /// Is this metric mandatory?
  ///
  /// # Example
  ///
  /// # use polycvss::v2::{AccessVector, Name};
  /// # fn main() {
  /// // check if metric is mandatory
  /// assert_eq!(true, Name::AccessVector.is_mandatory());
  /// # }
  pub fn is_mandatory(self) -> bool {
    Group::from(self) == Group::Base
  }
}

impl From<Metric> for Name {
  fn from(m: Metric) -> Name {
    match m {
      Metric::AccessVector(_) => Name::AccessVector,
      Metric::AccessComplexity(_) => Name::AccessComplexity,
      Metric::Authentication(_) => Name::Authentication,
      Metric::Confidentiality(_) => Name::Confidentiality,
      Metric::Integrity(_) => Name::Integrity,
      Metric::Availability(_) => Name::Availability,
      Metric::Exploitability(_) => Name::Exploitability,
      Metric::RemediationLevel(_) => Name::RemediationLevel,
      Metric::ReportConfidence(_) => Name::ReportConfidence,
      Metric::CollateralDamagePotential(_) => Name::CollateralDamagePotential,
      Metric::TargetDistribution(_) => Name::TargetDistribution,
      Metric::ConfidentialityRequirement(_) => Name::ConfidentialityRequirement,
      Metric::IntegrityRequirement(_) => Name::IntegrityRequirement,
      Metric::AvailabilityRequirement(_) => Name::AvailabilityRequirement,
    }
  }
}

impl std::str::FromStr for Name {
  type Err = super::Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "AV" => Ok(Name::AccessVector),
      "AC" => Ok(Name::AccessComplexity),
      "Au" => Ok(Name::Authentication),
      "C" => Ok(Name::Confidentiality),
      "I" => Ok(Name::Integrity),
      "A" => Ok(Name::Availability),
      "E" => Ok(Name::Exploitability),
      "RL" => Ok(Name::RemediationLevel),
      "RC" => Ok(Name::ReportConfidence),
      "CDP" => Ok(Name::CollateralDamagePotential),
      "TD" => Ok(Name::TargetDistribution),
      "CR" => Ok(Name::ConfidentialityRequirement),
      "IR" => Ok(Name::IntegrityRequirement),
      "AR" => Ok(Name::AvailabilityRequirement),
      _ => Err(Err::UnknownName),
    }
  }
}

impl std::fmt::Display for Name {
  // Format CVSSv3.1 metric name as a string.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{}", match self {
      Name::AccessVector => "AV",
      Name::AccessComplexity => "AC",
      Name::Authentication => "Au",
      Name::Confidentiality => "C",
      Name::Integrity => "I",
      Name::Availability => "A",
      Name::Exploitability => "E",
      Name::RemediationLevel => "RL",
      Name::ReportConfidence => "RC",
      Name::CollateralDamagePotential => "CDP",
      Name::TargetDistribution => "TD",
      Name::ConfidentialityRequirement => "CR",
      Name::IntegrityRequirement => "IR",
      Name::AvailabilityRequirement => "AR",
    })
  }
}

/// [`Vector`][] component.
///
/// # Examples
///
/// Parse string as metric and check it:
///
/// ```
/// # use polycvss::{Err, v2::{AccessVector, Metric}};
/// # fn main() -> Result<(), Err> {
/// // parse string as metric
/// let metric: Metric = "AV:N".parse()?;
///
/// // check result
/// assert_eq!(metric, Metric::AccessVector(AccessVector::Network));
/// # Ok(())
/// # }
/// ```
///
/// Convert metric to string:
///
/// ```
/// # use polycvss::v2::{AccessVector, Metric};
/// # fn main() {
/// // convert metric to string
/// let s = Metric::AccessVector(AccessVector::AdjacentNetwork).to_string();
///
/// // check result
/// assert_eq!(s, "AV:A");
/// # }
/// ```
///
/// Get metric name:
///
/// ```
/// # use polycvss::v2::{AccessVector, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AccessVector(AccessVector::Local));
///
/// // check result
/// assert_eq!(name, Name::AccessVector);
/// # }
/// ```
#[derive(Clone,Copy,Debug,PartialEq)]
#[cfg_attr(feature="serde", derive(Deserialize,Serialize))]
pub enum Metric {
  /// Access Vector (`AV`) metric.
  ///
  /// # Description
  ///
  /// This metric reflects how the vulnerability is exploited. The more remote an attacker can be to attack a host, the greater the vulnerability score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.1.1: Access Vector (`AV`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric and check it:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{AccessVector, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "AV:N".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::AccessVector(AccessVector::Network));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v2::{AccessVector, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::AccessVector(AccessVector::AdjacentNetwork).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "AV:A");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{AccessVector, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::AccessVector(AccessVector::Local));
  ///
  /// // check result
  /// assert_eq!(name, Name::AccessVector);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#2-1-1-Access-Vector-AV
  ///   "CVSS v2.0 Documentation, Section 2.1.1: Access Vector (AV)"
  AccessVector(AccessVector),

  /// Access Complexity (`AC`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system. For example, consider a buffer overflow in an Internet service: once the target system is located, the attacker can launch an exploit at will.
  ///
  /// Other vulnerabilities, however, may require additional steps in order to be exploited. For example, a vulnerability in an email client is only exploited after the user downloads and opens a tainted attachment. The possible values for this metric are listed in Table 2. The lower the required complexity, the higher the vulnerability score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.1.2: Access Complexity (`AC`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{AccessComplexity, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "AC:L".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::AccessComplexity(AccessComplexity::Low));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v2::{AccessComplexity, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::AccessComplexity(AccessComplexity::High).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "AC:H");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{AccessComplexity, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::AccessComplexity(AccessComplexity::High));
  ///
  /// // check result
  /// assert_eq!(name, Name::AccessComplexity);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#2-1-2-Access-Complexity-AC
  ///   "CVSS v2.0 Documentation, Section 2.1.2: Access Complexity (AC)"
  AccessComplexity(AccessComplexity),

  /// Authentication (`Au`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability. This metric does not gauge the strength or complexity of the authentication process, only that an attacker is required to provide credentials before an exploit may occur.  The fewer authentication instances that are required, the higher the vulnerability score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.1.3: Authentication (`Au`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{Authentication, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "Au:M".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Authentication(Authentication::Multiple));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v2::{Authentication, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Authentication(Authentication::Single).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "Au:S");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{Authentication, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Authentication(Authentication::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::Authentication);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#2-1-3-Authentication-Au
  ///   "CVSS v2.0 Documentation, Section 2.1.3: Authentication (Au)"
  Authentication(Authentication),

  /// Confidentiality Impact (`C`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the impact on confidentiality of a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.  Increased confidentiality impact increases the vulnerability score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.1.4: Confidentiality Impact (`C`)][c-doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "C:C".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Confidentiality(Impact::Complete));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v2::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Confidentiality(Impact::Partial).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "C:P");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Confidentiality(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::Confidentiality);
  /// # }
  /// ```
  ///
  /// [c-doc]: https://www.first.org/cvss/v2/guide#2-1-4-Confidentiality-Impact-C
  ///   "CVSS v2.0 Documentation, Section 2.1.4: Confidentiality Impact (C)"
  Confidentiality(Impact),

  /// Integrity Impact (`I`) metric.
  ///
  /// # Documentation
  ///
  /// This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and guaranteed veracity of information. Increased integrity impact increases the vulnerability score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.1.5: Integrity Impact (`I`)][i-doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "I:C".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Integrity(Impact::Complete));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v2::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Integrity(Impact::Partial).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "I:P");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Integrity(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::Integrity);
  /// # }
  /// ```
  ///
  /// [i-doc]: https://www.first.org/cvss/v2/guide#2-1-5-Integrity-Impact-I
  ///   "CVSS v2.0 Documentation, Section 2.1.5: Integrity Impact (I)"
  Integrity(Impact),

  /// Availability Impact (`A`) metric.
  ///
  /// # Documentation
  ///
  /// This metric measures the impact to availability of a successfully exploited vulnerability. Availability refers to the accessibility of information resources. Attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of a system. Increased availability impact increases the vulnerability score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Base
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.1.6: Availability Impact (`A`)][a-doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{Impact, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "A:C".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Availability(Impact::Complete));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v2::{Impact, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Availability(Impact::Partial).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "A:P");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{Impact, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Availability(Impact::None));
  ///
  /// // check result
  /// assert_eq!(name, Name::Availability);
  /// # }
  /// ```
  ///
  /// [a-doc]: https://www.first.org/cvss/v2/guide#2-1-6-Availability-Impact-A
  ///   "CVSS v2.0 Documentation, Section 2.1.6: Availability Impact (A)"
  Availability(Impact),

  /// Exploitability (`E`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the current state of exploit techniques or code availability. Public availability of easy-to-use exploit code increases the number of potential attackers by including those who are unskilled, thereby increasing the severity of the vulnerability.
  ///
  /// Initially, real-world exploitation may only be theoretical. Publication of proof of concept code, functional exploit code, or sufficient technical details necessary to exploit the vulnerability may follow. Furthermore, the exploit code available may progress from a proof-of-concept demonstration to exploit code that is successful in exploiting the vulnerability consistently. In severe cases, it may be delivered as the payload of a network-based worm or virus.  The more easily a vulnerability can be exploited, the higher the vulnerability score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Temporal
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.2.1: Exploitability (`E`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{Exploitability, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "E:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::Exploitability(Exploitability::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v2::{Exploitability, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::Exploitability(Exploitability::Functional).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "E:F");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{Exploitability, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::Exploitability(Exploitability::ProofOfConcept));
  ///
  /// // check result
  /// assert_eq!(name, Name::Exploitability);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#2-2-1-Exploitability-E
  ///   "CVSS v2.0 Documentation, Section 2.2.1: Exploitability (E)"
  Exploitability(Exploitability),

  /// Remediation Level (`RL`) metric.
  ///
  /// # Description
  ///
  /// The remediation level of a vulnerability is an important factor for prioritization. The typical vulnerability is unpatched when initially published. Workarounds or hotfixes may offer interim remediation until an official patch or upgrade is issued. Each of these respective stages adjusts the temporal score downwards, reflecting the decreasing urgency as remediation becomes final. The less official and permanent a fix, the higher the vulnerability score is.
  ///
  /// # Properties
  ///
  /// - Metric Group: Temporal
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.2.2: Remediation Level (`RL`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{RemediationLevel, Metric}};
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
  /// # use polycvss::v2::{RemediationLevel, Metric};
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
  /// # use polycvss::v2::{RemediationLevel, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::RemediationLevel(RemediationLevel::TemporaryFix));
  ///
  /// // check result
  /// assert_eq!(name, Name::RemediationLevel);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#2-2-2-Remediation-Level-RL
  ///   "CVSS v2.0 Documentation, Section 2.2.2: Remediation Level (RL)"
  RemediationLevel(RemediationLevel),

  /// Report Confidence (`RC`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the degree of confidence in the existence of the vulnerability and the credibility of the known technical details. Sometimes, only the existence of vulnerabilities are publicized, but without specific details. The vulnerability may later be corroborated and then confirmed through acknowledgement by the author or vendor of the affected technology. The urgency of a vulnerability is higher when a vulnerability is known to exist with certainty. This metric also suggests the level of technical knowledge available to would-be attackers. The more a vulnerability is validated by the vendor or other reputable sources, the higher the score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Temporal
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.2.3: Report Confidence (`RC`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{ReportConfidence, Metric}};
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
  /// # use polycvss::v2::{ReportConfidence, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ReportConfidence(ReportConfidence::Uncorroborated).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "RC:UR");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{ReportConfidence, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ReportConfidence(ReportConfidence::Unconfirmed));
  ///
  /// // check result
  /// assert_eq!(name, Name::ReportConfidence);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#2-2-3-Report-Confidence-RC
  ///   "CVSS v2.0 Documentation, Section 2.2.3: Report Confidence (RC)"
  ReportConfidence(ReportConfidence),

  /// Collateral Damage Potential (`CDP`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the potential for loss of life or physical assets through damage or theft of property or equipment.  The metric may also measure economic loss of productivity or revenue. Naturally, the greater the damage potential, the higher the vulnerability score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.3.1: Collateral Damage Potential (`CDP`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{CollateralDamagePotential, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "CDP:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::CollateralDamagePotential(CollateralDamagePotential::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v2::{CollateralDamagePotential, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::CollateralDamagePotential(CollateralDamagePotential::MediumHigh).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "CDP:MH");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{CollateralDamagePotential, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::CollateralDamagePotential(CollateralDamagePotential::LowMedium));
  ///
  /// // check result
  /// assert_eq!(name, Name::CollateralDamagePotential);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#2-3-1-Collateral-Damage-Potential-CDP
  ///   "CVSS v2.0 Documentation, Section 2.3.1: Collateral Damage Potential (CDP)"
  CollateralDamagePotential(CollateralDamagePotential),

  /// Target Distribution (`TD`) metric.
  ///
  /// # Description
  ///
  /// This metric measures the proportion of vulnerable systems. It is meant as an environment-specific indicator in order to approximate the percentage of systems that could be affected by the vulnerability. The greater the proportion of vulnerable systems, the higher the score.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.3.2: Target Distribution (`TD`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{TargetDistribution, Metric}};
  /// # fn main() -> Result<(), Err> {
  /// // parse string as metric
  /// let metric: Metric = "TD:H".parse()?;
  ///
  /// // check result
  /// assert_eq!(metric, Metric::TargetDistribution(TargetDistribution::High));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Convert metric to string:
  ///
  /// ```
  /// # use polycvss::v2::{TargetDistribution, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::TargetDistribution(TargetDistribution::Medium).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "TD:M");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{TargetDistribution, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::TargetDistribution(TargetDistribution::Low));
  ///
  /// // check result
  /// assert_eq!(name, Name::TargetDistribution);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#2-3-2-Target-Distribution-TD
  ///   "CVSS v2.0 Documentation, Section 2.3.2: Target Distribution (TD)"
  TargetDistribution(TargetDistribution),

  /// Confidentiality Requirement (`CR`) metric.
  ///
  /// # Description
  ///
  /// These metrics enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a users organization, measured in terms of confidentiality, integrity, and availability, That is, if an IT asset supports a business function for which availability is most important, the analyst can assign a greater value to availability, relative to confidentiality and integrity. Each security requirement has three possible values: low, medium, or high.
  ///
  /// The full effect on the environmental score is determined by the corresponding base impact metrics (please note that the base confidentiality, integrity and availability impact metrics, themselves, are not changed). That is, these metrics modify the environmental score by reweighting the (base) confidentiality, integrity, and availability impact metrics. For example, the confidentiality impact (C) metric has increased weight if the confidentiality requirement (CR) is high. Likewise, the confidentiality impact metric has decreased weight if the confidentiality requirement is low. The confidentiality impact metric weighting is neutral if the confidentiality requirement is medium. This same logic is applied to the integrity and availability requirements.
  ///
  /// Note that the confidentiality requirement will not affect the environmental score if the (base) confidentiality impact is set to none. Also, increasing the confidentiality requirement from medium to high will not change the environmental score when the (base) impact metrics are set to complete. This is because the impact sub score (part of the base score that calculates impact) is already at a maximum value of 10.
  ///
  /// The possible values for the security requirements are listed in Table 12. For brevity, the same table is used for all three metrics. The greater the security requirement, the higher the score (remember that medium is considered the default). These metrics will modify the score as much as plus or minus 2.5.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.3.3: Security Requirements (`CR`, `IR`, `AR`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{Requirement, Metric}};
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
  /// # use polycvss::v2::{Requirement, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::ConfidentialityRequirement(Requirement::Medium).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "CR:M");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{Requirement, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::ConfidentialityRequirement(Requirement::Low));
  ///
  /// // check result
  /// assert_eq!(name, Name::ConfidentialityRequirement);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#2-3-3-Security-Requirements-CR-IR-AR
  ///   "CVSS v2.0 Documentation, Section 2.3.3: Security Requirements (CR, IR, AR)"
  ConfidentialityRequirement(Requirement),

  /// Integrity Requirement (`IR`) metric.
  ///
  /// # Description
  ///
  /// These metrics enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a users organization, measured in terms of confidentiality, integrity, and availability, That is, if an IT asset supports a business function for which availability is most important, the analyst can assign a greater value to availability, relative to confidentiality and integrity. Each security requirement has three possible values: low, medium, or high.
  ///
  /// The full effect on the environmental score is determined by the corresponding base impact metrics (please note that the base confidentiality, integrity and availability impact metrics, themselves, are not changed). That is, these metrics modify the environmental score by reweighting the (base) confidentiality, integrity, and availability impact metrics. For example, the confidentiality impact (C) metric has increased weight if the confidentiality requirement (CR) is high. Likewise, the confidentiality impact metric has decreased weight if the confidentiality requirement is low. The confidentiality impact metric weighting is neutral if the confidentiality requirement is medium. This same logic is applied to the integrity and availability requirements.
  ///
  /// Note that the confidentiality requirement will not affect the environmental score if the (base) confidentiality impact is set to none. Also, increasing the confidentiality requirement from medium to high will not change the environmental score when the (base) impact metrics are set to complete. This is because the impact sub score (part of the base score that calculates impact) is already at a maximum value of 10.
  ///
  /// The possible values for the security requirements are listed in Table 12. For brevity, the same table is used for all three metrics. The greater the security requirement, the higher the score (remember that medium is considered the default). These metrics will modify the score as much as plus or minus 2.5.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.3.3: Security Requirements (`CR`, `IR`, `AR`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{Requirement, Metric}};
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
  /// # use polycvss::v2::{Requirement, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::IntegrityRequirement(Requirement::Medium).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "IR:M");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{Requirement, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::IntegrityRequirement(Requirement::Low));
  ///
  /// // check result
  /// assert_eq!(name, Name::IntegrityRequirement);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#2-3-3-Security-Requirements-CR-IR-AR
  ///   "CVSS v2.0 Documentation, Section 2.3.3: Security Requirements (CR, IR, AR)"
  IntegrityRequirement(Requirement),

  /// Availability Requirement (`AR`) metric.
  ///
  /// # Description
  ///
  /// These metrics enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a users organization, measured in terms of confidentiality, integrity, and availability, That is, if an IT asset supports a business function for which availability is most important, the analyst can assign a greater value to availability, relative to confidentiality and integrity. Each security requirement has three possible values: low, medium, or high.
  ///
  /// The full effect on the environmental score is determined by the corresponding base impact metrics (please note that the base confidentiality, integrity and availability impact metrics, themselves, are not changed). That is, these metrics modify the environmental score by reweighting the (base) confidentiality, integrity, and availability impact metrics. For example, the confidentiality impact (C) metric has increased weight if the confidentiality requirement (CR) is high. Likewise, the confidentiality impact metric has decreased weight if the confidentiality requirement is low. The confidentiality impact metric weighting is neutral if the confidentiality requirement is medium. This same logic is applied to the integrity and availability requirements.
  ///
  /// Note that the confidentiality requirement will not affect the environmental score if the (base) confidentiality impact is set to none. Also, increasing the confidentiality requirement from medium to high will not change the environmental score when the (base) impact metrics are set to complete. This is because the impact sub score (part of the base score that calculates impact) is already at a maximum value of 10.
  ///
  /// The possible values for the security requirements are listed in Table 12. For brevity, the same table is used for all three metrics. The greater the security requirement, the higher the score (remember that medium is considered the default). These metrics will modify the score as much as plus or minus 2.5.
  ///
  /// # Properties
  ///
  /// - Metric Group: Environmental
  /// - Documentation: [CVSS v2.0 Documentation, Section 2.3.3: Security Requirements (`CR`, `IR`, `AR`)][doc]
  ///
  /// # Examples
  ///
  /// Parse string as metric:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{Requirement, Metric}};
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
  /// # use polycvss::v2::{Requirement, Metric};
  /// # fn main() {
  /// // convert metric to string
  /// let s = Metric::AvailabilityRequirement(Requirement::Medium).to_string();
  ///
  /// // check result
  /// assert_eq!(s, "AR:M");
  /// # }
  /// ```
  ///
  /// Get metric name:
  ///
  /// ```
  /// # use polycvss::v2::{Requirement, Metric, Name};
  /// # fn main() {
  /// // get metric name
  /// let name = Name::from(Metric::AvailabilityRequirement(Requirement::Low));
  ///
  /// // check result
  /// assert_eq!(name, Name::AvailabilityRequirement);
  /// # }
  /// ```
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#2-3-3-Security-Requirements-CR-IR-AR
  ///   "CVSS v2.0 Documentation, Section 2.3.3: Security Requirements (CR, IR, AR)"
  AvailabilityRequirement(Requirement),
}

impl std::fmt::Display for Metric {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{}", match self {
      Metric::AccessVector(AccessVector::Local) => "AV:L",
      Metric::AccessVector(AccessVector::AdjacentNetwork) => "AV:A",
      Metric::AccessVector(AccessVector::Network) => "AV:N",

      Metric::AccessComplexity(AccessComplexity::High) => "AC:H",
      Metric::AccessComplexity(AccessComplexity::Medium) => "AC:M",
      Metric::AccessComplexity(AccessComplexity::Low) => "AC:L",

      Metric::Authentication(Authentication::Multiple) => "Au:M",
      Metric::Authentication(Authentication::Single) => "Au:S",
      Metric::Authentication(Authentication::None) => "Au:N",

      Metric::Confidentiality(Impact::None) => "C:N",
      Metric::Confidentiality(Impact::Partial) => "C:P",
      Metric::Confidentiality(Impact::Complete) => "C:C",

      Metric::Integrity(Impact::None) => "I:N",
      Metric::Integrity(Impact::Partial) => "I:P",
      Metric::Integrity(Impact::Complete) => "I:C",

      Metric::Availability(Impact::None) => "A:N",
      Metric::Availability(Impact::Partial) => "A:P",
      Metric::Availability(Impact::Complete) => "A:C",

      Metric::Exploitability(Exploitability::NotDefined) => "E:ND",
      Metric::Exploitability(Exploitability::Unproven) => "E:U",
      Metric::Exploitability(Exploitability::ProofOfConcept) => "E:POC",
      Metric::Exploitability(Exploitability::Functional) => "E:F",
      Metric::Exploitability(Exploitability::High) => "E:H",

      Metric::RemediationLevel(RemediationLevel::NotDefined) => "RL:ND",
      Metric::RemediationLevel(RemediationLevel::OfficialFix) => "RL:OF",
      Metric::RemediationLevel(RemediationLevel::TemporaryFix) => "RL:TF",
      Metric::RemediationLevel(RemediationLevel::Workaround) => "RL:W",
      Metric::RemediationLevel(RemediationLevel::Unavailable) => "RL:U",

      Metric::ReportConfidence(ReportConfidence::NotDefined) => "RC:ND",
      Metric::ReportConfidence(ReportConfidence::Unconfirmed) => "RC:UC",
      Metric::ReportConfidence(ReportConfidence::Uncorroborated) => "RC:UR",
      Metric::ReportConfidence(ReportConfidence::Confirmed) => "RC:C",

      Metric::CollateralDamagePotential(CollateralDamagePotential::NotDefined) => "CDP:ND",
      Metric::CollateralDamagePotential(CollateralDamagePotential::None) => "CDP:N",
      Metric::CollateralDamagePotential(CollateralDamagePotential::Low) => "CDP:L",
      Metric::CollateralDamagePotential(CollateralDamagePotential::LowMedium) => "CDP:LM",
      Metric::CollateralDamagePotential(CollateralDamagePotential::MediumHigh) => "CDP:MH",
      Metric::CollateralDamagePotential(CollateralDamagePotential::High) => "CDP:H",

      Metric::TargetDistribution(TargetDistribution::NotDefined) => "TD:ND",
      Metric::TargetDistribution(TargetDistribution::None) => "TD:N",
      Metric::TargetDistribution(TargetDistribution::Low) => "TD:L",
      Metric::TargetDistribution(TargetDistribution::Medium) => "TD:M",
      Metric::TargetDistribution(TargetDistribution::High) => "TD:H",

      Metric::ConfidentialityRequirement(Requirement::NotDefined) => "CR:ND",
      Metric::ConfidentialityRequirement(Requirement::Low) => "CR:L",
      Metric::ConfidentialityRequirement(Requirement::Medium) => "CR:M",
      Metric::ConfidentialityRequirement(Requirement::High) => "CR:H",

      Metric::IntegrityRequirement(Requirement::NotDefined) => "IR:ND",
      Metric::IntegrityRequirement(Requirement::Low) => "IR:L",
      Metric::IntegrityRequirement(Requirement::Medium) => "IR:M",
      Metric::IntegrityRequirement(Requirement::High) => "IR:H",

      Metric::AvailabilityRequirement(Requirement::NotDefined) => "AR:ND",
      Metric::AvailabilityRequirement(Requirement::Low) => "AR:L",
      Metric::AvailabilityRequirement(Requirement::Medium) => "AR:M",
      Metric::AvailabilityRequirement(Requirement::High) => "AR:H",
    })
  }
}

impl std::str::FromStr for Metric {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "AV:L" => Ok(Metric::AccessVector(AccessVector::Local)),
      "AV:A" => Ok(Metric::AccessVector(AccessVector::AdjacentNetwork)),
      "AV:N" => Ok(Metric::AccessVector(AccessVector::Network)),

      "AC:H" => Ok(Metric::AccessComplexity(AccessComplexity::High)),
      "AC:M" => Ok(Metric::AccessComplexity(AccessComplexity::Medium)),
      "AC:L" => Ok(Metric::AccessComplexity(AccessComplexity::Low)),

      "Au:M" => Ok(Metric::Authentication(Authentication::Multiple)),
      "Au:S" => Ok(Metric::Authentication(Authentication::Single)),
      "Au:N" => Ok(Metric::Authentication(Authentication::None)),

      "C:N" => Ok(Metric::Confidentiality(Impact::None)),
      "C:P" => Ok(Metric::Confidentiality(Impact::Partial)),
      "C:C" => Ok(Metric::Confidentiality(Impact::Complete)),

      "I:N" => Ok(Metric::Integrity(Impact::None)),
      "I:P" => Ok(Metric::Integrity(Impact::Partial)),
      "I:C" => Ok(Metric::Integrity(Impact::Complete)),

      "A:N" => Ok(Metric::Availability(Impact::None)),
      "A:P" => Ok(Metric::Availability(Impact::Partial)),
      "A:C" => Ok(Metric::Availability(Impact::Complete)),

      "E:ND" => Ok(Metric::Exploitability(Exploitability::NotDefined)),
      "E:U" => Ok(Metric::Exploitability(Exploitability::Unproven)),
      "E:POC" => Ok(Metric::Exploitability(Exploitability::ProofOfConcept)),
      "E:F" => Ok(Metric::Exploitability(Exploitability::Functional)),
      "E:H" => Ok(Metric::Exploitability(Exploitability::High)),

      "RL:ND" => Ok(Metric::RemediationLevel(RemediationLevel::NotDefined)),
      "RL:OF" => Ok(Metric::RemediationLevel(RemediationLevel::OfficialFix)),
      "RL:TF" => Ok(Metric::RemediationLevel(RemediationLevel::TemporaryFix)),
      "RL:W" => Ok(Metric::RemediationLevel(RemediationLevel::Workaround)),
      "RL:U" => Ok(Metric::RemediationLevel(RemediationLevel::Unavailable)),

      "RC:ND" => Ok(Metric::ReportConfidence(ReportConfidence::NotDefined)),
      "RC:UC" => Ok(Metric::ReportConfidence(ReportConfidence::Unconfirmed)),
      "RC:UR" => Ok(Metric::ReportConfidence(ReportConfidence::Uncorroborated)),
      "RC:C" => Ok(Metric::ReportConfidence(ReportConfidence::Confirmed)),

      "CDP:ND" => Ok(Metric::CollateralDamagePotential(CollateralDamagePotential::NotDefined)),
      "CDP:N" => Ok(Metric::CollateralDamagePotential(CollateralDamagePotential::None)),
      "CDP:L" => Ok(Metric::CollateralDamagePotential(CollateralDamagePotential::Low)),
      "CDP:LM" => Ok(Metric::CollateralDamagePotential(CollateralDamagePotential::LowMedium)),
      "CDP:MH" => Ok(Metric::CollateralDamagePotential(CollateralDamagePotential::MediumHigh)),
      "CDP:H" => Ok(Metric::CollateralDamagePotential(CollateralDamagePotential::High)),

      "TD:ND" => Ok(Metric::TargetDistribution(TargetDistribution::NotDefined)),
      "TD:N" => Ok(Metric::TargetDistribution(TargetDistribution::None)),
      "TD:L" => Ok(Metric::TargetDistribution(TargetDistribution::Low)),
      "TD:M" => Ok(Metric::TargetDistribution(TargetDistribution::Medium)),
      "TD:H" => Ok(Metric::TargetDistribution(TargetDistribution::High)),

      "CR:ND" => Ok(Metric::ConfidentialityRequirement(Requirement::NotDefined)),
      "CR:L" => Ok(Metric::ConfidentialityRequirement(Requirement::Low)),
      "CR:M" => Ok(Metric::ConfidentialityRequirement(Requirement::Medium)),
      "CR:H" => Ok(Metric::ConfidentialityRequirement(Requirement::High)),

      "IR:ND" => Ok(Metric::IntegrityRequirement(Requirement::NotDefined)),
      "IR:L" => Ok(Metric::IntegrityRequirement(Requirement::Low)),
      "IR:M" => Ok(Metric::IntegrityRequirement(Requirement::Medium)),
      "IR:H" => Ok(Metric::IntegrityRequirement(Requirement::High)),

      "AR:ND" => Ok(Metric::AvailabilityRequirement(Requirement::NotDefined)),
      "AR:L" => Ok(Metric::AvailabilityRequirement(Requirement::Low)),
      "AR:M" => Ok(Metric::AvailabilityRequirement(Requirement::Medium)),
      "AR:H" => Ok(Metric::AvailabilityRequirement(Requirement::High)),

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
      Metric::AccessVector(AccessVector::Local) => (0, EncodedVal::Shift(0)), // "AV:L"
      Metric::AccessVector(AccessVector::AdjacentNetwork) => (0, EncodedVal::Shift(1)), // "AV:A"
      Metric::AccessVector(AccessVector::Network) => (0, EncodedVal::Shift(2)), // "AV:N"

      Metric::AccessComplexity(AccessComplexity::High) => (1, EncodedVal::Shift(0 << 2)), // "AC:H"
      Metric::AccessComplexity(AccessComplexity::Medium) => (1, EncodedVal::Shift(1 << 2)), // "AC:M"
      Metric::AccessComplexity(AccessComplexity::Low) => (1, EncodedVal::Shift(2 << 2)), // "AC:L"

      Metric::Authentication(Authentication::Multiple) => (2, EncodedVal::Shift(0 << 4)), // "Au:M"
      Metric::Authentication(Authentication::Single) => (2, EncodedVal::Shift(1 << 4)), // "Au:S"
      Metric::Authentication(Authentication::None) => (2, EncodedVal::Shift(2 << 4)), // "Au:N"

      Metric::Confidentiality(Impact::None) => (3, EncodedVal::Shift(0 << 6)), // "C:N"
      Metric::Confidentiality(Impact::Partial) => (3, EncodedVal::Shift(1 << 6)), // "C:P"
      Metric::Confidentiality(Impact::Complete) => (3, EncodedVal::Shift(2 << 6)), // "C:C"

      Metric::Integrity(Impact::None) => (4, EncodedVal::Shift(0 << 8)), // "I:N"
      Metric::Integrity(Impact::Partial) => (4, EncodedVal::Shift(1 << 8)), // "I:P"
      Metric::Integrity(Impact::Complete) => (4, EncodedVal::Shift(2 << 8)), // "I:C"

      Metric::Availability(Impact::None) => (5, EncodedVal::Shift(0 << 10)), // "A:N"
      Metric::Availability(Impact::Partial) => (5, EncodedVal::Shift(1 << 10)), // "A:P"
      Metric::Availability(Impact::Complete) => (5, EncodedVal::Shift(2 << 10)), // "A:C"

      Metric::Exploitability(Exploitability::NotDefined) => (6, EncodedVal::Shift(0 << 12)), // "E:ND"
      Metric::Exploitability(Exploitability::Unproven) => (6, EncodedVal::Shift(1 << 12)), // "E:U"
      Metric::Exploitability(Exploitability::ProofOfConcept) => (6, EncodedVal::Shift(2 << 12)), // "E:POC"
      Metric::Exploitability(Exploitability::Functional) => (6, EncodedVal::Shift(3 << 12)), // "E:F"
      Metric::Exploitability(Exploitability::High) => (6, EncodedVal::Shift(4 << 12)), // "E:H"

      Metric::RemediationLevel(RemediationLevel::NotDefined) => (7, EncodedVal::Shift(0 << 15)), // "RL:ND"
      Metric::RemediationLevel(RemediationLevel::OfficialFix) => (7, EncodedVal::Shift(1 << 15)), // "RL:OF"
      Metric::RemediationLevel(RemediationLevel::TemporaryFix) => (7, EncodedVal::Shift(2 << 15)), // "RL:TF"
      Metric::RemediationLevel(RemediationLevel::Workaround) => (7, EncodedVal::Shift(3 << 15)), // "RL:W"
      Metric::RemediationLevel(RemediationLevel::Unavailable) => (7, EncodedVal::Shift(4 << 15)), // "RL:U"

      Metric::ReportConfidence(ReportConfidence::NotDefined) => (8, EncodedVal::Shift(0 << 18)), // "RC:ND"
      Metric::ReportConfidence(ReportConfidence::Unconfirmed) => (8, EncodedVal::Shift(1 << 18)), // "RC:UC"
      Metric::ReportConfidence(ReportConfidence::Uncorroborated) => (8, EncodedVal::Shift(2 << 18)), // "RC:UR"
      Metric::ReportConfidence(ReportConfidence::Confirmed) => (8, EncodedVal::Shift(3 << 18)), // "RC:C"

      Metric::CollateralDamagePotential(CollateralDamagePotential::NotDefined) => (9, EncodedVal::Shift(0 << 20)), // "CDP:ND"
      Metric::CollateralDamagePotential(CollateralDamagePotential::None) => (9, EncodedVal::Shift(1 << 20)), // "CDP:N"
      Metric::CollateralDamagePotential(CollateralDamagePotential::Low) => (9, EncodedVal::Shift(2 << 20)), // "CDP:L"
      Metric::CollateralDamagePotential(CollateralDamagePotential::LowMedium) => (9, EncodedVal::Shift(3 << 20)), // "CDP:LM"
      Metric::CollateralDamagePotential(CollateralDamagePotential::MediumHigh) => (9, EncodedVal::Shift(4 << 20)), // "CDP:MH"
      Metric::CollateralDamagePotential(CollateralDamagePotential::High) => (9, EncodedVal::Shift(5 << 20)), // "CDP:H"

      Metric::TargetDistribution(TargetDistribution::NotDefined) => (10, EncodedVal::Shift(0 << 23)), // "TD:ND"
      Metric::TargetDistribution(TargetDistribution::None) => (10, EncodedVal::Shift(1 << 23)), // "TD:N"
      Metric::TargetDistribution(TargetDistribution::Low) => (10, EncodedVal::Shift(2 << 23)), // "TD:L"
      Metric::TargetDistribution(TargetDistribution::Medium) => (10, EncodedVal::Shift(3 << 23)), // "TD:M"
      Metric::TargetDistribution(TargetDistribution::High) => (10, EncodedVal::Shift(4 << 23)), // "TD:H"

      Metric::ConfidentialityRequirement(Requirement::NotDefined) => (11, EncodedVal::Shift(0 << 26)), // "CR:ND"
      Metric::ConfidentialityRequirement(Requirement::Low) => (11, EncodedVal::Shift(1 << 26)), // "CR:L"
      Metric::ConfidentialityRequirement(Requirement::Medium) => (11, EncodedVal::Shift(2 << 26)), // "CR:M"
      Metric::ConfidentialityRequirement(Requirement::High) => (11, EncodedVal::Shift(3 << 26)), // "CR:H"

      Metric::IntegrityRequirement(Requirement::NotDefined) => (12, EncodedVal::Shift(0 << 28)), // "IR:ND"
      Metric::IntegrityRequirement(Requirement::Low) => (12, EncodedVal::Shift(1 << 28)), // "IR:L"
      Metric::IntegrityRequirement(Requirement::Medium) => (12, EncodedVal::Shift(2 << 28)), // "IR:M"
      Metric::IntegrityRequirement(Requirement::High) => (12, EncodedVal::Shift(3 << 28)), // "IR:H"

      Metric::AvailabilityRequirement(Requirement::NotDefined) => (13, EncodedVal::Shift(0 << 30)), // "AR:ND"
      Metric::AvailabilityRequirement(Requirement::Low) => (13, EncodedVal::Shift(1 << 30)), // "AR:L"
      Metric::AvailabilityRequirement(Requirement::Medium) => (13, EncodedVal::Shift(2 << 30)), // "AR:M"
      Metric::AvailabilityRequirement(Requirement::High) => (13, EncodedVal::Shift(3 << 30)), // "AR:H"
    };

    EncodedMetric { bit: 1 << bit, val }
  }
}

// Internal array of metrics.
//
// Used by the following methods to decode metric values from a
// `u64`: `Vector::get()`, `Vector::fmt()`, and
// `VectorIterator::next()`.
const METRICS: [Metric; 55] = [
  Metric::AccessVector(AccessVector::Local), // "AV:L"
  Metric::AccessVector(AccessVector::AdjacentNetwork), // "AV:A"
  Metric::AccessVector(AccessVector::Network), // "AV:N"

  Metric::AccessComplexity(AccessComplexity::High), // "AC:H"
  Metric::AccessComplexity(AccessComplexity::Medium), // "AC:M"
  Metric::AccessComplexity(AccessComplexity::Low), // "AC:L"

  Metric::Authentication(Authentication::Multiple), // "Au:M"
  Metric::Authentication(Authentication::Single), // "Au:S"
  Metric::Authentication(Authentication::None), // "Au:N"

  Metric::Confidentiality(Impact::None), // "C:N"
  Metric::Confidentiality(Impact::Partial), // "C:P"
  Metric::Confidentiality(Impact::Complete), // "C:C"

  Metric::Integrity(Impact::None), // "I:N"
  Metric::Integrity(Impact::Partial), // "I:P"
  Metric::Integrity(Impact::Complete), // "I:C"

  Metric::Availability(Impact::None), // "A:N"
  Metric::Availability(Impact::Partial), // "A:P"
  Metric::Availability(Impact::Complete), // "A:C"

  Metric::Exploitability(Exploitability::NotDefined), // "E:ND"
  Metric::Exploitability(Exploitability::Unproven), // "E:U"
  Metric::Exploitability(Exploitability::ProofOfConcept), // "E:POC"
  Metric::Exploitability(Exploitability::Functional), // "E:F"
  Metric::Exploitability(Exploitability::High), // "E:H"

  Metric::RemediationLevel(RemediationLevel::NotDefined), // "RL:ND"
  Metric::RemediationLevel(RemediationLevel::OfficialFix), // "RL:OF"
  Metric::RemediationLevel(RemediationLevel::TemporaryFix), // "RL:TF"
  Metric::RemediationLevel(RemediationLevel::Workaround), // "RL:W"
  Metric::RemediationLevel(RemediationLevel::Unavailable), // "RL:U"

  Metric::ReportConfidence(ReportConfidence::NotDefined), // "RC:ND"
  Metric::ReportConfidence(ReportConfidence::Unconfirmed), // "RC:UC"
  Metric::ReportConfidence(ReportConfidence::Uncorroborated), // "RC:UR"
  Metric::ReportConfidence(ReportConfidence::Confirmed), // "RC:C"

  Metric::CollateralDamagePotential(CollateralDamagePotential::NotDefined), // "CDP:ND"
  Metric::CollateralDamagePotential(CollateralDamagePotential::None), // "CDP:N"
  Metric::CollateralDamagePotential(CollateralDamagePotential::Low), // "CDP:L"
  Metric::CollateralDamagePotential(CollateralDamagePotential::LowMedium), // "CDP:LM"
  Metric::CollateralDamagePotential(CollateralDamagePotential::MediumHigh), // "CDP:MH"
  Metric::CollateralDamagePotential(CollateralDamagePotential::High), // "CDP:H"

  Metric::TargetDistribution(TargetDistribution::NotDefined), // "TD:ND"
  Metric::TargetDistribution(TargetDistribution::None), // "TD:N"
  Metric::TargetDistribution(TargetDistribution::Low), // "TD:L"
  Metric::TargetDistribution(TargetDistribution::Medium), // "TD:M"
  Metric::TargetDistribution(TargetDistribution::High), // "TD:H"

  Metric::ConfidentialityRequirement(Requirement::NotDefined), // "CR:ND"
  Metric::ConfidentialityRequirement(Requirement::Low), // "CR:L"
  Metric::ConfidentialityRequirement(Requirement::Medium), // "CR:M"
  Metric::ConfidentialityRequirement(Requirement::High), // "CR:H"

  Metric::IntegrityRequirement(Requirement::NotDefined), // "IR:ND"
  Metric::IntegrityRequirement(Requirement::Low), // "IR:L"
  Metric::IntegrityRequirement(Requirement::Medium), // "IR:M"
  Metric::IntegrityRequirement(Requirement::High), // "IR:H"

  Metric::AvailabilityRequirement(Requirement::NotDefined), // "AR:ND"
  Metric::AvailabilityRequirement(Requirement::Low), // "AR:L"
  Metric::AvailabilityRequirement(Requirement::Medium), // "AR:M"
  Metric::AvailabilityRequirement(Requirement::High), // "AR:H"
];

// Data used to decode metrics from a u64-encoded vector.
enum Decode {
  Shift(Name, usize, (usize, usize)), // key, shift, values range
  // Arith(Name, usize, (usize, usize)), // key, denominator, values range
}

impl From<Name> for Decode {
  fn from(name: Name) -> Decode {
    // note: copied from `DECODES` above
    match name {
      Name::AccessVector => Decode::Shift(Name::AccessVector, 0, (0, 3)), // AV
      Name::AccessComplexity => Decode::Shift(Name::AccessComplexity, 2, (3, 6)), // AC
      Name::Authentication => Decode::Shift(Name::Authentication, 4, (6, 9)), // Au
      Name::Confidentiality => Decode::Shift(Name::Confidentiality, 6, (9, 12)), // C
      Name::Integrity => Decode::Shift(Name::Integrity, 8, (12, 15)), // I
      Name::Availability => Decode::Shift(Name::Availability, 10, (15, 18)), // A
      Name::Exploitability => Decode::Shift(Name::Exploitability, 12, (18, 23)), // E
      Name::RemediationLevel => Decode::Shift(Name::RemediationLevel, 15, (23, 28)), // RL
      Name::ReportConfidence => Decode::Shift(Name::ReportConfidence, 18, (28, 32)), // RC
      Name::CollateralDamagePotential => Decode::Shift(Name::CollateralDamagePotential, 20, (32, 38)), // CDP
      Name::TargetDistribution => Decode::Shift(Name::TargetDistribution, 23, (38, 43)), // TD
      Name::ConfidentialityRequirement => Decode::Shift(Name::ConfidentialityRequirement, 26, (43, 47)), // CR
      Name::IntegrityRequirement => Decode::Shift(Name::IntegrityRequirement, 28, (47, 51)), // IR
      Name::AvailabilityRequirement => Decode::Shift(Name::AvailabilityRequirement, 30, (51, 55)), // AR
    }
  }
}

// Metric decodes.
//
// Used by `Vector::fmt()` and `VectorIterator::next()` to decode a
// u64-encoded vector into individual metrics in canonical order.
//
// Sorted in order specified in Table 11 in [Section 2.4 of the CVSS v2.0
// Documentation][vector-string].
//
// [vector-string]: https://www.first.org/cvss/v2/guide#2-4-Base-Temporal-Environmental-Vectors
//   "CVSS v2.0 Documentation, Section 2.4: Base, Temporal, Environmental Vectors"
const DECODES: [Decode; 14] = [
  Decode::Shift(Name::AccessVector, 0, (0, 3)), // AV
  Decode::Shift(Name::AccessComplexity, 2, (3, 6)), // AC
  Decode::Shift(Name::Authentication, 4, (6, 9)), // Au
  Decode::Shift(Name::Confidentiality, 6, (9, 12)), // C
  Decode::Shift(Name::Integrity, 8, (12, 15)), // I
  Decode::Shift(Name::Availability, 10, (15, 18)), // A
  Decode::Shift(Name::Exploitability, 12, (18, 23)), // E
  Decode::Shift(Name::RemediationLevel, 15, (23, 28)), // RL
  Decode::Shift(Name::ReportConfidence, 18, (28, 32)), // RC
  Decode::Shift(Name::CollateralDamagePotential, 20, (32, 38)), // CDP
  Decode::Shift(Name::TargetDistribution, 23, (38, 43)), // TD
  Decode::Shift(Name::ConfidentialityRequirement, 26, (43, 47)), // CR
  Decode::Shift(Name::IntegrityRequirement, 28, (47, 51)), // IR
  Decode::Shift(Name::AvailabilityRequirement, 30, (51, 55)), // AR
];

/// [`Vector`][] iterator.
///
/// # Description
///
/// Used to iterate over the defined [`Metric`s][Metric] of a
/// [`Vector`][] in the order specified in Table 11 in [Section 2.4 of
/// the CVSS v2.0 documentation][vector-string].
///
/// Created by [`Vector::into_iter()`][].
///
/// # Examples
///
/// Iterate over [`Vector`][] and appending each [`Metric`][]
/// to a [`std::vec::Vec`][]:
///
/// ```
/// # use polycvss::{Err, v2::{AccessVector, AccessComplexity, Authentication, Impact, Metric, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string
/// let v: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
///
/// // get defined metrics
/// let mut metrics = Vec::new();
/// for metric in v {
///   metrics.push(metric);
/// }
///
/// // check result
/// assert_eq!(metrics, vec!(
///   Metric::AccessVector(AccessVector::Network),
///   Metric::AccessComplexity(AccessComplexity::Low),
///   Metric::Authentication(Authentication::None),
///   Metric::Confidentiality(Impact::Complete),
///   Metric::Integrity(Impact::Complete),
///   Metric::Availability(Impact::Complete),
/// ));
/// # Ok(())
/// # }
/// ```
///
/// Same as above, but shorter:
///
/// ```
/// # use polycvss::{Err, v2::{AccessVector, AccessComplexity, Authentication, Impact, Metric, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string
/// let v: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
///
/// // get defined metrics
/// let metrics: Vec<Metric> = v.into_iter().collect();
///
/// // check result
/// assert_eq!(metrics, vec!(
///   Metric::AccessVector(AccessVector::Network),
///   Metric::AccessComplexity(AccessComplexity::Low),
///   Metric::Authentication(Authentication::None),
///   Metric::Confidentiality(Impact::Complete),
///   Metric::Integrity(Impact::Complete),
///   Metric::Availability(Impact::Complete),
/// ));
/// # Ok(())
/// # }
/// ```
///
/// Create a explicit iterator over [`Vector`][] and get the first
/// [`Metric`][]:
///
/// ```
/// # use polycvss::{Err, v2::{AccessVector, Metric, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string
/// let v: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
///
/// // create iterator
/// let mut iter = v.into_iter();
///
/// // get first metric
/// let metric = iter.next();
///
/// // check result
/// assert_eq!(metric, Some(Metric::AccessVector(AccessVector::Network)));
/// # Ok(())
/// # }
/// ```
///
/// [vector-string]: https://www.first.org/cvss/v2/guide#2-4-Base-Temporal-Environmental-Vectors
///   "CVSS v2.0 Documentation, Section 2.4: Base, Temporal, Environmental Vectors"
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
        Decode::Shift(key, shift, range) => {
          let vals = &METRICS[range.0..range.1];
          let mask = match vals.len() {
            2 => 0b001,
            3 | 4 => 0b011,
            5 | 6 => 0b111,
            _ => unreachable!(),
          };
          let ofs = ((self.val >> shift) as usize) & mask;
          (key.is_mandatory() || ofs > 0, vals[ofs])
        },
        // _ => unreachable!(),
      };

      if found {
        return Some(val) // found defined metric, return it
      }

      self.pos += 1; // step
    }
  }
}

/// [CVSS v2][cvss20] vector.
///
/// Notes:
///
/// - Represented internally as a `u64`.  See "Internal Representation" below.
/// - When iterating the metrics in a [`Vector`][] or converting a
///   [`Vector`][] to a string, the metrics are sorted in the order
///   specified in Table 11 of [Section 2.4 of the CVSS v2.0
///   documentation][vector-string]; the sort order of metrics within
///   the source vector string is **not** preserved. See "Examples" below.
/// - Optional metrics with a value of `Not Defined (ND)` are skipped
///   when iterating the metrics in a [`Vector`][] and when converting a
///   [`Vector`][] to a string. See "Examples" below.
///
/// # Examples
///
/// Parse a [`&str`][] into a [`Vector`][]:
///
/// ```
/// # use polycvss::{Err, v2::Vector};
/// # fn main() -> Result<(), Err> {
/// // CVSS v2 vector string
/// let s = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
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
/// # use polycvss::{Err, v2::{Scores, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v2 vector string
/// let v: Vector = "AV:N/AC:L/Au:N/C:N/I:N/A:C".parse()?;
///
/// // get scores
/// let scores = Scores::from(v);
///
/// // check result
/// assert_eq!(scores.base.to_string(), "7.8");
/// # Ok(())
/// # }
/// ```
///
/// Iterate over [`Metric`s][Metric] in a [`Vector`][]:
///
/// ```
/// # use polycvss::{Err, v2::Vector};
/// # fn main() -> Result<(), Err> {
/// // parse vector string
/// let v: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
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
/// # use polycvss::{Err, v2::{AccessVector, Vector, Metric, Name}};
/// # fn main() -> Result<(), Err> {
/// // parse vector string
/// let v: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
///
/// // get metric
/// let metric = v.get(Name::AccessVector);
///
/// // check result
/// assert_eq!(metric, Metric::AccessVector(AccessVector::Network));
/// # Ok(())
/// # }
/// ```
///
/// Show that the order of metrics within a vector string is **not**
/// preserved when parsing a vector string and then converting the
/// [`Vector`][] back to a string:
///
/// ```
/// # use polycvss::{Err, v2::Vector};
/// # fn main() -> Result<(), Err> {
/// // vector string with first two metrics (AV and AC) swapped
/// let s = "AC:L/AV:N/Au:N/C:C/I:C/A:C";
///
/// // expected result after parsing vector string above and converting
/// // the parsed vector back to a vector string
/// let exp = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
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
/// Show that optional metrics with a value of `Not Defined (ND)` are
/// **not** preserved when parsing a vector string and then converting the
/// [`Vector`][] back to a string:
///
/// ```
/// # use polycvss::{Err, v2::Vector};
/// # fn main() -> Result<(), Err> {
/// // vector string which contains an optional metric (MAV) with a
/// // value of `Not Defined (ND)`
/// let s = "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:ND";
///
/// // expected result after parsing vector string above and converting
/// // the parsed vector back to a vector string
/// let exp = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
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
/// # use polycvss::v2::Vector;
/// # fn main() {
/// assert_eq!(size_of::<Vector>(), size_of::<u64>());
/// # }
/// ```
///
/// # Internal Representation
///
/// A [`Vector`][] is represented internally as a [bit field][bit-field]
/// in the lower 32 bits (bits `0..32`) of a [`u64`][],  The number of
/// bits used by a metric value is calculated by the number of possible
/// values for that metric (e.g. `num_bits = ceil(log2(num_vals))`):
///
/// | # of Values | # of Bits |
/// | ----------- | --------- |
/// | 2 values    | 1 bit     |
/// | 3 values    | 2 bits    |
/// | 4 values    | 2 bits    |
/// | 5 values    | 3 bits    |
///
/// [cvss20]: https://www.first.org/cvss/v2/guide
///   "CVSS v2.0 Documentation"
/// [bit-field]: https://en.wikipedia.org/wiki/Bit_field
///   "Bit field (Wikipedia)"
/// [vector-string]: https://www.first.org/cvss/v2/guide#2-4-Base-Temporal-Environmental-Vectors
///   "CVSS v2.0 Documentation, Section 2.4: Base, Temporal, Environmental Vectors"
#[derive(Clone,Copy,Debug,PartialEq)]
// #[cfg_attr(feature="serde", serde(try_from="String"))]
// #[cfg_attr(feature="serde", derive(Deserialize,Serialize)]
pub struct Vector(u64);

impl Vector {
  /// Get [`Metric`][] from [`Vector`][] by [`Name`][].
  ///
  /// # Examples
  ///
  /// Get metric from vector:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{AccessVector, Vector, Metric, Name}};
  /// # fn main() -> Result<(), Err> {
  /// // parse vector string
  /// let v: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
  ///
  /// // get metric
  /// let metric = v.get(Name::AccessVector);
  ///
  /// // check result
  /// assert_eq!(metric, Metric::AccessVector(AccessVector::Network));
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Get optional metric from vector:
  ///
  /// ```
  /// # use polycvss::{Err, v2::{Requirement, Vector, Metric, Name}};
  /// # fn main() -> Result<(), Err> {
  /// // parse vector string
  /// let v: Vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C".parse()?;
  ///
  /// // get metric
  /// let metric = v.get(Name::ConfidentialityRequirement);
  ///
  /// // check result
  /// assert_eq!(metric, Metric::ConfidentialityRequirement(Requirement::NotDefined));
  /// # Ok(())
  /// # }
  /// ```
  pub fn get(self, name: Name) -> Metric {
    match Decode::from(name) {
      Decode::Shift(_, shift, range) => {
        let vals = &METRICS[range.0..range.1];
        let mask = match vals.len() {
          2 => 0b001,
          3 | 4 => 0b011,
          5 | 6 => 0b111,
          _ => unreachable!(),
        };
        let ofs = ((self.0 >> shift) as usize) & mask;
        vals[ofs]
      },
      // _ => unreachable!(),
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
    if s.len() < 26 {
      return Err(Err::Len);
    }

    // split into metrics, then encode as u64
    let mut val = 0; // encoded PoT metrics
    let mut seen: u32 = 0; // seen keys
    for s in s.split('/') {
      let c = EncodedMetric::from(s.parse::<Metric>()?); // parse metric

      // check for duplicate key
      if seen & c.bit != 0 {
        return Err(Err::DuplicateName);
      }
      seen |= c.bit; // mark key as seen

      match c.val {
        EncodedVal::Shift(v) => val |= v,
        _ => unreachable!(),
      }
    }

    // check for missing mandatory metrics
    if seen & 0x3f != 0x3f {
      return Err(Err::MissingMandatoryMetrics);
    }

    // return encoded vector (assume v2.3)
    Ok(Vector(u64::from(Version::V23) | val))
  }
}

impl TryFrom<String> for Vector {
  type Error = Err;

  fn try_from(s: String) -> Result<Self, Self::Error> {
    s.parse::<Vector>()
  }
}

impl std::fmt::Display for Vector {
  // Format CVSS v2 vector as a string.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    // write metrics
    for pos in DECODES {
      let (found, val) = match pos {
        Decode::Shift(key, shift, range) => {
          let vals = &METRICS[range.0..range.1];
          let mask = match vals.len() {
            2 => 0b001,
            3 | 4 => 0b011,
            5 | 6 => 0b111,
            _ => unreachable!(),
          };
          let ofs = ((self.0 >> shift) as usize) & mask;
          (key.is_mandatory() || ofs > 0, vals[ofs])
        },
        // _ => unimplemented!(),
      };

      if found {
        match val {
          Metric::AccessVector(_) => write!(f, "{val}")?, // write AV w/o "/"
          _ => write!(f, "/{val}")?, // write other metrics with "/"
        }
      }
    }

    Ok(())
  }
}

/// [CVSS v2][doc] base, temporal, and environmental scores.
///
/// See [CVSS v2.0 Documentation, Section 3. Scoring][scoring].
///
/// # Example
///
/// Get base score for [CVSS v2][doc] vector:
///
/// ```
/// # use polycvss::{Err, v2::{Scores, Vector}};
/// # fn main() -> Result<(), Err> {
/// // parse CVSS v2 vector string
/// let v: Vector = "AV:N/AC:L/Au:N/C:N/I:N/A:C".parse()?;
///
/// // get scores
/// let scores = Scores::from(v);
///
/// // check result
/// assert_eq!(scores.base.to_string(), "7.8");
/// # Ok(())
/// # }
/// ```
///
/// [doc]: https://www.first.org/cvss/v2/guide
///   "CVSS v2.0 Documentation"
/// [scoring]: https://www.first.org/cvss/v2/guide#3-Scoring
///   "CVSS v2.0 Documentation, Section 3. Scoring"
#[derive(Clone,Copy,Debug,PartialEq)]
pub struct Scores {
  /// Base Score.
  ///
  /// See [CVSS v2.0 Documentation, Section 3.2.1. Base Equation][doc].
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#3-2-1-Base-Equation
  ///   "CVSS v2.0 Documentation, Section 3.2.1. Base Equation"
  pub base: Score,

  /// Temporal Score. Will have a value of `None` if no Temporal
  /// metrics are defined.
  ///
  /// See [CVSS v2.0 Documentation, Section 3.2.2. Temporal Equation][doc].
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#3-2-2-Temporal-Equation
  ///   "CVSS v2.0 Documentation, Section 3.2.2. Temporal Equation"
  pub temporal: Option<Score>,

  /// Environmental Score. Will have a value of `None` if no Temporal
  /// metrics are defined.
  ///
  /// See [CVSS v2.0 Documentation, Section 3.2.3. Environmental Equation][doc].
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#3-2-3-Environmental-Equation
  ///   "CVSS v2.0 Documentation, Section 3.2.3. Environmental Equation"
  pub environmental: Option<Score>,
}

impl From<Vector> for Scores {
  fn from(vec: Vector) -> Scores {
    // AccessVector = case AccessVector of
    //   requires local access: 0.395
    //   adjacent network accessible: 0.646
    //   network accessible: 1.0
    let av = match vec.get(Name::AccessVector) {
      Metric::AccessVector(AccessVector::Local) => 0.395,
      Metric::AccessVector(AccessVector::AdjacentNetwork) => 0.646,
      Metric::AccessVector(AccessVector::Network) => 1.0,
      _ => unreachable!(),
    };

    // AccessComplexity = case AccessComplexity of
    //   high: 0.35
    //   medium: 0.61
    //   low: 0.71
    let ac = match vec.get(Name::AccessComplexity) {
      Metric::AccessComplexity(AccessComplexity::High) => 0.35,
      Metric::AccessComplexity(AccessComplexity::Medium) => 0.61,
      Metric::AccessComplexity(AccessComplexity::Low) => 0.71,
      _ => unreachable!(),
    };

    // Authentication = case Authentication of
    //   requires multiple instances of authentication: 0.45
    //   requires single instance of authentication: 0.56
    //   requires no authentication: 0.704
    let au = match vec.get(Name::Authentication) {
      Metric::Authentication(Authentication::Multiple) => 0.45,
      Metric::Authentication(Authentication::Single) => 0.56,
      Metric::Authentication(Authentication::None) => 0.704,
      _ => unreachable!(),
    };

    // ConfImpact = case ConfidentialityImpact of
    //   none:             0.0
    //   partial:          0.275
    //   complete:         0.660
    let c = match vec.get(Name::Confidentiality) {
      Metric::Confidentiality(Impact::None) => 0.0,
      Metric::Confidentiality(Impact::Partial) => 0.275,
      Metric::Confidentiality(Impact::Complete) => 0.660,
      _ => unreachable!(),
    };

    // IntegImpact = case IntegrityImpact of
    //   none:             0.0
    //   partial:          0.275
    //   complete:         0.660
    let i = match vec.get(Name::Integrity) {
      Metric::Integrity(Impact::None) => 0.0,
      Metric::Integrity(Impact::Partial) => 0.275,
      Metric::Integrity(Impact::Complete) => 0.660,
      _ => unreachable!(),
    };

    // AvailImpact = case AvailabilityImpact of
    //   none:             0.0
    //   partial:          0.275
    //   complete:         0.660
    let a = match vec.get(Name::Availability) {
      Metric::Availability(Impact::None) => 0.0,
      Metric::Availability(Impact::Partial) => 0.275,
      Metric::Availability(Impact::Complete) => 0.660,
      _ => unreachable!(),
    };

    // Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
    let impact = 10.41 * (1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a));

    // Exploitability = 20* AccessVector*AccessComplexity*Authentication
    let exploitability = 20.0 * av * ac * au;

    // f(impact)= 0 if Impact=0, 1.176 otherwise
    let f_impact = if impact > 0.001 { 1.176 } else { 0.0 };

    // BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
    let base_score = round1(((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact);

    // Exploitability = case Exploitability of
    //   unproven:             0.85
    //   proof-of-concept:     0.9
    //   functional:           0.95
    //   high:                 1.00
    //   not defined:          1.00
    let e = match vec.get(Name::Exploitability) {
      Metric::Exploitability(Exploitability::Unproven) => 0.85,
      Metric::Exploitability(Exploitability::ProofOfConcept) => 0.9,
      Metric::Exploitability(Exploitability::Functional) => 0.95,
      Metric::Exploitability(Exploitability::High) => 1.00,
      Metric::Exploitability(Exploitability::NotDefined) => 1.00,
      _ => unreachable!(),
    };

    // RemediationLevel = case RemediationLevel of
    //   official-fix:         0.87
    //   temporary-fix:        0.90
    //   workaround:           0.95
    //   unavailable:          1.00
    //   not defined:          1.00
    let rl = match vec.get(Name::RemediationLevel) {
      Metric::RemediationLevel(RemediationLevel::OfficialFix) => 0.87,
      Metric::RemediationLevel(RemediationLevel::TemporaryFix) => 0.90,
      Metric::RemediationLevel(RemediationLevel::Workaround) => 0.95,
      Metric::RemediationLevel(RemediationLevel::Unavailable) => 1.00,
      Metric::RemediationLevel(RemediationLevel::NotDefined) => 1.00,
      _ => unreachable!(),
    };

    // ReportConfidence = case ReportConfidence of
    //   unconfirmed:          0.90
    //   uncorroborated:       0.95
    //   confirmed:            1.00
    //   not defined:          1.00
    let rc = match vec.get(Name::ReportConfidence) {
      Metric::ReportConfidence(ReportConfidence::Unconfirmed) => 0.90,
      Metric::ReportConfidence(ReportConfidence::Uncorroborated) => 0.95,
      Metric::ReportConfidence(ReportConfidence::Confirmed) => 1.00,
      Metric::ReportConfidence(ReportConfidence::NotDefined) => 1.00,
      _ => unreachable!(),
    };

    // are any temporal metrics defined?
    let has_temporal_metrics = {
      // cache "not defined" temporal metric values
      let m_e_nd = Metric::Exploitability(Exploitability::NotDefined);
      let m_rl_nd = Metric::RemediationLevel(RemediationLevel::NotDefined);
      let m_rc_nd = Metric::ReportConfidence(ReportConfidence::NotDefined);

      vec.get(Name::Exploitability) != m_e_nd ||
      vec.get(Name::RemediationLevel) != m_rl_nd ||
      vec.get(Name::ReportConfidence) != m_rc_nd
    };

    // are any environmental metrics defined?
    let has_env_metrics = {
      // cache "not defined" temporal metric values
      let m_cdp_nd = Metric::CollateralDamagePotential(CollateralDamagePotential::NotDefined);
      let m_td_nd = Metric::TargetDistribution(TargetDistribution::NotDefined);
      let m_cr_nd = Metric::ConfidentialityRequirement(Requirement::NotDefined);
      let m_ir_nd = Metric::IntegrityRequirement(Requirement::NotDefined);
      let m_ar_nd = Metric::AvailabilityRequirement(Requirement::NotDefined);

      vec.get(Name::CollateralDamagePotential) != m_cdp_nd ||
      vec.get(Name::TargetDistribution) != m_td_nd ||
      vec.get(Name::ConfidentialityRequirement) != m_cr_nd ||
      vec.get(Name::IntegrityRequirement) != m_ir_nd ||
      vec.get(Name::AvailabilityRequirement) != m_ar_nd
    };

    let temporal_score = if has_temporal_metrics {
      // TemporalScore = round_to_1_decimal(BaseScore*Exploitability
      //                 *RemediationLevel*ReportConfidence)
      Some(round1(base_score * e * rl * rc))
    } else {
      None
    };

    // ConfReq = case ConfReq of
    //   low:              0.5
    //   medium:           1.0
    //   high:             1.51
    //   not defined:      1.0
    let cr = match vec.get(Name::ConfidentialityRequirement) {
      Metric::ConfidentialityRequirement(Requirement::Low) => 0.5,
      Metric::ConfidentialityRequirement(Requirement::Medium) => 1.0,
      Metric::ConfidentialityRequirement(Requirement::High) => 1.51,
      Metric::ConfidentialityRequirement(Requirement::NotDefined) => 1.0,
      _ => unreachable!(),
    };

    // IntegReq = case IntegReq of
    //   low:              0.5
    //   medium:           1.0
    //   high:             1.51
    //   not defined:      1.0
    let ir = match vec.get(Name::IntegrityRequirement) {
      Metric::IntegrityRequirement(Requirement::Low) => 0.5,
      Metric::IntegrityRequirement(Requirement::Medium) => 1.0,
      Metric::IntegrityRequirement(Requirement::High) => 1.51,
      Metric::IntegrityRequirement(Requirement::NotDefined) => 1.0,
      _ => unreachable!(),
    };

    // AvailReq = case AvailReq of
    //   low:              0.5
    //   medium:           1.0
    //   high:             1.51
    //   not defined:      1.0
    let ar = match vec.get(Name::AvailabilityRequirement) {
      Metric::AvailabilityRequirement(Requirement::Low) => 0.5,
      Metric::AvailabilityRequirement(Requirement::Medium) => 1.0,
      Metric::AvailabilityRequirement(Requirement::High) => 1.51,
      Metric::AvailabilityRequirement(Requirement::NotDefined) => 1.0,
      _ => unreachable!(),
    };

    // CollateralDamagePotential = case CollateralDamagePotential of
    //   none:            0
    //   low:             0.1
    //   low-medium:      0.3
    //   medium-high:     0.4
    //   high:            0.5
    //   not defined:     0
    //   none:            0
    let cdp = match vec.get(Name::CollateralDamagePotential) {
      Metric::CollateralDamagePotential(CollateralDamagePotential::Low) => 0.1,
      Metric::CollateralDamagePotential(CollateralDamagePotential::LowMedium) => 0.3,
      Metric::CollateralDamagePotential(CollateralDamagePotential::MediumHigh) => 0.4,
      Metric::CollateralDamagePotential(CollateralDamagePotential::High) => 0.5,
      Metric::CollateralDamagePotential(CollateralDamagePotential::NotDefined) => 0.0,
      Metric::CollateralDamagePotential(CollateralDamagePotential::None) => 0.0,
      _ => unreachable!(),
    };

    // TargetDistribution = case TargetDistribution of
    //   none:            0
    //   low:             0.25
    //   medium:          0.75
    //   high:            1.00
    //   not defined:     1.00
    let td = match vec.get(Name::TargetDistribution) {
      Metric::TargetDistribution(TargetDistribution::None) => 0.0,
      Metric::TargetDistribution(TargetDistribution::Low) => 0.25,
      Metric::TargetDistribution(TargetDistribution::Medium) => 0.75,
      Metric::TargetDistribution(TargetDistribution::High) => 1.00,
      Metric::TargetDistribution(TargetDistribution::NotDefined) => 1.00,
      _ => unreachable!(),
    };

    // AdjustedImpact = min(10,10.41*(1-(1-ConfImpact*ConfReq)*(1-IntegImpact*IntegReq)
    //                      *(1-AvailImpact*AvailReq)))
    let adj_impact = 10.0_f64.min(10.41 * (1.0 - (1.0 - c*cr) * (1.0 - i*ir) * (1.0 - a*ar)));

    // recalculate base score with the BaseScore's Impact sub-
    // equation replaced with the AdjustedImpact equation
    let f_adj_impact = if adj_impact > 0.001 { 1.176 } else { 0.0 };
    let adj_base_score = ((0.6 * adj_impact) + (0.4 * round1(exploitability)) - 1.5) * f_adj_impact;
    // println!("DEBUG: adj_impact={adj_impact}, exploitability={exploitability}, f_adj_impact={f_adj_impact}");

    // AdjustedTemporal = TemporalScore recomputed with the BaseScore's Impact sub-
    // equation replaced with the AdjustedImpact equation
    let adj_temporal_score = if has_temporal_metrics {
      adj_base_score * e * rl * rc
    } else {
      adj_base_score
    };
    // println!("DEBUG: adj_base_score={adj_base_score}, e={e}, rl={rl}, rc={rc}");

    // EnvironmentalScore = round_to_1_decimal((AdjustedTemporal+
    // (10-AdjustedTemporal)*CollateralDamagePotential)*TargetDistribution)
    let env_score = if has_env_metrics {
      Some(round1((adj_temporal_score + (10.0 - adj_temporal_score)*cdp)*td))
    } else {
      None
    };
    // println!("DEBUG: adj_temporal_score={adj_temporal_score:?}, cdp={cdp}, td={td}");

    Scores {
      base: Score::from(base_score),
      temporal: temporal_score.map(Score::from),
      environmental: env_score.map(Score::from),
    }
  }
}

impl std::fmt::Display for Scores {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{self:?}")
  }
}

#[cfg(test)]
mod tests {
  mod group {
    use super::super::{Name, Group};

    #[test]
    fn test_from_name() {
      let tests = vec!(
        (Name::AccessVector, Group::Base),
        (Name::Exploitability, Group::Temporal),
        (Name::CollateralDamagePotential, Group::Environmental),
      );

      for (name, group) in tests {
        assert_eq!(Group::from(name), group, "{}", group);
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
        assert_eq!(s.parse::<Name>(), Err(exp), "{}", name);
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        ("AV", Name::AccessVector),
        ("AC", Name::AccessComplexity),
        ("Au", Name::Authentication),
        ("C", Name::Confidentiality),
        ("I", Name::Integrity),
        ("A", Name::Availability),
        ("E", Name::Exploitability),
        ("RL", Name::RemediationLevel),
        ("RC", Name::ReportConfidence),
        ("CDP", Name::CollateralDamagePotential),
        ("TD", Name::TargetDistribution),
        ("CR", Name::ConfidentialityRequirement),
        ("IR", Name::IntegrityRequirement),
        ("AR", Name::AvailabilityRequirement),
      );

      for (s, exp) in tests {
        assert_eq!(s.parse::<Name>(), Ok(exp), "{}", s);
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Name::AccessVector, "AV"),
        (Name::AccessComplexity, "AC"),
        (Name::Authentication, "Au"),
        (Name::Confidentiality, "C"),
        (Name::Integrity, "I"),
        (Name::Availability, "A"),
        (Name::Exploitability, "E"),
        (Name::RemediationLevel, "RL"),
        (Name::ReportConfidence, "RC"),
        (Name::CollateralDamagePotential, "CDP"),
        (Name::TargetDistribution, "TD"),
        (Name::ConfidentialityRequirement, "CR"),
        (Name::IntegrityRequirement, "IR"),
        (Name::AvailabilityRequirement, "AR"),
      );

      for (name, exp) in tests {
        assert_eq!(name.to_string(), exp, "{}", exp);
      }
    }
  }

  mod metric {
    use super::super::{
      Err,
      Metric,
      AccessVector,
      AccessComplexity,
      Authentication,
      Impact,
      Exploitability,
      RemediationLevel,
      ReportConfidence,
      CollateralDamagePotential,
      TargetDistribution,
      Requirement,
    };

    #[test]
    fn test_from_str_fail() {
      let tests = vec!(
        ("empty", "", Err::UnknownMetric),
      );

      for (name, s, exp) in tests {
        assert_eq!(s.parse::<Metric>(), Err(exp), "{}", name);
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        ("AV:L", Metric::AccessVector(AccessVector::Local)),
        ("AV:A", Metric::AccessVector(AccessVector::AdjacentNetwork)),
        ("AV:N", Metric::AccessVector(AccessVector::Network)),

        ("AC:H", Metric::AccessComplexity(AccessComplexity::High)),
        ("AC:M", Metric::AccessComplexity(AccessComplexity::Medium)),
        ("AC:L", Metric::AccessComplexity(AccessComplexity::Low)),

        ("Au:M", Metric::Authentication(Authentication::Multiple)),
        ("Au:S", Metric::Authentication(Authentication::Single)),
        ("Au:N", Metric::Authentication(Authentication::None)),

        ("C:N", Metric::Confidentiality(Impact::None)),
        ("C:P", Metric::Confidentiality(Impact::Partial)),
        ("C:C", Metric::Confidentiality(Impact::Complete)),

        ("I:N", Metric::Integrity(Impact::None)),
        ("I:P", Metric::Integrity(Impact::Partial)),
        ("I:C", Metric::Integrity(Impact::Complete)),

        ("A:N", Metric::Availability(Impact::None)),
        ("A:P", Metric::Availability(Impact::Partial)),
        ("A:C", Metric::Availability(Impact::Complete)),

        ("E:ND", Metric::Exploitability(Exploitability::NotDefined)),
        ("E:U", Metric::Exploitability(Exploitability::Unproven)),
        ("E:POC", Metric::Exploitability(Exploitability::ProofOfConcept)),
        ("E:F", Metric::Exploitability(Exploitability::Functional)),
        ("E:H", Metric::Exploitability(Exploitability::High)),

        ("RL:ND", Metric::RemediationLevel(RemediationLevel::NotDefined)),
        ("RL:OF", Metric::RemediationLevel(RemediationLevel::OfficialFix)),
        ("RL:TF", Metric::RemediationLevel(RemediationLevel::TemporaryFix)),
        ("RL:W", Metric::RemediationLevel(RemediationLevel::Workaround)),
        ("RL:U", Metric::RemediationLevel(RemediationLevel::Unavailable)),

        ("RC:ND", Metric::ReportConfidence(ReportConfidence::NotDefined)),
        ("RC:UC", Metric::ReportConfidence(ReportConfidence::Unconfirmed)),
        ("RC:UR", Metric::ReportConfidence(ReportConfidence::Uncorroborated)),
        ("RC:C", Metric::ReportConfidence(ReportConfidence::Confirmed)),

        ("CDP:ND", Metric::CollateralDamagePotential(CollateralDamagePotential::NotDefined)),
        ("CDP:N", Metric::CollateralDamagePotential(CollateralDamagePotential::None)),
        ("CDP:L", Metric::CollateralDamagePotential(CollateralDamagePotential::Low)),
        ("CDP:LM", Metric::CollateralDamagePotential(CollateralDamagePotential::LowMedium)),
        ("CDP:MH", Metric::CollateralDamagePotential(CollateralDamagePotential::MediumHigh)),
        ("CDP:H", Metric::CollateralDamagePotential(CollateralDamagePotential::High)),

        ("TD:ND", Metric::TargetDistribution(TargetDistribution::NotDefined)),
        ("TD:N", Metric::TargetDistribution(TargetDistribution::None)),
        ("TD:L", Metric::TargetDistribution(TargetDistribution::Low)),
        ("TD:M", Metric::TargetDistribution(TargetDistribution::Medium)),
        ("TD:H", Metric::TargetDistribution(TargetDistribution::High)),

        ("CR:ND", Metric::ConfidentialityRequirement(Requirement::NotDefined)),
        ("CR:L", Metric::ConfidentialityRequirement(Requirement::Low)),
        ("CR:M", Metric::ConfidentialityRequirement(Requirement::Medium)),
        ("CR:H", Metric::ConfidentialityRequirement(Requirement::High)),

        ("IR:ND", Metric::IntegrityRequirement(Requirement::NotDefined)),
        ("IR:L", Metric::IntegrityRequirement(Requirement::Low)),
        ("IR:M", Metric::IntegrityRequirement(Requirement::Medium)),
        ("IR:H", Metric::IntegrityRequirement(Requirement::High)),

        ("AR:ND", Metric::AvailabilityRequirement(Requirement::NotDefined)),
        ("AR:L", Metric::AvailabilityRequirement(Requirement::Low)),
        ("AR:M", Metric::AvailabilityRequirement(Requirement::Medium)),
        ("AR:H", Metric::AvailabilityRequirement(Requirement::High)),
      );

      for (s, exp) in tests {
        assert_eq!(s.parse::<Metric>().unwrap(), exp);
      }
    }

    #[test]
    fn test_to_string() {
      let tests = vec!(
        (Metric::AccessVector(AccessVector::Local), "AV:L"),
        (Metric::AccessVector(AccessVector::AdjacentNetwork), "AV:A"),
        (Metric::AccessVector(AccessVector::Network), "AV:N"),

        (Metric::AccessComplexity(AccessComplexity::High), "AC:H"),
        (Metric::AccessComplexity(AccessComplexity::Medium), "AC:M"),
        (Metric::AccessComplexity(AccessComplexity::Low), "AC:L"),

        (Metric::Authentication(Authentication::Multiple), "Au:M"),
        (Metric::Authentication(Authentication::Single), "Au:S"),
        (Metric::Authentication(Authentication::None), "Au:N"),

        (Metric::Confidentiality(Impact::None), "C:N"),
        (Metric::Confidentiality(Impact::Partial), "C:P"),
        (Metric::Confidentiality(Impact::Complete), "C:C"),

        (Metric::Integrity(Impact::None), "I:N"),
        (Metric::Integrity(Impact::Partial), "I:P"),
        (Metric::Integrity(Impact::Complete), "I:C"),

        (Metric::Availability(Impact::None), "A:N"),
        (Metric::Availability(Impact::Partial), "A:P"),
        (Metric::Availability(Impact::Complete), "A:C"),

        (Metric::Exploitability(Exploitability::NotDefined), "E:ND"),
        (Metric::Exploitability(Exploitability::Unproven), "E:U"),
        (Metric::Exploitability(Exploitability::ProofOfConcept), "E:POC"),
        (Metric::Exploitability(Exploitability::Functional), "E:F"),
        (Metric::Exploitability(Exploitability::High), "E:H"),

        (Metric::RemediationLevel(RemediationLevel::NotDefined), "RL:ND"),
        (Metric::RemediationLevel(RemediationLevel::OfficialFix), "RL:OF"),
        (Metric::RemediationLevel(RemediationLevel::TemporaryFix), "RL:TF"),
        (Metric::RemediationLevel(RemediationLevel::Workaround), "RL:W"),
        (Metric::RemediationLevel(RemediationLevel::Unavailable), "RL:U"),

        (Metric::ReportConfidence(ReportConfidence::NotDefined), "RC:ND"),
        (Metric::ReportConfidence(ReportConfidence::Unconfirmed), "RC:UC"),
        (Metric::ReportConfidence(ReportConfidence::Uncorroborated), "RC:UR"),
        (Metric::ReportConfidence(ReportConfidence::Confirmed), "RC:C"),

        (Metric::CollateralDamagePotential(CollateralDamagePotential::NotDefined), "CDP:ND"),
        (Metric::CollateralDamagePotential(CollateralDamagePotential::None), "CDP:N"),
        (Metric::CollateralDamagePotential(CollateralDamagePotential::Low), "CDP:L"),
        (Metric::CollateralDamagePotential(CollateralDamagePotential::LowMedium), "CDP:LM"),
        (Metric::CollateralDamagePotential(CollateralDamagePotential::MediumHigh), "CDP:MH"),
        (Metric::CollateralDamagePotential(CollateralDamagePotential::High), "CDP:H"),

        (Metric::TargetDistribution(TargetDistribution::NotDefined), "TD:ND"),
        (Metric::TargetDistribution(TargetDistribution::None), "TD:N"),
        (Metric::TargetDistribution(TargetDistribution::Low), "TD:L"),
        (Metric::TargetDistribution(TargetDistribution::Medium), "TD:M"),
        (Metric::TargetDistribution(TargetDistribution::High), "TD:H"),

        (Metric::ConfidentialityRequirement(Requirement::NotDefined), "CR:ND"),
        (Metric::ConfidentialityRequirement(Requirement::Low), "CR:L"),
        (Metric::ConfidentialityRequirement(Requirement::Medium), "CR:M"),
        (Metric::ConfidentialityRequirement(Requirement::High), "CR:H"),

        (Metric::IntegrityRequirement(Requirement::NotDefined), "IR:ND"),
        (Metric::IntegrityRequirement(Requirement::Low), "IR:L"),
        (Metric::IntegrityRequirement(Requirement::Medium), "IR:M"),
        (Metric::IntegrityRequirement(Requirement::High), "IR:H"),

        (Metric::AvailabilityRequirement(Requirement::NotDefined), "AR:ND"),
        (Metric::AvailabilityRequirement(Requirement::Low), "AR:L"),
        (Metric::AvailabilityRequirement(Requirement::Medium), "AR:M"),
        (Metric::AvailabilityRequirement(Requirement::High), "AR:H"),
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
      super::{Score, Version},
      Err,
      Name,
      Metric,
      Vector,
      AccessVector,
      AccessComplexity,
      Authentication,
      Impact,
      Exploitability,
      RemediationLevel,
      ReportConfidence,
      CollateralDamagePotential,
      TargetDistribution,
      Requirement,
    };

    #[test]
    fn test_from_str_fail() {
      let tests = vec!(
        ("empty", "", Err::Len),
        ("dup metric", "AV:N/AV:N/Au:N/C:C/I:C/A:C", Err::DuplicateName),
        ("dup key", "AV:N/AV:A/Au:N/C:C/I:C/A:C", Err::DuplicateName),
        ("unknown val", "AV:Z/AC:L/Au:N/C:C/I:C/A:C", Err::UnknownMetric),
        ("unknown key", "AV:N/AC:L/Au:N/C:C/I:C/A:C/ZZ:Z", Err::UnknownMetric),
        ("missing AV", "AC:L/Au:N/C:C/I:C/A:C/CR:H/IR:H/AR:H", Err::MissingMandatoryMetrics),
        ("missing AC", "AV:N/Au:N/C:C/I:C/A:C/CR:H/IR:H/AR:H", Err::MissingMandatoryMetrics),
        ("missing Au", "AV:N/AC:L/C:C/I:C/A:C/CR:H/IR:H/AR:H", Err::MissingMandatoryMetrics),
        ("missing C", "AV:N/AC:L/Au:N/I:C/A:C/CR:H/IR:H/AR:H", Err::MissingMandatoryMetrics),
        ("missing I", "AV:N/AC:L/Au:N/C:C/A:C/CR:H/IR:H/AR:H", Err::MissingMandatoryMetrics),
        ("missing A", "AV:N/AC:L/Au:N/C:C/I:C/CR:H/IR:H/AR:H", Err::MissingMandatoryMetrics),
      );

      for (name, s, exp) in tests {
        assert_eq!(s.parse::<Vector>(), Err(exp), "{}", name);
      }
    }

    #[test]
    fn test_from_str_pass() {
      let tests = vec!(
        // AV
        "AV:L/AC:L/Au:N/C:C/I:C/A:C", // AV:L
        "AV:A/AC:L/Au:N/C:C/I:C/A:C", // AV:A
        "AV:N/AC:L/Au:N/C:C/I:C/A:C", // AV:N

        // AC
        "AV:N/AC:H/Au:N/C:C/I:C/A:C", // AC:H
        "AV:N/AC:M/Au:N/C:C/I:C/A:C", // AC:M
        "AV:N/AC:L/Au:N/C:C/I:C/A:C", // AC:L

        // Au
        "AV:N/AC:L/Au:M/C:C/I:C/A:C", // Au:M
        "AV:N/AC:L/Au:S/C:C/I:C/A:C", // Au:S
        "AV:N/AC:L/Au:N/C:C/I:C/A:C", // Au:N

        // C
        "AV:N/AC:L/Au:N/C:N/I:C/A:C", // C:N
        "AV:N/AC:L/Au:N/C:P/I:C/A:C", // C:P
        "AV:N/AC:L/Au:N/C:C/I:C/A:C", // C:C

        // I
        "AV:N/AC:L/Au:N/C:C/I:N/A:C", // I:N
        "AV:N/AC:L/Au:N/C:C/I:P/A:C", // I:P
        "AV:N/AC:L/Au:N/C:C/I:C/A:C", // I:C

        // A
        "AV:N/AC:L/Au:N/C:C/I:C/A:N", // A:N
        "AV:N/AC:L/Au:N/C:C/I:C/A:P", // A:P
        "AV:N/AC:L/Au:N/C:C/I:C/A:C", // A:C

        // E
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND", // E:ND
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U", // E:U
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC", // E:POC
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F", // E:F
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H", // E:H

        // RL
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:ND", // RL:ND
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:OF", // RL:OF
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:TF", // RL:TF
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:W", // RL:W
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:U", // RL:U

        // RC
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:ND", // RC:ND
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:UC", // RC:UC
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:UR", // RC:UR
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:C", // RC:C

        // CDP
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:ND", // CDP:ND
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:N", // CDP:N
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:L", // CDP:L
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:LM", // CDP:LM
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:MH", // CDP:MH
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:H", // CDP:H

        // TD
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:ND", // TD:ND
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:N", // TD:N
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:L", // TD:L
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:M", // TD:M
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:H", // TD:H

        // CR
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:ND", // CR:ND
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:L", // CR:L
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:M", // CR:M
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:H", // CR:H

        // IR
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:ND", // IR:ND
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:L", // IR:L
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:M", // IR:M
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:H", // IR:H

        // AR
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:ND", // AR:ND
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:L", // AR:L
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:M", // AR:M
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:H", // AR:H
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
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "everything", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H", // exp
        ),

        // AV
        (
          "AV:L", // name
          "AV:L/AC:L/Au:N/C:C/I:C/A:C", // val
          "AV:L/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "AV:A", // name
          "AV:A/AC:L/Au:N/C:C/I:C/A:C", // val
          "AV:A/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "AV:N", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        // AC
        (
          "AC:H", // name
          "AV:N/AC:H/Au:N/C:C/I:C/A:C", // val
          "AV:N/AC:H/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "AC:M", // name
          "AV:N/AC:M/Au:N/C:C/I:C/A:C", // val
          "AV:N/AC:M/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "AC:L", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        // Au
        (
          "Au:M", // name
          "AV:N/AC:L/Au:M/C:C/I:C/A:C", // val
          "AV:N/AC:L/Au:M/C:C/I:C/A:C", // exp
        ),

        (
          "Au:S", // name
          "AV:N/AC:L/Au:S/C:C/I:C/A:C", // val
          "AV:N/AC:L/Au:S/C:C/I:C/A:C", // exp
        ),

        (
          "Au:N", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        // C
        (
          "C:N", // name
          "AV:N/AC:L/Au:N/C:N/I:C/A:C", // val
          "AV:N/AC:L/Au:N/C:N/I:C/A:C", // exp
        ),

        (
          "C:P", // name
          "AV:N/AC:L/Au:N/C:P/I:C/A:C", // val
          "AV:N/AC:L/Au:N/C:P/I:C/A:C", // exp
        ),

        (
          "C:C", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        // I
        (
          "I:N", // name
          "AV:N/AC:L/Au:N/C:C/I:N/A:C", // val
          "AV:N/AC:L/Au:N/C:C/I:N/A:C", // exp
        ),

        (
          "I:P", // name
          "AV:N/AC:L/Au:N/C:C/I:P/A:C", // val
          "AV:N/AC:L/Au:N/C:C/I:P/A:C", // exp
        ),

        (
          "I:C", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        // A
        (
          "A:N", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:N", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:N", // exp
        ),

        (
          "A:P", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:P", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:P", // exp
        ),

        (
          "A:C", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        // E
        (
          "E:ND", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "E:U", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U", // exp
        ),

        (
          "E:POC", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC", // exp
        ),

        (
          "E:F", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F", // exp
        ),

        (
          "E:H", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H", // exp
        ),

        // RL
        (
          "RL:ND", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:ND", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "RL:OF", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:OF", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:OF", // exp
        ),

        (
          "RL:TF", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:TF", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:TF", // exp
        ),

        (
          "RL:W", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:W", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:W", // exp
        ),

        (
          "RL:U", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:U", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:U", // exp
        ),

        // RC
        (
          "RC:ND", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:ND", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "RC:UC", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:UC", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:UC", // exp
        ),

        (
          "RC:UR", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:UR", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:UR", // exp
        ),

        (
          "RC:C", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:C", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:C", // exp
        ),

        // CDP
        (
          "CDP:ND", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:ND", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "CDP:N", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:N", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:N", // exp
        ),

        (
          "CDP:L", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:L", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:L", // exp
        ),

        (
          "CDP:LM", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:LM", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:LM", // exp
        ),

        (
          "CDP:MH", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:MH", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:MH", // exp
        ),

        (
          "CDP:H", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:H", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:H", // exp
        ),

        // TD
        (
          "TD:ND", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:ND", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "TD:N", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:N", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:N", // exp
        ),

        (
          "TD:L", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:L", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:L", // exp
        ),

        (
          "TD:M", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:M", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:M", // exp
        ),

        (
          "TD:H", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:H", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:H", // exp
        ),

        // CR
        (
          "CR:ND", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:ND", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "CR:L", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:L", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:L", // exp
        ),

        (
          "CR:M", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:M", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:M", // exp
        ),

        (
          "CR:H", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:H", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:H", // exp
        ),

        // IR
        (
          "IR:ND", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:ND", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "IR:L", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:L", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:L", // exp
        ),

        (
          "IR:M", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:M", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:M", // exp
        ),

        (
          "IR:H", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:H", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:H", // exp
        ),

        // AR
        (
          "AR:ND", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:ND", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // exp
        ),

        (
          "AR:L", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:L", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:L", // exp
        ),

        (
          "AR:M", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:M", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:M", // exp
        ),

        (
          "AR:H", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:H", // val
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:H", // exp
        ),
      );

      for (name, s, exp) in tests {
        assert_eq!(s.parse::<Vector>().expect(name).to_string(), exp, "{}", name);
      }
    }

    #[test]
    fn test_get() {
      let tests = vec!((
        "base metric", // test name
        "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
        Name::AccessVector, // metric name
        Metric::AccessVector(AccessVector::Network), // exp
      ), (
        "optional metric, not defined", // test name
        "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
        Name::Exploitability, // metric name
        Metric::Exploitability(Exploitability::NotDefined), // exp
      ), (
        "optional metric, defined", // test name
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H", // val
        Name::Exploitability, // metric name
        Metric::Exploitability(Exploitability::High), // exp
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
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          vec!(
            Metric::AccessVector(AccessVector::Network),
            Metric::AccessComplexity(AccessComplexity::Low),
            Metric::Authentication(Authentication::None),
            Metric::Confidentiality(Impact::Complete),
            Metric::Integrity(Impact::Complete),
            Metric::Availability(Impact::Complete),
          )
        ),

        (
          "everything",
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H", // val
          vec!(
            Metric::AccessVector(AccessVector::Network), // AV:N
            Metric::AccessComplexity(AccessComplexity::Low), // AC:L
            Metric::Authentication(Authentication::None), // Au:N
            Metric::Confidentiality(Impact::Complete), // C:C
            Metric::Integrity(Impact::Complete), // I:C
            Metric::Availability(Impact::Complete), // A:C
            Metric::Exploitability(Exploitability::High), // E:H
            Metric::RemediationLevel(RemediationLevel::Unavailable), // RL:U
            Metric::ReportConfidence(ReportConfidence::Confirmed), // RC:C
            Metric::CollateralDamagePotential(CollateralDamagePotential::High), // CDP:H
            Metric::TargetDistribution(TargetDistribution::High), // TD:H
            Metric::ConfidentialityRequirement(Requirement::High), // CR:H
            Metric::IntegrityRequirement(Requirement::High), // IR:H
            Metric::AvailabilityRequirement(Requirement::High), // AR:H
          )
        ),
      );

      for (name, s, exp) in tests {
        let got: Vec<Metric> = s.parse::<Vector>().unwrap().into_iter().collect();
        assert_eq!(got, exp, "{}", name);
      }
    }

    #[test]
    fn test_iter_implicit() {
      let tests = vec!(
        (
          "basic",
          "AV:N/AC:L/Au:N/C:C/I:C/A:C", // val
          vec!(
            Metric::AccessVector(AccessVector::Network),
            Metric::AccessComplexity(AccessComplexity::Low),
            Metric::Authentication(Authentication::None),
            Metric::Confidentiality(Impact::Complete),
            Metric::Integrity(Impact::Complete),
            Metric::Availability(Impact::Complete),
          )
        ),

        (
          "everything",
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H", // val
          vec!(
            Metric::AccessVector(AccessVector::Network), // AV:N
            Metric::AccessComplexity(AccessComplexity::Low), // AC:L
            Metric::Authentication(Authentication::None), // Au:N
            Metric::Confidentiality(Impact::Complete), // C:C
            Metric::Integrity(Impact::Complete), // I:C
            Metric::Availability(Impact::Complete), // A:C
            Metric::Exploitability(Exploitability::High), // E:H
            Metric::RemediationLevel(RemediationLevel::Unavailable), // RL:U
            Metric::ReportConfidence(ReportConfidence::Confirmed), // RC:C
            Metric::CollateralDamagePotential(CollateralDamagePotential::High), // CDP:H
            Metric::TargetDistribution(TargetDistribution::High), // TD:H
            Metric::ConfidentialityRequirement(Requirement::High), // CR:H
            Metric::IntegrityRequirement(Requirement::High), // IR:H
            Metric::AvailabilityRequirement(Requirement::High), // AR:H
          )
        ),
      );

      for (name, s, exp) in tests {
        let mut got: Vec<Metric> = Vec::new();
        for c in s.parse::<Vector>().unwrap() {
          got.push(c);
        }
        assert_eq!(got, exp, "{}", name);
      }
    }

    #[test]
    fn test_into_version() {
      let tests = vec!(
        ("AV:N/AC:L/Au:N/C:N/I:N/A:C", Version::V23),
      );

      for (s, exp) in tests {
        let got = Version::from(s.parse::<Vector>().unwrap());
        assert_eq!(got, exp, "{s}");
      }
    }

    #[test]
    fn test_size() {
      assert_eq!(size_of::<Vector>(), size_of::<u64>());
    }

    #[test]
    fn test_into_score() {
      let tests = vec!(
        (
          "3.3.2. CVE-2003-0818, high", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L", // val
          Score(90), // exp
        ),
        // lots more tests in tests::scores::test_from_vector()
      );

      for (name, s, exp) in tests {
        let got = Score::from(s.parse::<Vector>().unwrap());
        assert_eq!(got, exp, "{name}");
      }
    }
  }

  mod scores {
    use super::super::{super::Score, Scores, Vector};

    #[test]
    fn test_examples() {
      // examples from the "Examples" section of the CVSS v2 guide:
      // https://www.first.org/cvss/v2/guide#3-3-Examples
      let tests = vec!(
        (
          "3.3.1, CVE-2002-0392, low", // name
          "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:H", // val
          Scores {
            base: Score(78),
            temporal: Some(Score(64)),
            environmental: Some(Score(0)),
          }, // exp
        ),

        (
          "3.3.1, CVE-2002-0392, high", // name
          "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H", // val
          Scores {
            base: Score(78),
            temporal: Some(Score(64)),
            environmental: Some(Score(91)),
          }, // exp
        ),

        (
          "3.3.2. CVE-2003-0818, low", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:L", // val
          Scores {
            base: Score(100),
            temporal: Some(Score(83)),
            environmental: Some(Score(0)),
          }, // exp
        ),

        (
          "3.3.2. CVE-2003-0818, high", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L", // val
          Scores {
            base: Score(100),
            temporal: Some(Score(83)),
            environmental: Some(Score(90)),
          }, // exp
        ),

        (
          "3.3.3. CVE-2003-0062, low", // name
          "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:M", // val
          Scores {
            base: Score(62),
            temporal: Some(Score(49)),
            environmental: Some(Score(0)),
          }, // exp
        ),

        (
          "3.3.3. CVE-2003-0062, high", // name
          "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M", // val
          Scores {
            base: Score(62),
            temporal: Some(Score(49)),
            environmental: Some(Score(74)),
          }, // exp
        ),
      );

      for (name, vs, exp) in tests {
        let vec: Vector = vs.parse().unwrap(); // parse vector
        let got = Scores::from(vec); // get scores
        assert_eq!(got, exp, "{}, {}", name, vec); // check result
      }
    }

    #[test]
    fn test_from_vector() {
      // first few test cases generated manually using cvss v2 calc; the
      // rest were generated with `random.js v2 1000` in `cvss-calc`
      // repo
      let tests = vec!((
        "ba86600d 3.4", // name
        "AV:L/AC:H/Au:M/C:P/I:P/A:P", // val
        Scores {
          base: Score(34),
          temporal: None,
          environmental: None,
        }, // exp
      ), (
        "90a10b19 3.7", // name
        "AV:A/AC:H/Au:M/C:P/I:P/A:P", // val
        Scores {
          base: Score(37),
          temporal: None,
          environmental: None,
        }, // exp
      ), (
        "a6510d8f 4.5", // name
        "AV:A/AC:M/Au:M/C:P/I:P/A:P", // val
        Scores {
          base: Score(45),
          temporal: None,
          environmental: None,
        }, // exp
      ), (
        "428a9e9f 7.3", // name
        "AV:A/AC:M/Au:N/C:C/I:N/A:C", // val
        Scores {
          base: Score(73),
          temporal: None,
          environmental: None,
        }, // exp
      ), (
        "297bba86 8.6", // name
        "AV:N/AC:M/Au:S/C:C/I:N/A:P/E:H/RL:ND/RC:C/CDP:L/TD:H/CR:H/IR:M/AR:ND", // val
        Scores {
          base: Score(70),
          temporal: Some(Score(70)),
          environmental: Some(Score(86)),
        }, // exp
      ),

      // randomly generated with `random.js v2 1000`
      (
        "5c56f91c 0.6", // test name
        "AV:A/AC:H/Au:M/C:C/I:N/A:P/E:POC/RL:U/RC:UR/CDP:N/TD:L/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(0.6)), // exp environmental score
        }, // exp
      ), (
        "f0147231 1.3", // test name
        "AV:A/AC:H/Au:M/C:C/I:P/A:C/E:F/RL:ND/RC:UC/CDP:N/TD:L/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "21f99914 0.0", // test name
        "AV:A/AC:H/Au:M/C:N/I:P/A:P/E:H/RL:U/RC:ND/CDP:ND/TD:N/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "663d1441 6.3", // test name
        "AV:A/AC:H/Au:M/C:P/I:N/A:P/E:POC/RL:OF/RC:ND/CDP:H/TD:H/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "c7b3cff4 3.7", // test name
        "AV:A/AC:H/Au:N/C:C/I:C/A:C/E:U/RL:ND/RC:UC/CDP:N/TD:M/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "24d6e78e 0.0", // test name
        "AV:A/AC:H/Au:S/C:C/I:P/A:N/E:ND/RL:W/RC:C/CDP:H/TD:N/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "158ba17b 0.0", // test name
        "AV:A/AC:H/Au:S/C:N/I:N/A:C/E:ND/RL:TF/RC:ND/CDP:N/TD:N/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "3fb66812 0.0", // test name
        "AV:A/AC:H/Au:S/C:N/I:N/A:P/E:F/RL:OF/RC:ND/CDP:MH/TD:N/CR:L/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "80b7eee7 1.0", // test name
        "AV:A/AC:H/Au:S/C:N/I:N/A:P/E:POC/RL:OF/RC:UC/CDP:ND/TD:H/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.0)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "b413b17b 4.6", // test name
        "AV:A/AC:L/Au:M/C:N/I:C/A:P/E:ND/RL:ND/RC:ND/CDP:L/TD:M/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "91d2756c 0.0", // test name
        "AV:A/AC:L/Au:M/C:N/I:N/A:N/E:H/RL:TF/RC:UC/CDP:ND/TD:M/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "b3e6499d 0.0", // test name
        "AV:A/AC:L/Au:M/C:N/I:P/A:C/E:ND/RL:OF/RC:C/CDP:MH/TD:N/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "1f881e5a 0.6", // test name
        "AV:A/AC:L/Au:M/C:P/I:N/A:P/E:H/RL:OF/RC:UR/CDP:N/TD:L/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(0.6)), // exp environmental score
        }, // exp
      ), (
        "18fc0ab6 8.6", // test name
        "AV:A/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:OF/RC:ND/CDP:H/TD:H/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(8.6)), // exp environmental score
        }, // exp
      ), (
        "096b42d5 0.0", // test name
        "AV:A/AC:L/Au:N/C:C/I:C/A:N/E:POC/RL:W/RC:C/CDP:L/TD:N/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "50254d56 5.4", // test name
        "AV:A/AC:L/Au:S/C:C/I:P/A:P/E:ND/RL:TF/RC:UC/CDP:N/TD:ND/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "c2d7c72a 0.8", // test name
        "AV:A/AC:L/Au:S/C:N/I:N/A:N/E:POC/RL:U/RC:ND/CDP:LM/TD:L/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.8)), // exp environmental score
        }, // exp
      ), (
        "524b36a8 6.9", // test name
        "AV:A/AC:L/Au:S/C:N/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:ND/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "cd591ef1 1.5", // test name
        "AV:A/AC:L/Au:S/C:P/I:C/A:N/E:ND/RL:U/RC:UR/CDP:ND/TD:L/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "dabcb350 1.0", // test name
        "AV:A/AC:M/Au:M/C:N/I:N/A:P/E:H/RL:TF/RC:ND/CDP:LM/TD:L/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "8f0906ec 4.1", // test name
        "AV:A/AC:M/Au:M/C:N/I:P/A:P/E:H/RL:U/RC:ND/CDP:N/TD:ND/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "308dc49d 3.9", // test name
        "AV:A/AC:M/Au:M/C:P/I:N/A:P/E:H/RL:ND/RC:UR/CDP:L/TD:ND/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "d28f53c0 2.2", // test name
        "AV:A/AC:M/Au:M/C:P/I:P/A:C/E:POC/RL:OF/RC:UC/CDP:ND/TD:M/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "3d0ee880 0.0", // test name
        "AV:A/AC:M/Au:M/C:P/I:P/A:N/E:POC/RL:W/RC:ND/CDP:ND/TD:N/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "daed3737 0.0", // test name
        "AV:A/AC:M/Au:N/C:C/I:C/A:P/E:ND/RL:W/RC:UR/CDP:H/TD:N/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "e86828b5 1.7", // test name
        "AV:A/AC:M/Au:N/C:C/I:N/A:P/E:U/RL:U/RC:UC/CDP:MH/TD:L/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "19b374a3 0.0", // test name
        "AV:A/AC:M/Au:N/C:N/I:N/A:N/E:F/RL:U/RC:C/CDP:N/TD:M/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "0fc697e3 1.8", // test name
        "AV:A/AC:M/Au:N/C:P/I:C/A:P/E:U/RL:TF/RC:UR/CDP:LM/TD:L/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "d162d0a2 3.3", // test name
        "AV:A/AC:M/Au:S/C:N/I:N/A:C/E:F/RL:TF/RC:ND/CDP:ND/TD:M/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "faefd571 4.2", // test name
        "AV:A/AC:M/Au:S/C:N/I:P/A:N/E:F/RL:W/RC:C/CDP:H/TD:M/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "d0456876 1.4", // test name
        "AV:A/AC:M/Au:S/C:P/I:N/A:C/E:H/RL:OF/RC:UC/CDP:ND/TD:L/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "b106cee0 2.0", // test name
        "AV:A/AC:M/Au:S/C:P/I:N/A:N/E:POC/RL:W/RC:C/CDP:N/TD:ND/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "d35c5d42 4.1", // test name
        "AV:L/AC:H/Au:M/C:C/I:N/A:C/E:POC/RL:OF/RC:C/CDP:N/TD:H/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "12a0fd4f 3.8", // test name
        "AV:L/AC:H/Au:M/C:N/I:N/A:C/E:H/RL:TF/RC:ND/CDP:LM/TD:H/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "1aa812e6 5.3", // test name
        "AV:L/AC:H/Au:M/C:N/I:P/A:P/E:ND/RL:U/RC:UR/CDP:MH/TD:H/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "56e0ded5 0.0", // test name
        "AV:L/AC:H/Au:N/C:C/I:C/A:P/E:POC/RL:U/RC:C/CDP:ND/TD:N/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "00a330d5 4.3", // test name
        "AV:L/AC:H/Au:N/C:C/I:P/A:C/E:F/RL:W/RC:C/CDP:L/TD:ND/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "2a47838f 3.6", // test name
        "AV:L/AC:H/Au:N/C:N/I:C/A:N/E:POC/RL:ND/RC:C/CDP:N/TD:ND/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "fb2fc086 5.0", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:C/E:F/RL:OF/RC:UR/CDP:H/TD:M/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "776d422d 1.9", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:P/E:ND/RL:U/RC:UR/CDP:N/TD:M/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "6158ed04 1.2", // test name
        "AV:L/AC:H/Au:N/C:P/I:N/A:C/E:POC/RL:TF/RC:UR/CDP:N/TD:L/CR:L/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "a0741a9a 0.0", // test name
        "AV:L/AC:H/Au:S/C:C/I:C/A:C/E:H/RL:ND/RC:UR/CDP:MH/TD:N/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "fb52aca8 6.3", // test name
        "AV:L/AC:H/Au:S/C:C/I:P/A:P/E:F/RL:OF/RC:C/CDP:H/TD:ND/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "d52d7ec3 1.8", // test name
        "AV:L/AC:H/Au:S/C:N/I:C/A:C/E:ND/RL:OF/RC:C/CDP:H/TD:L/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "f5e82720 0.0", // test name
        "AV:L/AC:H/Au:S/C:N/I:P/A:P/E:ND/RL:OF/RC:C/CDP:L/TD:N/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(2.4), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "cd87d33a 5.7", // test name
        "AV:L/AC:L/Au:M/C:C/I:P/A:N/E:POC/RL:TF/RC:ND/CDP:L/TD:ND/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "8e64967a 1.6", // test name
        "AV:L/AC:L/Au:M/C:C/I:P/A:N/E:POC/RL:TF/RC:UR/CDP:MH/TD:L/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "a9ed9889 1.7", // test name
        "AV:L/AC:L/Au:M/C:N/I:C/A:C/E:F/RL:TF/RC:UR/CDP:LM/TD:L/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "15de42b6 4.2", // test name
        "AV:L/AC:L/Au:N/C:C/I:P/A:P/E:ND/RL:OF/RC:ND/CDP:L/TD:M/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "62461d3f 1.7", // test name
        "AV:L/AC:L/Au:N/C:N/I:N/A:P/E:ND/RL:OF/RC:UR/CDP:ND/TD:ND/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "3e31ba93 0.0", // test name
        "AV:L/AC:L/Au:N/C:N/I:P/A:N/E:POC/RL:TF/RC:C/CDP:LM/TD:N/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "17228ec1 0.0", // test name
        "AV:L/AC:L/Au:N/C:P/I:C/A:C/E:H/RL:TF/RC:ND/CDP:H/TD:N/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "4a2ceb5c 4.0", // test name
        "AV:L/AC:L/Au:N/C:P/I:C/A:N/E:F/RL:U/RC:UR/CDP:ND/TD:M/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "f4ae6dd1 4.4", // test name
        "AV:L/AC:L/Au:N/C:P/I:C/A:P/E:H/RL:TF/RC:ND/CDP:N/TD:ND/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "5bcd5427 1.7", // test name
        "AV:L/AC:L/Au:S/C:C/I:N/A:N/E:F/RL:OF/RC:UR/CDP:H/TD:L/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "13f23f7f 1.6", // test name
        "AV:L/AC:L/Au:S/C:N/I:C/A:N/E:H/RL:OF/RC:ND/CDP:MH/TD:L/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "9636b909 6.1", // test name
        "AV:L/AC:L/Au:S/C:P/I:C/A:N/E:H/RL:U/RC:UC/CDP:N/TD:ND/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "06dc20a0 4.0", // test name
        "AV:L/AC:L/Au:S/C:P/I:P/A:N/E:F/RL:U/RC:C/CDP:MH/TD:M/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "b22fd998 0.0", // test name
        "AV:L/AC:M/Au:M/C:C/I:N/A:N/E:ND/RL:ND/RC:ND/CDP:MH/TD:N/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "0d927f2e 5.1", // test name
        "AV:L/AC:M/Au:M/C:C/I:P/A:C/E:H/RL:OF/RC:UR/CDP:ND/TD:H/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "db5f1563 2.8", // test name
        "AV:L/AC:M/Au:M/C:N/I:C/A:N/E:U/RL:TF/RC:UC/CDP:N/TD:H/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "50bef73f 5.9", // test name
        "AV:L/AC:M/Au:M/C:N/I:C/A:P/E:POC/RL:U/RC:UC/CDP:LM/TD:ND/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "9778fe35 5.8", // test name
        "AV:L/AC:M/Au:M/C:N/I:N/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "ef5e6fe4 1.6", // test name
        "AV:L/AC:M/Au:N/C:C/I:C/A:C/E:ND/RL:W/RC:C/CDP:ND/TD:L/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "efd74c5e 0.0", // test name
        "AV:L/AC:M/Au:N/C:C/I:P/A:P/E:F/RL:ND/RC:UC/CDP:MH/TD:N/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "6647e8c1 6.1", // test name
        "AV:L/AC:M/Au:N/C:P/I:P/A:C/E:F/RL:OF/RC:UC/CDP:LM/TD:H/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "a9ab9dbd 0.0", // test name
        "AV:N/AC:H/Au:M/C:C/I:P/A:C/E:H/RL:W/RC:ND/CDP:ND/TD:N/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "34956359 8.4", // test name
        "AV:N/AC:H/Au:N/C:C/I:C/A:N/E:POC/RL:ND/RC:C/CDP:H/TD:ND/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "762898b2 0.7", // test name
        "AV:N/AC:H/Au:N/C:C/I:N/A:N/E:H/RL:ND/RC:C/CDP:ND/TD:L/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(0.7)), // exp environmental score
        }, // exp
      ), (
        "8fe095e1 8.1", // test name
        "AV:N/AC:H/Au:N/C:C/I:P/A:N/E:ND/RL:U/RC:UC/CDP:MH/TD:ND/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "c16b84ba 6.1", // test name
        "AV:N/AC:H/Au:N/C:N/I:N/A:C/E:U/RL:W/RC:ND/CDP:N/TD:ND/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "587d6f45 3.3", // test name
        "AV:N/AC:H/Au:N/C:N/I:P/A:C/E:POC/RL:W/RC:UC/CDP:ND/TD:H/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "9eeb16e6 4.2", // test name
        "AV:N/AC:H/Au:N/C:N/I:P/A:N/E:ND/RL:ND/RC:ND/CDP:L/TD:H/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "4a1cf3e1 4.6", // test name
        "AV:N/AC:H/Au:N/C:P/I:C/A:P/E:F/RL:U/RC:C/CDP:L/TD:M/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "34a31e9e 1.5", // test name
        "AV:N/AC:H/Au:S/C:C/I:C/A:N/E:F/RL:TF/RC:ND/CDP:L/TD:L/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "8765cad3 6.8", // test name
        "AV:N/AC:H/Au:S/C:C/I:P/A:P/E:ND/RL:W/RC:C/CDP:N/TD:H/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "dad0e799 0.0", // test name
        "AV:N/AC:L/Au:M/C:C/I:P/A:P/E:H/RL:W/RC:C/CDP:L/TD:N/CR:ND/IR:H/AR:H", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "60b80796 0.0", // test name
        "AV:N/AC:L/Au:M/C:N/I:C/A:C/E:POC/RL:TF/RC:UR/CDP:LM/TD:N/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d7a152d9 4.9", // test name
        "AV:N/AC:L/Au:M/C:N/I:P/A:P/E:U/RL:TF/RC:UC/CDP:LM/TD:ND/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "f39248e0 0.0", // test name
        "AV:N/AC:L/Au:M/C:P/I:C/A:N/E:POC/RL:U/RC:UC/CDP:ND/TD:N/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "ab7c8678 0.0", // test name
        "AV:N/AC:L/Au:M/C:P/I:P/A:C/E:POC/RL:U/RC:UC/CDP:ND/TD:N/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "ae336cf2 8.4", // test name
        "AV:N/AC:L/Au:N/C:C/I:C/A:N/E:F/RL:OF/RC:ND/CDP:L/TD:H/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(9.4), // exp base score
          temporal: Some(Score::from(7.8)), // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "adb59edf 1.6", // test name
        "AV:N/AC:L/Au:N/C:N/I:C/A:N/E:F/RL:TF/RC:C/CDP:LM/TD:L/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "35ff58e1 5.0", // test name
        "AV:N/AC:L/Au:N/C:N/I:C/A:P/E:ND/RL:ND/RC:ND/CDP:N/TD:M/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "b239936c 6.3", // test name
        "AV:N/AC:L/Au:N/C:P/I:N/A:N/E:POC/RL:OF/RC:ND/CDP:MH/TD:ND/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "6151d4dd 5.4", // test name
        "AV:N/AC:L/Au:N/C:P/I:P/A:P/E:ND/RL:U/RC:UC/CDP:N/TD:M/CR:M/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "193183a4 9.4", // test name
        "AV:N/AC:L/Au:S/C:C/I:P/A:N/E:H/RL:ND/RC:ND/CDP:MH/TD:H/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(9.4)), // exp environmental score
        }, // exp
      ), (
        "389d57bc 0.0", // test name
        "AV:N/AC:L/Au:S/C:C/I:P/A:P/E:U/RL:U/RC:UC/CDP:N/TD:N/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "6e8ed73c 1.8", // test name
        "AV:N/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UC/CDP:LM/TD:L/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "e54f7cc9 0.0", // test name
        "AV:N/AC:M/Au:M/C:C/I:P/A:N/E:ND/RL:TF/RC:UC/CDP:ND/TD:N/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "aa314a91 2.9", // test name
        "AV:N/AC:M/Au:M/C:C/I:P/A:N/E:POC/RL:TF/RC:UC/CDP:ND/TD:H/CR:L/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "3059f861 5.6", // test name
        "AV:N/AC:M/Au:M/C:N/I:N/A:C/E:H/RL:U/RC:UR/CDP:ND/TD:M/CR:L/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "3256427b 1.2", // test name
        "AV:N/AC:M/Au:M/C:N/I:P/A:N/E:U/RL:W/RC:ND/CDP:LM/TD:L/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "bbceb2ae 7.4", // test name
        "AV:N/AC:M/Au:N/C:C/I:C/A:P/E:U/RL:OF/RC:UC/CDP:LM/TD:H/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "d4aab307 6.0", // test name
        "AV:N/AC:M/Au:N/C:C/I:N/A:C/E:POC/RL:U/RC:C/CDP:LM/TD:M/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(8.8), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "dbcf4f71 6.7", // test name
        "AV:N/AC:M/Au:N/C:P/I:C/A:C/E:ND/RL:OF/RC:ND/CDP:MH/TD:M/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(7.8)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "f8c633ac 1.3", // test name
        "AV:N/AC:M/Au:N/C:P/I:N/A:C/E:U/RL:U/RC:C/CDP:ND/TD:L/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "62e94804 8.1", // test name
        "AV:N/AC:M/Au:S/C:C/I:C/A:P/E:H/RL:TF/RC:UC/CDP:H/TD:H/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "2d70f285 0.0", // test name
        "AV:N/AC:M/Au:S/C:C/I:N/A:N/E:H/RL:ND/RC:UR/CDP:MH/TD:N/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "e56d06e6 5.8", // test name
        "AV:N/AC:M/Au:S/C:C/I:P/A:N/E:ND/RL:OF/RC:ND/CDP:N/TD:H/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "ef421e86 0.0", // test name
        "AV:A/AC:H/Au:M/C:C/I:C/A:P/E:H/RL:W/RC:ND/CDP:L/TD:N/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "cda6964e 1.7", // test name
        "AV:A/AC:H/Au:M/C:C/I:N/A:N/E:F/RL:ND/RC:UC/CDP:LM/TD:L/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "8f1ae712 3.8", // test name
        "AV:A/AC:H/Au:M/C:C/I:N/A:N/E:U/RL:U/RC:UC/CDP:L/TD:ND/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "bfb0cd74 1.3", // test name
        "AV:A/AC:H/Au:M/C:C/I:N/A:N/E:U/RL:U/RC:UR/CDP:ND/TD:ND/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "ac3352fc 7.5", // test name
        "AV:A/AC:H/Au:M/C:C/I:N/A:P/E:U/RL:W/RC:ND/CDP:H/TD:ND/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "aa0cc916 3.3", // test name
        "AV:A/AC:H/Au:M/C:C/I:P/A:N/E:POC/RL:U/RC:UR/CDP:LM/TD:M/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "5d6e4d54 3.9", // test name
        "AV:A/AC:H/Au:M/C:C/I:P/A:P/E:POC/RL:OF/RC:C/CDP:ND/TD:ND/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "b2ee7906 0.0", // test name
        "AV:A/AC:H/Au:M/C:N/I:C/A:P/E:POC/RL:TF/RC:UC/CDP:H/TD:N/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "97aef686 1.4", // test name
        "AV:A/AC:H/Au:M/C:N/I:N/A:C/E:POC/RL:ND/RC:C/CDP:H/TD:L/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "a8108d23 0.0", // test name
        "AV:A/AC:H/Au:M/C:N/I:P/A:N/E:POC/RL:OF/RC:C/CDP:MH/TD:N/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(1.2), // exp base score
          temporal: Some(Score::from(0.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "e24deb88 2.3", // test name
        "AV:A/AC:H/Au:M/C:N/I:P/A:P/E:POC/RL:U/RC:C/CDP:ND/TD:M/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(2.3)), // exp environmental score
        }, // exp
      ), (
        "c5402bfb 5.2", // test name
        "AV:A/AC:H/Au:M/C:P/I:C/A:C/E:POC/RL:TF/RC:UR/CDP:L/TD:ND/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "fbe29561 7.1", // test name
        "AV:A/AC:H/Au:M/C:P/I:C/A:N/E:F/RL:W/RC:UC/CDP:H/TD:H/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "b871f1c7 5.2", // test name
        "AV:A/AC:H/Au:M/C:P/I:C/A:N/E:U/RL:W/RC:C/CDP:H/TD:M/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "5a83b24c 6.5", // test name
        "AV:A/AC:H/Au:M/C:P/I:C/A:P/E:POC/RL:U/RC:UC/CDP:MH/TD:H/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "355389e5 0.7", // test name
        "AV:A/AC:H/Au:M/C:P/I:N/A:P/E:F/RL:U/RC:UC/CDP:N/TD:L/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(0.7)), // exp environmental score
        }, // exp
      ), (
        "47f9742a 0.0", // test name
        "AV:A/AC:H/Au:M/C:P/I:N/A:P/E:ND/RL:ND/RC:ND/CDP:L/TD:N/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "bdc9ef39 0.7", // test name
        "AV:A/AC:H/Au:M/C:P/I:N/A:P/E:U/RL:ND/RC:UR/CDP:ND/TD:L/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(0.7)), // exp environmental score
        }, // exp
      ), (
        "94afac8e 1.7", // test name
        "AV:A/AC:H/Au:M/C:P/I:P/A:C/E:POC/RL:TF/RC:UC/CDP:H/TD:L/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "0c239619 2.7", // test name
        "AV:A/AC:H/Au:M/C:P/I:P/A:P/E:F/RL:W/RC:UR/CDP:N/TD:ND/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "3ebc7586 6.9", // test name
        "AV:A/AC:H/Au:M/C:P/I:P/A:P/E:POC/RL:U/RC:UR/CDP:H/TD:H/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "abed878e 7.1", // test name
        "AV:A/AC:H/Au:N/C:C/I:C/A:C/E:H/RL:TF/RC:UR/CDP:LM/TD:ND/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "0f4bc406 7.5", // test name
        "AV:A/AC:H/Au:N/C:C/I:C/A:C/E:ND/RL:TF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "2afaccd2 5.3", // test name
        "AV:A/AC:H/Au:N/C:C/I:C/A:N/E:ND/RL:OF/RC:UC/CDP:ND/TD:H/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "c908bf51 4.4", // test name
        "AV:A/AC:H/Au:N/C:C/I:C/A:N/E:POC/RL:W/RC:ND/CDP:ND/TD:M/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "4399c274 0.0", // test name
        "AV:A/AC:H/Au:N/C:C/I:C/A:N/E:U/RL:W/RC:C/CDP:N/TD:N/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "550c1f2a 0.0", // test name
        "AV:A/AC:H/Au:N/C:C/I:C/A:P/E:ND/RL:TF/RC:ND/CDP:N/TD:N/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "aae2d9ac 7.7", // test name
        "AV:A/AC:H/Au:N/C:C/I:N/A:C/E:F/RL:TF/RC:C/CDP:H/TD:H/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "292ac9b7 0.0", // test name
        "AV:A/AC:H/Au:N/C:C/I:N/A:C/E:POC/RL:W/RC:UC/CDP:L/TD:N/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "76c7127f 4.0", // test name
        "AV:A/AC:H/Au:N/C:C/I:N/A:P/E:H/RL:U/RC:UR/CDP:N/TD:M/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "8355958b 6.1", // test name
        "AV:A/AC:H/Au:N/C:C/I:P/A:C/E:F/RL:W/RC:ND/CDP:N/TD:ND/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "729eca93 4.3", // test name
        "AV:A/AC:H/Au:N/C:C/I:P/A:N/E:U/RL:U/RC:C/CDP:N/TD:M/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "bb27ab62 4.1", // test name
        "AV:A/AC:H/Au:N/C:C/I:P/A:P/E:ND/RL:OF/RC:C/CDP:L/TD:M/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "b89e5802 5.5", // test name
        "AV:A/AC:H/Au:N/C:N/I:C/A:C/E:POC/RL:TF/RC:ND/CDP:MH/TD:M/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "c1e2f915 1.1", // test name
        "AV:A/AC:H/Au:N/C:N/I:C/A:N/E:ND/RL:TF/RC:UR/CDP:L/TD:L/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "79edb4ba 1.9", // test name
        "AV:A/AC:H/Au:N/C:N/I:C/A:N/E:POC/RL:W/RC:C/CDP:ND/TD:ND/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "d283eedc 1.4", // test name
        "AV:A/AC:H/Au:N/C:N/I:C/A:N/E:U/RL:ND/RC:C/CDP:ND/TD:L/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "417b58df 0.9", // test name
        "AV:A/AC:H/Au:N/C:N/I:C/A:P/E:F/RL:U/RC:UC/CDP:ND/TD:L/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(0.9)), // exp environmental score
        }, // exp
      ), (
        "6f04a9b9 0.0", // test name
        "AV:A/AC:H/Au:N/C:N/I:C/A:P/E:F/RL:W/RC:ND/CDP:N/TD:N/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9770dc98 4.9", // test name
        "AV:A/AC:H/Au:N/C:N/I:C/A:P/E:ND/RL:TF/RC:C/CDP:L/TD:M/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "1cb4bf59 0.0", // test name
        "AV:A/AC:H/Au:N/C:N/I:N/A:C/E:H/RL:U/RC:C/CDP:ND/TD:N/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "27f8c875 0.0", // test name
        "AV:A/AC:H/Au:N/C:N/I:N/A:N/E:H/RL:W/RC:UC/CDP:N/TD:H/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "639c6b66 0.0", // test name
        "AV:A/AC:H/Au:N/C:N/I:N/A:N/E:ND/RL:W/RC:UR/CDP:N/TD:H/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "844aa9f2 0.0", // test name
        "AV:A/AC:H/Au:N/C:N/I:N/A:P/E:F/RL:OF/RC:UR/CDP:ND/TD:N/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d5318791 1.8", // test name
        "AV:A/AC:H/Au:N/C:N/I:P/A:C/E:H/RL:OF/RC:ND/CDP:H/TD:L/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "857466f9 2.1", // test name
        "AV:A/AC:H/Au:N/C:N/I:P/A:N/E:H/RL:ND/RC:ND/CDP:N/TD:M/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.8)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "be2df86a 0.0", // test name
        "AV:A/AC:H/Au:N/C:N/I:P/A:N/E:ND/RL:U/RC:UR/CDP:H/TD:N/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d0904b14 0.0", // test name
        "AV:A/AC:H/Au:N/C:N/I:P/A:P/E:U/RL:OF/RC:ND/CDP:H/TD:N/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "33cea7b4 6.7", // test name
        "AV:A/AC:H/Au:N/C:P/I:C/A:C/E:U/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "fc82cc63 3.5", // test name
        "AV:A/AC:H/Au:N/C:P/I:C/A:N/E:POC/RL:OF/RC:C/CDP:L/TD:M/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "bfabaa0c 7.4", // test name
        "AV:A/AC:H/Au:N/C:P/I:C/A:P/E:U/RL:TF/RC:C/CDP:H/TD:ND/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "88dbcc49 4.2", // test name
        "AV:A/AC:H/Au:N/C:P/I:N/A:C/E:U/RL:W/RC:UR/CDP:LM/TD:M/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "dd6408dc 3.5", // test name
        "AV:A/AC:H/Au:N/C:P/I:N/A:N/E:ND/RL:W/RC:ND/CDP:LM/TD:H/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "8b5e252f 1.3", // test name
        "AV:A/AC:H/Au:N/C:P/I:N/A:N/E:U/RL:OF/RC:C/CDP:H/TD:L/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(1.8), // exp base score
          temporal: Some(Score::from(1.3)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "08019882 4.5", // test name
        "AV:A/AC:H/Au:N/C:P/I:N/A:P/E:H/RL:OF/RC:C/CDP:LM/TD:ND/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "898cadfe 0.0", // test name
        "AV:A/AC:H/Au:N/C:P/I:N/A:P/E:U/RL:W/RC:C/CDP:H/TD:N/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "fd967feb 1.1", // test name
        "AV:A/AC:H/Au:N/C:P/I:N/A:P/E:U/RL:W/RC:UR/CDP:LM/TD:L/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "8803938a 7.1", // test name
        "AV:A/AC:H/Au:N/C:P/I:P/A:C/E:F/RL:OF/RC:UC/CDP:H/TD:H/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "476a40b1 5.8", // test name
        "AV:A/AC:H/Au:N/C:P/I:P/A:C/E:F/RL:OF/RC:UR/CDP:L/TD:H/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "621c0a60 0.0", // test name
        "AV:A/AC:H/Au:N/C:P/I:P/A:C/E:U/RL:W/RC:C/CDP:MH/TD:N/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d2024b94 1.6", // test name
        "AV:A/AC:H/Au:N/C:P/I:P/A:N/E:F/RL:TF/RC:UR/CDP:L/TD:M/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "349f1f75 1.3", // test name
        "AV:A/AC:H/Au:S/C:C/I:C/A:C/E:F/RL:TF/RC:UR/CDP:ND/TD:L/CR:L/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "1a2e8c8c 0.0", // test name
        "AV:A/AC:H/Au:S/C:C/I:C/A:C/E:POC/RL:W/RC:UR/CDP:ND/TD:N/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "3eb920c2 7.2", // test name
        "AV:A/AC:H/Au:S/C:C/I:C/A:P/E:F/RL:OF/RC:C/CDP:MH/TD:ND/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "8097080b 1.4", // test name
        "AV:A/AC:H/Au:S/C:C/I:C/A:P/E:H/RL:TF/RC:C/CDP:N/TD:L/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "7e4805a6 0.0", // test name
        "AV:A/AC:H/Au:S/C:C/I:N/A:C/E:F/RL:U/RC:UR/CDP:MH/TD:N/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "0ff1995a 6.0", // test name
        "AV:A/AC:H/Au:S/C:C/I:N/A:N/E:F/RL:TF/RC:UC/CDP:MH/TD:H/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "a8e6a2ce 5.5", // test name
        "AV:A/AC:H/Au:S/C:C/I:N/A:N/E:H/RL:TF/RC:UR/CDP:LM/TD:H/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "d1aea843 0.6", // test name
        "AV:A/AC:H/Au:S/C:C/I:N/A:N/E:U/RL:TF/RC:C/CDP:L/TD:L/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(0.6)), // exp environmental score
        }, // exp
      ), (
        "77a9a711 1.9", // test name
        "AV:A/AC:H/Au:S/C:C/I:N/A:N/E:U/RL:W/RC:ND/CDP:H/TD:L/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "393effe8 0.8", // test name
        "AV:A/AC:H/Au:S/C:C/I:N/A:P/E:H/RL:W/RC:UR/CDP:L/TD:L/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(0.8)), // exp environmental score
        }, // exp
      ), (
        "ff44270c 0.0", // test name
        "AV:A/AC:H/Au:S/C:C/I:N/A:P/E:POC/RL:U/RC:C/CDP:ND/TD:N/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "18ba431c 5.4", // test name
        "AV:A/AC:H/Au:S/C:C/I:P/A:C/E:H/RL:U/RC:C/CDP:LM/TD:M/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "80c2a8ef 6.5", // test name
        "AV:A/AC:H/Au:S/C:C/I:P/A:N/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "b0d93069 0.0", // test name
        "AV:A/AC:H/Au:S/C:C/I:P/A:N/E:ND/RL:ND/RC:C/CDP:N/TD:N/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "43d6a333 0.0", // test name
        "AV:A/AC:H/Au:S/C:C/I:P/A:N/E:POC/RL:ND/RC:C/CDP:H/TD:N/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "4f9d0c04 0.0", // test name
        "AV:A/AC:H/Au:S/C:C/I:P/A:N/E:POC/RL:OF/RC:UC/CDP:H/TD:N/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "2140a4cc 6.5", // test name
        "AV:A/AC:H/Au:S/C:C/I:P/A:P/E:F/RL:U/RC:C/CDP:L/TD:ND/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "90a85749 3.7", // test name
        "AV:A/AC:H/Au:S/C:C/I:P/A:P/E:ND/RL:W/RC:UC/CDP:N/TD:M/CR:M/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "abfb7849 7.1", // test name
        "AV:A/AC:H/Au:S/C:N/I:C/A:C/E:U/RL:W/RC:C/CDP:MH/TD:ND/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "82b25a62 1.8", // test name
        "AV:A/AC:H/Au:S/C:N/I:C/A:N/E:ND/RL:ND/RC:C/CDP:H/TD:L/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "6d111b4d 0.0", // test name
        "AV:A/AC:H/Au:S/C:N/I:C/A:N/E:U/RL:TF/RC:C/CDP:H/TD:N/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "53905d07 1.5", // test name
        "AV:A/AC:H/Au:S/C:N/I:C/A:N/E:U/RL:W/RC:UR/CDP:MH/TD:L/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "b92be14f 4.2", // test name
        "AV:A/AC:H/Au:S/C:N/I:C/A:P/E:F/RL:OF/RC:ND/CDP:MH/TD:M/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "ca1239d3 0.3", // test name
        "AV:A/AC:H/Au:S/C:N/I:N/A:P/E:H/RL:TF/RC:UC/CDP:N/TD:L/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(0.3)), // exp environmental score
        }, // exp
      ), (
        "1004903f 0.0", // test name
        "AV:A/AC:H/Au:S/C:N/I:N/A:P/E:ND/RL:ND/RC:ND/CDP:N/TD:N/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "6171a3f1 1.3", // test name
        "AV:A/AC:H/Au:S/C:N/I:N/A:P/E:POC/RL:TF/RC:UC/CDP:N/TD:M/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.0)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "f738e140 1.2", // test name
        "AV:A/AC:H/Au:S/C:N/I:P/A:C/E:H/RL:ND/RC:C/CDP:N/TD:L/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "a0b37833 1.1", // test name
        "AV:A/AC:H/Au:S/C:N/I:P/A:C/E:ND/RL:TF/RC:ND/CDP:ND/TD:L/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "26f780b7 0.0", // test name
        "AV:A/AC:H/Au:S/C:N/I:P/A:C/E:U/RL:ND/RC:UC/CDP:N/TD:N/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "e47c9426 0.3", // test name
        "AV:A/AC:H/Au:S/C:N/I:P/A:N/E:U/RL:ND/RC:C/CDP:L/TD:L/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.2)), // exp temporal score
          environmental: Some(Score::from(0.3)), // exp environmental score
        }, // exp
      ), (
        "ff000aa7 1.3", // test name
        "AV:A/AC:H/Au:S/C:N/I:P/A:N/E:U/RL:ND/RC:C/CDP:MH/TD:L/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.2)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "22253264 4.1", // test name
        "AV:A/AC:H/Au:S/C:N/I:P/A:P/E:U/RL:U/RC:ND/CDP:MH/TD:M/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "190e3ba8 7.8", // test name
        "AV:A/AC:H/Au:S/C:P/I:C/A:C/E:H/RL:U/RC:ND/CDP:MH/TD:ND/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "744a3728 0.0", // test name
        "AV:A/AC:H/Au:S/C:P/I:C/A:C/E:U/RL:U/RC:C/CDP:MH/TD:N/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "26935abd 5.0", // test name
        "AV:A/AC:H/Au:S/C:P/I:N/A:C/E:F/RL:ND/RC:UR/CDP:MH/TD:M/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "0ad8fc40 1.8", // test name
        "AV:A/AC:H/Au:S/C:P/I:N/A:P/E:U/RL:ND/RC:C/CDP:N/TD:H/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "a9303e56 0.0", // test name
        "AV:A/AC:H/Au:S/C:P/I:P/A:C/E:POC/RL:ND/RC:ND/CDP:ND/TD:N/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "51fec675 0.0", // test name
        "AV:A/AC:H/Au:S/C:P/I:P/A:C/E:POC/RL:OF/RC:UR/CDP:MH/TD:N/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "5a399105 0.8", // test name
        "AV:A/AC:H/Au:S/C:P/I:P/A:P/E:F/RL:OF/RC:ND/CDP:ND/TD:L/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(0.8)), // exp environmental score
        }, // exp
      ), (
        "a4412182 1.4", // test name
        "AV:A/AC:H/Au:S/C:P/I:P/A:P/E:F/RL:TF/RC:UC/CDP:LM/TD:L/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "09d28af9 6.2", // test name
        "AV:A/AC:H/Au:S/C:P/I:P/A:P/E:F/RL:W/RC:ND/CDP:MH/TD:ND/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "388b5a0f 0.0", // test name
        "AV:A/AC:H/Au:S/C:P/I:P/A:P/E:ND/RL:W/RC:ND/CDP:N/TD:N/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "fa6ac2fd 4.5", // test name
        "AV:A/AC:H/Au:S/C:P/I:P/A:P/E:POC/RL:W/RC:C/CDP:L/TD:ND/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "1d1f16e9 1.5", // test name
        "AV:A/AC:L/Au:M/C:C/I:C/A:C/E:F/RL:U/RC:UC/CDP:ND/TD:L/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "b78d23b3 0.0", // test name
        "AV:A/AC:L/Au:M/C:C/I:C/A:C/E:POC/RL:W/RC:UC/CDP:ND/TD:N/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "4c5ebbf1 4.9", // test name
        "AV:A/AC:L/Au:M/C:C/I:C/A:C/E:U/RL:OF/RC:UC/CDP:MH/TD:M/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(7.2), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "cd1e18a4 1.9", // test name
        "AV:A/AC:L/Au:M/C:C/I:C/A:P/E:F/RL:U/RC:ND/CDP:LM/TD:L/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "fb01323d 5.1", // test name
        "AV:A/AC:L/Au:M/C:C/I:C/A:P/E:ND/RL:ND/RC:ND/CDP:N/TD:H/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "913c3cb7 5.0", // test name
        "AV:A/AC:L/Au:M/C:C/I:N/A:N/E:ND/RL:OF/RC:ND/CDP:MH/TD:M/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "c8418b29 7.3", // test name
        "AV:A/AC:L/Au:M/C:C/I:N/A:P/E:F/RL:TF/RC:C/CDP:H/TD:ND/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "c8c42b86 4.1", // test name
        "AV:A/AC:L/Au:M/C:C/I:N/A:P/E:H/RL:OF/RC:ND/CDP:L/TD:H/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "acc9ac25 0.0", // test name
        "AV:A/AC:L/Au:M/C:C/I:P/A:C/E:F/RL:OF/RC:ND/CDP:H/TD:N/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "6686435c 1.9", // test name
        "AV:A/AC:L/Au:M/C:C/I:P/A:C/E:ND/RL:OF/RC:ND/CDP:MH/TD:L/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "34393f2e 2.0", // test name
        "AV:A/AC:L/Au:M/C:C/I:P/A:C/E:ND/RL:TF/RC:ND/CDP:H/TD:L/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "da51e0b2 7.3", // test name
        "AV:A/AC:L/Au:M/C:C/I:P/A:C/E:U/RL:W/RC:ND/CDP:MH/TD:H/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "7f5f47de 8.4", // test name
        "AV:A/AC:L/Au:M/C:C/I:P/A:N/E:F/RL:ND/RC:ND/CDP:H/TD:ND/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "fbf000bd 5.6", // test name
        "AV:A/AC:L/Au:M/C:C/I:P/A:N/E:F/RL:U/RC:UC/CDP:H/TD:M/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "f2aa8692 0.0", // test name
        "AV:A/AC:L/Au:M/C:C/I:P/A:N/E:POC/RL:U/RC:ND/CDP:H/TD:N/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "7f4517f6 1.7", // test name
        "AV:A/AC:L/Au:M/C:C/I:P/A:N/E:U/RL:TF/RC:ND/CDP:MH/TD:L/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "cf5e514b 0.0", // test name
        "AV:A/AC:L/Au:M/C:C/I:P/A:P/E:H/RL:U/RC:UC/CDP:LM/TD:N/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "3ded18df 6.7", // test name
        "AV:A/AC:L/Au:M/C:N/I:C/A:C/E:H/RL:U/RC:C/CDP:ND/TD:H/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "aa9a059b 1.7", // test name
        "AV:A/AC:L/Au:M/C:N/I:C/A:C/E:POC/RL:W/RC:UC/CDP:MH/TD:L/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "45713ded 0.0", // test name
        "AV:A/AC:L/Au:M/C:N/I:C/A:C/E:POC/RL:W/RC:UC/CDP:ND/TD:N/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "15258561 0.0", // test name
        "AV:A/AC:L/Au:M/C:N/I:C/A:C/E:U/RL:TF/RC:ND/CDP:MH/TD:N/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "26d888d3 3.7", // test name
        "AV:A/AC:L/Au:M/C:N/I:C/A:C/E:U/RL:TF/RC:UC/CDP:ND/TD:M/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "1e49db4b 2.0", // test name
        "AV:A/AC:L/Au:M/C:N/I:C/A:C/E:U/RL:U/RC:UR/CDP:H/TD:L/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "b30f929c 7.8", // test name
        "AV:A/AC:L/Au:M/C:N/I:C/A:N/E:H/RL:OF/RC:ND/CDP:MH/TD:ND/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "b038b895 4.3", // test name
        "AV:A/AC:L/Au:M/C:N/I:C/A:N/E:U/RL:TF/RC:UR/CDP:LM/TD:H/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "6b674b71 5.0", // test name
        "AV:A/AC:L/Au:M/C:N/I:N/A:N/E:ND/RL:W/RC:ND/CDP:H/TD:ND/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "e6cdbf97 0.0", // test name
        "AV:A/AC:L/Au:M/C:N/I:N/A:N/E:POC/RL:U/RC:C/CDP:ND/TD:M/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "489e6f73 0.7", // test name
        "AV:A/AC:L/Au:M/C:N/I:N/A:P/E:F/RL:W/RC:C/CDP:L/TD:L/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(2.2), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(0.7)), // exp environmental score
        }, // exp
      ), (
        "a51abb51 0.9", // test name
        "AV:A/AC:L/Au:M/C:N/I:P/A:N/E:POC/RL:OF/RC:ND/CDP:LM/TD:L/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(2.2), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(0.9)), // exp environmental score
        }, // exp
      ), (
        "e6956e59 3.1", // test name
        "AV:A/AC:L/Au:M/C:N/I:P/A:N/E:POC/RL:OF/RC:UR/CDP:LM/TD:M/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(2.2), // exp base score
          temporal: Some(Score::from(1.6)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "68b0af88 1.4", // test name
        "AV:A/AC:L/Au:M/C:N/I:P/A:N/E:POC/RL:U/RC:UC/CDP:L/TD:M/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(2.2), // exp base score
          temporal: Some(Score::from(1.8)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "e02f6c70 3.1", // test name
        "AV:A/AC:L/Au:M/C:N/I:P/A:P/E:ND/RL:TF/RC:UC/CDP:ND/TD:ND/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "e120bdcd 5.5", // test name
        "AV:A/AC:L/Au:M/C:P/I:C/A:N/E:F/RL:W/RC:UR/CDP:LM/TD:M/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "034432c4 1.6", // test name
        "AV:A/AC:L/Au:M/C:P/I:C/A:P/E:ND/RL:OF/RC:C/CDP:MH/TD:L/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "f65a61d7 6.9", // test name
        "AV:A/AC:L/Au:M/C:P/I:N/A:C/E:H/RL:W/RC:C/CDP:ND/TD:H/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "5784075e 2.6", // test name
        "AV:A/AC:L/Au:M/C:P/I:N/A:P/E:H/RL:OF/RC:ND/CDP:L/TD:ND/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "f68e5427 2.9", // test name
        "AV:A/AC:L/Au:M/C:P/I:N/A:P/E:ND/RL:U/RC:C/CDP:N/TD:ND/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "057e00ec 4.2", // test name
        "AV:A/AC:L/Au:M/C:P/I:N/A:P/E:ND/RL:U/RC:UR/CDP:N/TD:H/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "97be9ac7 0.0", // test name
        "AV:A/AC:L/Au:M/C:P/I:N/A:P/E:U/RL:TF/RC:UR/CDP:N/TD:N/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "62551a46 1.4", // test name
        "AV:A/AC:L/Au:M/C:P/I:N/A:P/E:U/RL:U/RC:UC/CDP:MH/TD:L/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "3098672e 3.3", // test name
        "AV:A/AC:L/Au:M/C:P/I:P/A:C/E:H/RL:ND/RC:UC/CDP:N/TD:M/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "4c1293a4 1.4", // test name
        "AV:A/AC:L/Au:M/C:P/I:P/A:P/E:H/RL:ND/RC:C/CDP:LM/TD:L/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "c689b010 3.0", // test name
        "AV:A/AC:L/Au:M/C:P/I:P/A:P/E:U/RL:TF/RC:UR/CDP:N/TD:H/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "cfe3a659 7.7", // test name
        "AV:A/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:U/RC:C/CDP:N/TD:ND/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "4edd28bf 7.7", // test name
        "AV:A/AC:L/Au:N/C:C/I:C/A:N/E:U/RL:TF/RC:C/CDP:H/TD:H/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "fc93aefa 7.7", // test name
        "AV:A/AC:L/Au:N/C:C/I:C/A:P/E:U/RL:W/RC:ND/CDP:H/TD:ND/CR:L/IR:L/AR:H", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "73201c00 1.8", // test name
        "AV:A/AC:L/Au:N/C:C/I:N/A:C/E:F/RL:TF/RC:C/CDP:N/TD:L/CR:L/IR:L/AR:H", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "e0ba3691 8.5", // test name
        "AV:A/AC:L/Au:N/C:C/I:N/A:C/E:H/RL:U/RC:ND/CDP:H/TD:H/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(7.8)), // exp temporal score
          environmental: Some(Score::from(8.5)), // exp environmental score
        }, // exp
      ), (
        "8c0845ce 5.7", // test name
        "AV:A/AC:L/Au:N/C:C/I:N/A:C/E:U/RL:TF/RC:ND/CDP:MH/TD:M/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "c345d65e 5.8", // test name
        "AV:A/AC:L/Au:N/C:C/I:N/A:N/E:H/RL:U/RC:UR/CDP:N/TD:H/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "88e517c7 1.4", // test name
        "AV:A/AC:L/Au:N/C:C/I:N/A:P/E:POC/RL:W/RC:C/CDP:N/TD:L/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "40a289cc 1.6", // test name
        "AV:A/AC:L/Au:N/C:C/I:N/A:P/E:U/RL:U/RC:UC/CDP:LM/TD:L/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "f76da346 7.6", // test name
        "AV:A/AC:L/Au:N/C:C/I:P/A:C/E:H/RL:OF/RC:UC/CDP:LM/TD:H/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "ad9fa5fb 6.4", // test name
        "AV:A/AC:L/Au:N/C:C/I:P/A:C/E:POC/RL:ND/RC:C/CDP:MH/TD:M/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "31fa7577 8.1", // test name
        "AV:A/AC:L/Au:N/C:C/I:P/A:N/E:H/RL:TF/RC:C/CDP:H/TD:H/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "20e80978 1.7", // test name
        "AV:A/AC:L/Au:N/C:C/I:P/A:P/E:U/RL:OF/RC:UC/CDP:MH/TD:L/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "d106f328 2.0", // test name
        "AV:A/AC:L/Au:N/C:N/I:C/A:C/E:POC/RL:ND/RC:UC/CDP:H/TD:L/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "39c37353 6.7", // test name
        "AV:A/AC:L/Au:N/C:N/I:C/A:C/E:POC/RL:TF/RC:C/CDP:L/TD:H/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "43bda20b 4.9", // test name
        "AV:A/AC:L/Au:N/C:N/I:C/A:N/E:F/RL:TF/RC:ND/CDP:H/TD:M/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "6306de12 0.0", // test name
        "AV:A/AC:L/Au:N/C:N/I:N/A:N/E:F/RL:W/RC:ND/CDP:ND/TD:L/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "27891fcf 0.0", // test name
        "AV:A/AC:L/Au:N/C:N/I:N/A:N/E:U/RL:TF/RC:ND/CDP:L/TD:N/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "3298ac31 6.5", // test name
        "AV:A/AC:L/Au:N/C:N/I:N/A:P/E:F/RL:W/RC:ND/CDP:H/TD:ND/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "d6865734 4.8", // test name
        "AV:A/AC:L/Au:N/C:N/I:N/A:P/E:POC/RL:OF/RC:ND/CDP:LM/TD:H/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "0b5ec106 1.9", // test name
        "AV:A/AC:L/Au:N/C:N/I:P/A:C/E:H/RL:TF/RC:C/CDP:N/TD:L/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "6ba9536d 0.0", // test name
        "AV:A/AC:L/Au:N/C:N/I:P/A:N/E:POC/RL:OF/RC:UR/CDP:LM/TD:N/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8ab6a6a0 7.5", // test name
        "AV:A/AC:L/Au:N/C:N/I:P/A:P/E:ND/RL:TF/RC:ND/CDP:H/TD:ND/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "c6480a57 3.5", // test name
        "AV:A/AC:L/Au:N/C:N/I:P/A:P/E:ND/RL:TF/RC:UR/CDP:L/TD:M/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "8110de8e 3.6", // test name
        "AV:A/AC:L/Au:N/C:N/I:P/A:P/E:POC/RL:ND/RC:ND/CDP:N/TD:H/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "5189438e 5.7", // test name
        "AV:A/AC:L/Au:N/C:N/I:P/A:P/E:U/RL:W/RC:ND/CDP:LM/TD:ND/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "f3afd4bc 6.7", // test name
        "AV:A/AC:L/Au:N/C:P/I:C/A:C/E:POC/RL:ND/RC:C/CDP:ND/TD:ND/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "a6f2bcb7 4.6", // test name
        "AV:A/AC:L/Au:N/C:P/I:C/A:C/E:U/RL:ND/RC:UC/CDP:N/TD:M/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "89a02185 0.0", // test name
        "AV:A/AC:L/Au:N/C:P/I:C/A:C/E:U/RL:U/RC:C/CDP:MH/TD:N/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "b6f1fffe 6.9", // test name
        "AV:A/AC:L/Au:N/C:P/I:C/A:P/E:F/RL:OF/RC:C/CDP:N/TD:H/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "83fae13d 5.7", // test name
        "AV:A/AC:L/Au:N/C:P/I:C/A:P/E:POC/RL:TF/RC:UC/CDP:MH/TD:M/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "b2c33970 5.6", // test name
        "AV:A/AC:L/Au:N/C:P/I:C/A:P/E:U/RL:OF/RC:C/CDP:ND/TD:H/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "4dbd3ed6 1.6", // test name
        "AV:A/AC:L/Au:N/C:P/I:N/A:C/E:F/RL:OF/RC:UR/CDP:MH/TD:L/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "a8c1908d 3.5", // test name
        "AV:A/AC:L/Au:N/C:P/I:N/A:N/E:F/RL:ND/RC:UC/CDP:L/TD:ND/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "0a0d0890 3.2", // test name
        "AV:A/AC:L/Au:N/C:P/I:N/A:P/E:POC/RL:OF/RC:ND/CDP:N/TD:ND/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "4a6a5da8 0.0", // test name
        "AV:A/AC:L/Au:N/C:P/I:N/A:P/E:POC/RL:W/RC:C/CDP:L/TD:N/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "6d66fb59 5.6", // test name
        "AV:A/AC:L/Au:N/C:P/I:P/A:C/E:F/RL:TF/RC:UC/CDP:ND/TD:H/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "434fd6cd 2.1", // test name
        "AV:A/AC:L/Au:N/C:P/I:P/A:C/E:H/RL:U/RC:UR/CDP:H/TD:L/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "9713b702 4.0", // test name
        "AV:A/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:U/RC:C/CDP:N/TD:H/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "426f634a 4.8", // test name
        "AV:A/AC:L/Au:N/C:P/I:P/A:P/E:F/RL:OF/RC:C/CDP:N/TD:H/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "d502b98c 0.0", // test name
        "AV:A/AC:L/Au:S/C:C/I:C/A:C/E:POC/RL:W/RC:UC/CDP:N/TD:N/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "371a0c4c 6.6", // test name
        "AV:A/AC:L/Au:S/C:C/I:C/A:N/E:H/RL:TF/RC:UR/CDP:N/TD:ND/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "0d4e6454 0.0", // test name
        "AV:A/AC:L/Au:S/C:C/I:C/A:N/E:POC/RL:OF/RC:UR/CDP:ND/TD:N/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "cab07bdb 6.2", // test name
        "AV:A/AC:L/Au:S/C:C/I:N/A:N/E:F/RL:TF/RC:UC/CDP:H/TD:H/CR:L/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "fb788ebd 1.4", // test name
        "AV:A/AC:L/Au:S/C:C/I:N/A:N/E:F/RL:TF/RC:UC/CDP:MH/TD:L/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "e2aa3278 2.8", // test name
        "AV:A/AC:L/Au:S/C:C/I:N/A:N/E:F/RL:U/RC:UR/CDP:N/TD:ND/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "facd28e9 5.2", // test name
        "AV:A/AC:L/Au:S/C:C/I:N/A:N/E:ND/RL:W/RC:ND/CDP:ND/TD:H/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "93388255 5.0", // test name
        "AV:A/AC:L/Au:S/C:C/I:N/A:N/E:POC/RL:ND/RC:UC/CDP:L/TD:M/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "3deef772 6.8", // test name
        "AV:A/AC:L/Au:S/C:C/I:N/A:N/E:POC/RL:W/RC:ND/CDP:MH/TD:ND/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "f9e7574c 3.0", // test name
        "AV:A/AC:L/Au:S/C:C/I:N/A:N/E:U/RL:OF/RC:ND/CDP:N/TD:M/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "3db7580e 4.4", // test name
        "AV:A/AC:L/Au:S/C:C/I:N/A:N/E:U/RL:W/RC:C/CDP:ND/TD:H/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "46247246 7.8", // test name
        "AV:A/AC:L/Au:S/C:C/I:N/A:P/E:ND/RL:TF/RC:C/CDP:LM/TD:ND/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "aa29a5e0 4.6", // test name
        "AV:A/AC:L/Au:S/C:C/I:N/A:P/E:POC/RL:OF/RC:UR/CDP:L/TD:M/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "1f3e8384 7.2", // test name
        "AV:A/AC:L/Au:S/C:C/I:P/A:C/E:F/RL:OF/RC:ND/CDP:MH/TD:H/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "5d201a5e 1.5", // test name
        "AV:A/AC:L/Au:S/C:C/I:P/A:C/E:U/RL:ND/RC:UR/CDP:L/TD:L/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "2271ce57 5.1", // test name
        "AV:A/AC:L/Au:S/C:C/I:P/A:P/E:U/RL:OF/RC:ND/CDP:N/TD:H/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "373107fe 4.4", // test name
        "AV:A/AC:L/Au:S/C:N/I:N/A:C/E:U/RL:U/RC:UC/CDP:ND/TD:M/CR:L/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "82db75aa 0.0", // test name
        "AV:A/AC:L/Au:S/C:N/I:N/A:P/E:F/RL:U/RC:C/CDP:N/TD:N/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "47ab57fe 4.8", // test name
        "AV:A/AC:L/Au:S/C:N/I:N/A:P/E:POC/RL:W/RC:ND/CDP:MH/TD:ND/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "9245df83 0.0", // test name
        "AV:A/AC:L/Au:S/C:N/I:P/A:P/E:ND/RL:ND/RC:UR/CDP:H/TD:N/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "7a5736f8 0.0", // test name
        "AV:A/AC:L/Au:S/C:N/I:P/A:P/E:ND/RL:TF/RC:C/CDP:ND/TD:N/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "c467edc9 7.3", // test name
        "AV:A/AC:L/Au:S/C:P/I:C/A:C/E:ND/RL:W/RC:ND/CDP:ND/TD:ND/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "2d85eb10 0.0", // test name
        "AV:A/AC:L/Au:S/C:P/I:C/A:C/E:POC/RL:TF/RC:C/CDP:L/TD:N/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(7.4), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "6ba17d06 4.9", // test name
        "AV:A/AC:L/Au:S/C:P/I:C/A:N/E:U/RL:U/RC:C/CDP:N/TD:M/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "7d92a529 7.9", // test name
        "AV:A/AC:L/Au:S/C:P/I:C/A:P/E:ND/RL:ND/RC:UC/CDP:H/TD:H/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "d9b2fa23 1.2", // test name
        "AV:A/AC:L/Au:S/C:P/I:N/A:N/E:H/RL:ND/RC:UR/CDP:N/TD:M/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "f7871527 0.0", // test name
        "AV:A/AC:L/Au:S/C:P/I:N/A:N/E:ND/RL:ND/RC:ND/CDP:L/TD:N/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "59ba87ed 1.3", // test name
        "AV:A/AC:L/Au:S/C:P/I:N/A:P/E:F/RL:OF/RC:ND/CDP:LM/TD:L/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "a7806e85 4.0", // test name
        "AV:A/AC:L/Au:S/C:P/I:N/A:P/E:ND/RL:U/RC:ND/CDP:L/TD:ND/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "bb566552 7.0", // test name
        "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:F/RL:OF/RC:UR/CDP:MH/TD:H/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "1ca257bc 7.9", // test name
        "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:H/RL:U/RC:ND/CDP:L/TD:ND/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "1db1c0b9 0.0", // test name
        "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:U/RC:ND/CDP:N/TD:N/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.7), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "1d65a7d2 5.2", // test name
        "AV:A/AC:L/Au:S/C:P/I:P/A:P/E:ND/RL:W/RC:ND/CDP:H/TD:M/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "5e8c686d 3.5", // test name
        "AV:A/AC:L/Au:S/C:P/I:P/A:P/E:POC/RL:W/RC:UR/CDP:N/TD:M/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "a8e82d98 1.8", // test name
        "AV:A/AC:M/Au:M/C:C/I:C/A:P/E:H/RL:TF/RC:UR/CDP:LM/TD:L/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "af36d705 0.0", // test name
        "AV:A/AC:M/Au:M/C:C/I:C/A:P/E:POC/RL:OF/RC:ND/CDP:N/TD:N/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "650bf835 0.0", // test name
        "AV:A/AC:M/Au:M/C:C/I:C/A:P/E:POC/RL:U/RC:UC/CDP:L/TD:N/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "e3ad8179 4.5", // test name
        "AV:A/AC:M/Au:M/C:C/I:N/A:N/E:F/RL:U/RC:UR/CDP:LM/TD:H/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "e19cdd6c 4.3", // test name
        "AV:A/AC:M/Au:M/C:C/I:N/A:P/E:H/RL:ND/RC:ND/CDP:L/TD:ND/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "482da4d8 4.1", // test name
        "AV:A/AC:M/Au:M/C:C/I:N/A:P/E:ND/RL:OF/RC:UC/CDP:MH/TD:M/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "7b389882 1.4", // test name
        "AV:A/AC:M/Au:M/C:C/I:P/A:N/E:ND/RL:TF/RC:UR/CDP:L/TD:L/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "6efb50e1 1.3", // test name
        "AV:A/AC:M/Au:M/C:C/I:P/A:P/E:H/RL:TF/RC:C/CDP:L/TD:L/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "9c9f272d 6.9", // test name
        "AV:A/AC:M/Au:M/C:C/I:P/A:P/E:H/RL:TF/RC:ND/CDP:H/TD:H/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "a85212bf 5.3", // test name
        "AV:A/AC:M/Au:M/C:C/I:P/A:P/E:U/RL:U/RC:UC/CDP:N/TD:H/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "2f468288 1.2", // test name
        "AV:A/AC:M/Au:M/C:N/I:C/A:C/E:H/RL:ND/RC:UC/CDP:N/TD:L/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "6c4e3774 6.3", // test name
        "AV:A/AC:M/Au:M/C:N/I:C/A:C/E:ND/RL:W/RC:UR/CDP:N/TD:ND/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "cd5b255b 4.8", // test name
        "AV:A/AC:M/Au:M/C:N/I:C/A:N/E:H/RL:TF/RC:C/CDP:L/TD:H/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "1140639d 4.0", // test name
        "AV:A/AC:M/Au:M/C:N/I:C/A:N/E:U/RL:ND/RC:ND/CDP:N/TD:H/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "2dbc3230 4.7", // test name
        "AV:A/AC:M/Au:M/C:N/I:C/A:N/E:U/RL:W/RC:C/CDP:MH/TD:M/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "7b44383a 3.0", // test name
        "AV:A/AC:M/Au:M/C:N/I:N/A:N/E:ND/RL:ND/RC:C/CDP:MH/TD:M/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "8cf534ab 0.3", // test name
        "AV:A/AC:M/Au:M/C:N/I:N/A:N/E:POC/RL:U/RC:C/CDP:L/TD:L/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.3)), // exp environmental score
        }, // exp
      ), (
        "ada064bb 1.5", // test name
        "AV:A/AC:M/Au:M/C:N/I:N/A:P/E:F/RL:ND/RC:UC/CDP:H/TD:L/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.6)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "398a26a1 0.0", // test name
        "AV:A/AC:M/Au:M/C:N/I:P/A:C/E:H/RL:U/RC:ND/CDP:LM/TD:N/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8d9e420a 6.9", // test name
        "AV:A/AC:M/Au:M/C:N/I:P/A:C/E:ND/RL:ND/RC:ND/CDP:ND/TD:H/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "7bac0a70 1.7", // test name
        "AV:A/AC:M/Au:M/C:N/I:P/A:C/E:ND/RL:W/RC:ND/CDP:MH/TD:L/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "25aae316 1.2", // test name
        "AV:A/AC:M/Au:M/C:N/I:P/A:P/E:POC/RL:ND/RC:ND/CDP:LM/TD:L/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "ed3bd01b 4.3", // test name
        "AV:A/AC:M/Au:M/C:P/I:C/A:C/E:F/RL:ND/RC:ND/CDP:N/TD:M/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "51f59cdb 0.0", // test name
        "AV:A/AC:M/Au:M/C:P/I:C/A:C/E:ND/RL:U/RC:UC/CDP:ND/TD:N/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "19e4bb73 0.0", // test name
        "AV:A/AC:M/Au:M/C:P/I:C/A:P/E:ND/RL:W/RC:UR/CDP:MH/TD:N/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "1e16d711 4.1", // test name
        "AV:A/AC:M/Au:M/C:P/I:C/A:P/E:POC/RL:TF/RC:UR/CDP:ND/TD:ND/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "5cc7b53e 0.0", // test name
        "AV:A/AC:M/Au:M/C:P/I:N/A:N/E:F/RL:ND/RC:C/CDP:ND/TD:N/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "20a4bbfb 4.9", // test name
        "AV:A/AC:M/Au:M/C:P/I:N/A:N/E:ND/RL:OF/RC:UR/CDP:MH/TD:H/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.6)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "af23f938 3.7", // test name
        "AV:A/AC:M/Au:M/C:P/I:N/A:P/E:ND/RL:TF/RC:UC/CDP:LM/TD:M/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "77533b22 3.3", // test name
        "AV:A/AC:M/Au:M/C:P/I:N/A:P/E:POC/RL:TF/RC:C/CDP:ND/TD:ND/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "9218ed8f 4.5", // test name
        "AV:A/AC:M/Au:M/C:P/I:P/A:C/E:U/RL:OF/RC:UR/CDP:MH/TD:M/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "84e2e2f0 0.0", // test name
        "AV:A/AC:M/Au:M/C:P/I:P/A:N/E:ND/RL:ND/RC:UR/CDP:H/TD:N/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "f67df70b 4.8", // test name
        "AV:A/AC:M/Au:M/C:P/I:P/A:P/E:H/RL:ND/RC:UR/CDP:ND/TD:ND/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "d2a31f35 7.1", // test name
        "AV:A/AC:M/Au:M/C:P/I:P/A:P/E:H/RL:W/RC:C/CDP:H/TD:ND/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "1c602ded 6.3", // test name
        "AV:A/AC:M/Au:M/C:P/I:P/A:P/E:POC/RL:ND/RC:UR/CDP:MH/TD:H/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "0373a58f 4.1", // test name
        "AV:A/AC:M/Au:M/C:P/I:P/A:P/E:POC/RL:OF/RC:C/CDP:L/TD:ND/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "0742468b 7.5", // test name
        "AV:A/AC:M/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:ND/CDP:MH/TD:ND/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "d4774c52 0.0", // test name
        "AV:A/AC:M/Au:N/C:C/I:C/A:N/E:F/RL:W/RC:UR/CDP:MH/TD:N/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8fcfbd3c 4.3", // test name
        "AV:A/AC:M/Au:N/C:C/I:C/A:P/E:U/RL:OF/RC:ND/CDP:N/TD:ND/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "5da8ab94 7.5", // test name
        "AV:A/AC:M/Au:N/C:C/I:C/A:P/E:U/RL:TF/RC:UR/CDP:H/TD:ND/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "01c26e09 1.7", // test name
        "AV:A/AC:M/Au:N/C:C/I:N/A:C/E:F/RL:TF/RC:C/CDP:LM/TD:L/CR:L/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "37efe799 2.1", // test name
        "AV:A/AC:M/Au:N/C:C/I:N/A:C/E:H/RL:TF/RC:ND/CDP:MH/TD:L/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "b8c46c59 4.6", // test name
        "AV:A/AC:M/Au:N/C:C/I:N/A:N/E:H/RL:TF/RC:UC/CDP:N/TD:ND/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "aa7b4539 0.0", // test name
        "AV:A/AC:M/Au:N/C:C/I:N/A:N/E:POC/RL:ND/RC:C/CDP:L/TD:N/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "bcfb29c0 0.0", // test name
        "AV:A/AC:M/Au:N/C:C/I:P/A:N/E:U/RL:TF/RC:UC/CDP:LM/TD:N/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "11c8fa02 5.1", // test name
        "AV:A/AC:M/Au:N/C:N/I:C/A:C/E:ND/RL:OF/RC:UC/CDP:N/TD:ND/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "f93cf539 6.0", // test name
        "AV:A/AC:M/Au:N/C:N/I:C/A:P/E:H/RL:TF/RC:UR/CDP:MH/TD:H/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "4d8d39ee 1.1", // test name
        "AV:A/AC:M/Au:N/C:N/I:N/A:C/E:POC/RL:W/RC:UC/CDP:ND/TD:L/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "dc86362c 5.5", // test name
        "AV:A/AC:M/Au:N/C:N/I:N/A:C/E:U/RL:W/RC:UR/CDP:MH/TD:H/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "91b01ee3 0.0", // test name
        "AV:A/AC:M/Au:N/C:N/I:N/A:N/E:F/RL:ND/RC:C/CDP:N/TD:H/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "efaf6c70 0.0", // test name
        "AV:A/AC:M/Au:N/C:N/I:N/A:N/E:F/RL:U/RC:UC/CDP:N/TD:ND/CR:L/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9446168a 0.8", // test name
        "AV:A/AC:M/Au:N/C:N/I:N/A:N/E:H/RL:ND/RC:C/CDP:L/TD:M/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.8)), // exp environmental score
        }, // exp
      ), (
        "ed8dd30d 2.3", // test name
        "AV:A/AC:M/Au:N/C:N/I:N/A:P/E:POC/RL:TF/RC:C/CDP:N/TD:ND/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(2.3)), // exp environmental score
        }, // exp
      ), (
        "8bc53ebf 1.6", // test name
        "AV:A/AC:M/Au:N/C:N/I:N/A:P/E:POC/RL:U/RC:C/CDP:H/TD:L/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "19d3e65f 1.0", // test name
        "AV:A/AC:M/Au:N/C:N/I:P/A:N/E:U/RL:U/RC:ND/CDP:LM/TD:L/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "f6d98e00 2.5", // test name
        "AV:A/AC:M/Au:N/C:N/I:P/A:P/E:ND/RL:W/RC:C/CDP:ND/TD:M/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(2.5)), // exp environmental score
        }, // exp
      ), (
        "99d6c112 4.6", // test name
        "AV:A/AC:M/Au:N/C:N/I:P/A:P/E:POC/RL:OF/RC:C/CDP:L/TD:H/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "953f9a8b 3.7", // test name
        "AV:A/AC:M/Au:N/C:N/I:P/A:P/E:U/RL:TF/RC:UR/CDP:N/TD:ND/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "9ac2be70 1.9", // test name
        "AV:A/AC:M/Au:N/C:P/I:C/A:C/E:U/RL:ND/RC:C/CDP:LM/TD:L/CR:L/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "fb543c16 5.0", // test name
        "AV:A/AC:M/Au:N/C:P/I:C/A:N/E:POC/RL:OF/RC:C/CDP:LM/TD:M/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "e29029e1 7.8", // test name
        "AV:A/AC:M/Au:N/C:P/I:C/A:P/E:H/RL:TF/RC:C/CDP:MH/TD:H/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "2d99a9ee 6.2", // test name
        "AV:A/AC:M/Au:N/C:P/I:C/A:P/E:H/RL:TF/RC:ND/CDP:N/TD:H/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "95714d61 6.4", // test name
        "AV:A/AC:M/Au:N/C:P/I:N/A:C/E:F/RL:U/RC:C/CDP:N/TD:H/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "4d0be557 4.4", // test name
        "AV:A/AC:M/Au:N/C:P/I:N/A:C/E:H/RL:OF/RC:C/CDP:N/TD:M/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "f3e7e223 0.0", // test name
        "AV:A/AC:M/Au:N/C:P/I:N/A:N/E:H/RL:OF/RC:UR/CDP:ND/TD:N/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "b0343c8b 0.0", // test name
        "AV:A/AC:M/Au:N/C:P/I:N/A:N/E:H/RL:TF/RC:ND/CDP:MH/TD:N/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "4389df20 2.7", // test name
        "AV:A/AC:M/Au:N/C:P/I:N/A:N/E:ND/RL:U/RC:UR/CDP:ND/TD:H/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "03e47ec1 0.0", // test name
        "AV:A/AC:M/Au:N/C:P/I:N/A:P/E:F/RL:W/RC:ND/CDP:MH/TD:N/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "2003026d 2.0", // test name
        "AV:A/AC:M/Au:N/C:P/I:P/A:C/E:F/RL:U/RC:ND/CDP:H/TD:L/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "cac497cd 6.5", // test name
        "AV:A/AC:M/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:ND/CDP:MH/TD:ND/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "98e524bc 4.9", // test name
        "AV:A/AC:M/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C/CDP:L/TD:H/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "b4627d37 1.3", // test name
        "AV:A/AC:M/Au:S/C:C/I:N/A:C/E:H/RL:TF/RC:UC/CDP:L/TD:L/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "cf844df4 6.8", // test name
        "AV:A/AC:M/Au:S/C:C/I:N/A:C/E:H/RL:W/RC:C/CDP:L/TD:H/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "354a74df 7.8", // test name
        "AV:A/AC:M/Au:S/C:C/I:N/A:C/E:POC/RL:W/RC:ND/CDP:MH/TD:ND/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "4f634889 6.6", // test name
        "AV:A/AC:M/Au:S/C:C/I:N/A:N/E:F/RL:U/RC:UR/CDP:N/TD:H/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "8482866f 0.7", // test name
        "AV:A/AC:M/Au:S/C:C/I:N/A:N/E:U/RL:OF/RC:UC/CDP:L/TD:L/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(0.7)), // exp environmental score
        }, // exp
      ), (
        "06948d64 8.3", // test name
        "AV:A/AC:M/Au:S/C:C/I:N/A:P/E:F/RL:ND/RC:UR/CDP:H/TD:H/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(8.3)), // exp environmental score
        }, // exp
      ), (
        "eb28294f 0.0", // test name
        "AV:A/AC:M/Au:S/C:C/I:N/A:P/E:F/RL:U/RC:ND/CDP:H/TD:N/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "dd67d700 7.6", // test name
        "AV:A/AC:M/Au:S/C:C/I:N/A:P/E:POC/RL:U/RC:ND/CDP:H/TD:H/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "00d2034b 4.5", // test name
        "AV:A/AC:M/Au:S/C:C/I:N/A:P/E:U/RL:OF/RC:UR/CDP:LM/TD:M/CR:ND/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "da5a9557 5.7", // test name
        "AV:A/AC:M/Au:S/C:C/I:P/A:C/E:F/RL:TF/RC:UC/CDP:ND/TD:H/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "4d8cda01 7.0", // test name
        "AV:A/AC:M/Au:S/C:C/I:P/A:N/E:POC/RL:U/RC:ND/CDP:L/TD:ND/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "b5274929 2.0", // test name
        "AV:A/AC:M/Au:S/C:N/I:C/A:C/E:H/RL:W/RC:UR/CDP:H/TD:L/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "8b8b3600 1.6", // test name
        "AV:A/AC:M/Au:S/C:N/I:C/A:C/E:POC/RL:U/RC:UR/CDP:ND/TD:L/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "8742b02a 7.5", // test name
        "AV:A/AC:M/Au:S/C:N/I:C/A:C/E:U/RL:U/RC:C/CDP:MH/TD:ND/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(7.5)), // exp environmental score
        }, // exp
      ), (
        "fdaa794d 5.7", // test name
        "AV:A/AC:M/Au:S/C:N/I:C/A:N/E:H/RL:U/RC:ND/CDP:H/TD:M/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "f1fd872b 6.7", // test name
        "AV:A/AC:M/Au:S/C:N/I:C/A:P/E:H/RL:W/RC:C/CDP:LM/TD:H/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "33eb7494 0.0", // test name
        "AV:A/AC:M/Au:S/C:N/I:N/A:C/E:H/RL:OF/RC:C/CDP:N/TD:N/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "f81f932a 0.0", // test name
        "AV:A/AC:M/Au:S/C:N/I:N/A:N/E:H/RL:TF/RC:UR/CDP:N/TD:L/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "e9348d2c 2.3", // test name
        "AV:A/AC:M/Au:S/C:N/I:N/A:N/E:ND/RL:ND/RC:ND/CDP:LM/TD:M/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(2.3)), // exp environmental score
        }, // exp
      ), (
        "542596ed 0.0", // test name
        "AV:A/AC:M/Au:S/C:N/I:N/A:N/E:ND/RL:W/RC:C/CDP:H/TD:N/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "7a2d904d 3.6", // test name
        "AV:A/AC:M/Au:S/C:N/I:N/A:P/E:H/RL:W/RC:UC/CDP:L/TD:H/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "c74edf6e 5.1", // test name
        "AV:A/AC:M/Au:S/C:N/I:P/A:C/E:H/RL:OF/RC:UR/CDP:N/TD:H/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "084e1a85 7.6", // test name
        "AV:A/AC:M/Au:S/C:N/I:P/A:C/E:ND/RL:U/RC:ND/CDP:L/TD:H/CR:L/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "1dfc999b 6.7", // test name
        "AV:A/AC:M/Au:S/C:N/I:P/A:N/E:H/RL:U/RC:ND/CDP:H/TD:ND/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "f95b4c9f 6.6", // test name
        "AV:A/AC:M/Au:S/C:N/I:P/A:P/E:H/RL:U/RC:UR/CDP:MH/TD:ND/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "8184d7a8 4.0", // test name
        "AV:A/AC:M/Au:S/C:P/I:C/A:N/E:F/RL:OF/RC:ND/CDP:LM/TD:M/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "4c2356e9 1.7", // test name
        "AV:A/AC:M/Au:S/C:P/I:C/A:P/E:F/RL:W/RC:ND/CDP:N/TD:L/CR:ND/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "ab7f431e 1.6", // test name
        "AV:A/AC:M/Au:S/C:P/I:C/A:P/E:H/RL:ND/RC:ND/CDP:ND/TD:L/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "33a28b81 0.0", // test name
        "AV:A/AC:M/Au:S/C:P/I:N/A:C/E:ND/RL:ND/RC:UC/CDP:N/TD:N/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "80b04e3e 1.6", // test name
        "AV:A/AC:M/Au:S/C:P/I:N/A:C/E:U/RL:ND/RC:C/CDP:LM/TD:L/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "ac81d580 1.6", // test name
        "AV:A/AC:M/Au:S/C:P/I:N/A:N/E:F/RL:W/RC:C/CDP:ND/TD:M/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "63b947cf 3.4", // test name
        "AV:A/AC:M/Au:S/C:P/I:N/A:N/E:F/RL:W/RC:ND/CDP:LM/TD:M/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "6764ca84 3.7", // test name
        "AV:A/AC:M/Au:S/C:P/I:N/A:P/E:ND/RL:U/RC:UR/CDP:ND/TD:M/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "b8d18966 0.0", // test name
        "AV:A/AC:M/Au:S/C:P/I:N/A:P/E:POC/RL:ND/RC:C/CDP:ND/TD:N/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "0975719e 7.9", // test name
        "AV:A/AC:M/Au:S/C:P/I:P/A:C/E:H/RL:ND/RC:UR/CDP:LM/TD:H/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "0a5f6b01 5.8", // test name
        "AV:A/AC:M/Au:S/C:P/I:P/A:C/E:ND/RL:W/RC:C/CDP:L/TD:ND/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "b40e7d71 3.2", // test name
        "AV:A/AC:M/Au:S/C:P/I:P/A:N/E:ND/RL:U/RC:UR/CDP:L/TD:M/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "70140898 1.3", // test name
        "AV:L/AC:H/Au:M/C:C/I:C/A:C/E:POC/RL:W/RC:C/CDP:ND/TD:L/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "acd91656 3.8", // test name
        "AV:L/AC:H/Au:M/C:C/I:C/A:N/E:U/RL:TF/RC:UR/CDP:ND/TD:ND/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "6d320e7f 6.7", // test name
        "AV:L/AC:H/Au:M/C:C/I:C/A:P/E:ND/RL:U/RC:UC/CDP:LM/TD:ND/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "a33735b7 1.8", // test name
        "AV:L/AC:H/Au:M/C:C/I:N/A:P/E:U/RL:OF/RC:ND/CDP:H/TD:L/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "cb44809c 0.0", // test name
        "AV:L/AC:H/Au:M/C:C/I:P/A:C/E:H/RL:U/RC:UC/CDP:N/TD:N/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "87b5be4a 4.2", // test name
        "AV:L/AC:H/Au:M/C:C/I:P/A:C/E:ND/RL:W/RC:C/CDP:ND/TD:M/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "3d79bd59 5.5", // test name
        "AV:L/AC:H/Au:M/C:C/I:P/A:C/E:ND/RL:W/RC:UC/CDP:L/TD:H/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "26cdcd7c 6.0", // test name
        "AV:L/AC:H/Au:M/C:C/I:P/A:C/E:POC/RL:U/RC:C/CDP:LM/TD:H/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "251d2722 5.7", // test name
        "AV:L/AC:H/Au:M/C:C/I:P/A:N/E:POC/RL:OF/RC:ND/CDP:H/TD:ND/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "15d43ae2 1.6", // test name
        "AV:L/AC:H/Au:M/C:C/I:P/A:P/E:ND/RL:U/RC:UC/CDP:LM/TD:L/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "8aac39cd 4.5", // test name
        "AV:L/AC:H/Au:M/C:N/I:C/A:C/E:H/RL:W/RC:UC/CDP:ND/TD:H/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "c067cd0b 3.5", // test name
        "AV:L/AC:H/Au:M/C:N/I:C/A:N/E:H/RL:TF/RC:UR/CDP:MH/TD:M/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "dfb8e552 2.7", // test name
        "AV:L/AC:H/Au:M/C:N/I:C/A:N/E:U/RL:W/RC:UC/CDP:ND/TD:ND/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "8019c893 0.0", // test name
        "AV:L/AC:H/Au:M/C:N/I:N/A:C/E:H/RL:W/RC:UR/CDP:H/TD:N/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "ac1ddd3c 2.7", // test name
        "AV:L/AC:H/Au:M/C:N/I:N/A:C/E:U/RL:OF/RC:ND/CDP:ND/TD:H/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "36d1457e 1.0", // test name
        "AV:L/AC:H/Au:M/C:N/I:N/A:N/E:F/RL:U/RC:C/CDP:L/TD:ND/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "1d8045f2 1.0", // test name
        "AV:L/AC:H/Au:M/C:N/I:N/A:N/E:H/RL:TF/RC:UR/CDP:L/TD:ND/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "30dd2a0d 0.0", // test name
        "AV:L/AC:H/Au:M/C:N/I:N/A:N/E:U/RL:ND/RC:C/CDP:ND/TD:H/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d9e85d81 1.0", // test name
        "AV:L/AC:H/Au:M/C:N/I:N/A:N/E:U/RL:U/RC:UC/CDP:L/TD:ND/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "ea4c6750 5.3", // test name
        "AV:L/AC:H/Au:M/C:N/I:P/A:N/E:POC/RL:W/RC:UC/CDP:H/TD:ND/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(0.8), // exp base score
          temporal: Some(Score::from(0.6)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "7753724a 4.4", // test name
        "AV:L/AC:H/Au:M/C:N/I:P/A:P/E:ND/RL:TF/RC:ND/CDP:LM/TD:H/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "175fb285 0.0", // test name
        "AV:L/AC:H/Au:M/C:P/I:C/A:C/E:H/RL:TF/RC:UC/CDP:H/TD:N/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9eb98a72 4.8", // test name
        "AV:L/AC:H/Au:M/C:P/I:C/A:P/E:F/RL:OF/RC:C/CDP:LM/TD:M/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "194dcef8 3.7", // test name
        "AV:L/AC:H/Au:M/C:P/I:C/A:P/E:H/RL:U/RC:ND/CDP:N/TD:H/CR:L/IR:L/AR:H", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "d2fd8fce 7.6", // test name
        "AV:L/AC:H/Au:M/C:P/I:N/A:C/E:POC/RL:U/RC:C/CDP:H/TD:H/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "3dd2465a 0.0", // test name
        "AV:L/AC:H/Au:M/C:P/I:N/A:C/E:U/RL:OF/RC:UC/CDP:L/TD:N/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "54178dc0 4.4", // test name
        "AV:L/AC:H/Au:M/C:P/I:N/A:N/E:H/RL:OF/RC:UC/CDP:MH/TD:H/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(0.8), // exp base score
          temporal: Some(Score::from(0.6)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "923ae12c 0.0", // test name
        "AV:L/AC:H/Au:M/C:P/I:N/A:N/E:H/RL:U/RC:UC/CDP:N/TD:N/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(0.8), // exp base score
          temporal: Some(Score::from(0.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "1bf4bdf8 2.6", // test name
        "AV:L/AC:H/Au:M/C:P/I:N/A:P/E:H/RL:W/RC:UC/CDP:N/TD:H/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "2898b227 3.8", // test name
        "AV:L/AC:H/Au:M/C:P/I:P/A:N/E:H/RL:ND/RC:C/CDP:LM/TD:M/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "0b96c010 2.7", // test name
        "AV:L/AC:H/Au:M/C:P/I:P/A:N/E:POC/RL:U/RC:UC/CDP:L/TD:ND/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(2.3), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(2.7)), // exp environmental score
        }, // exp
      ), (
        "ea5aa4ac 5.6", // test name
        "AV:L/AC:H/Au:M/C:P/I:P/A:P/E:ND/RL:W/RC:ND/CDP:MH/TD:H/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "05a2dd8d 3.5", // test name
        "AV:L/AC:H/Au:M/C:P/I:P/A:P/E:POC/RL:W/RC:UR/CDP:ND/TD:H/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "24790fe8 3.6", // test name
        "AV:L/AC:H/Au:M/C:P/I:P/A:P/E:U/RL:ND/RC:ND/CDP:L/TD:ND/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(3.4), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "83e218d0 0.0", // test name
        "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:UC/CDP:LM/TD:N/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "f97a268a 0.0", // test name
        "AV:L/AC:H/Au:N/C:C/I:C/A:N/E:H/RL:ND/RC:C/CDP:MH/TD:N/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9cdfa916 1.0", // test name
        "AV:L/AC:H/Au:N/C:C/I:N/A:C/E:U/RL:W/RC:C/CDP:ND/TD:L/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "e81fb1de 5.0", // test name
        "AV:L/AC:H/Au:N/C:C/I:P/A:C/E:F/RL:ND/RC:UR/CDP:N/TD:ND/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "2ceb4f07 5.8", // test name
        "AV:L/AC:H/Au:N/C:C/I:P/A:N/E:ND/RL:OF/RC:ND/CDP:L/TD:ND/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "fc69d778 6.9", // test name
        "AV:L/AC:H/Au:N/C:C/I:P/A:P/E:F/RL:OF/RC:UR/CDP:H/TD:H/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "e0ba6f8c 4.9", // test name
        "AV:L/AC:H/Au:N/C:N/I:C/A:P/E:ND/RL:TF/RC:C/CDP:MH/TD:M/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "bda726d7 1.7", // test name
        "AV:L/AC:H/Au:N/C:N/I:C/A:P/E:POC/RL:U/RC:C/CDP:LM/TD:L/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "447bf9bc 5.0", // test name
        "AV:L/AC:H/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:UC/CDP:LM/TD:ND/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "a3ff3d77 0.0", // test name
        "AV:L/AC:H/Au:N/C:N/I:N/A:N/E:U/RL:OF/RC:UC/CDP:LM/TD:N/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "09c5b714 0.0", // test name
        "AV:L/AC:H/Au:N/C:N/I:N/A:P/E:POC/RL:U/RC:ND/CDP:ND/TD:L/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(1.2), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "518864c5 4.8", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:C/E:F/RL:ND/RC:ND/CDP:ND/TD:H/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "3b226760 7.7", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:C/E:H/RL:U/RC:ND/CDP:MH/TD:H/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "9df5c14f 1.0", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:C/E:H/RL:W/RC:UC/CDP:N/TD:L/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "2050bf84 1.4", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:C/E:POC/RL:W/RC:UC/CDP:LM/TD:L/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "d4f02ef0 5.1", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:N/E:F/RL:TF/RC:ND/CDP:H/TD:ND/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(1.2), // exp base score
          temporal: Some(Score::from(1.0)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "08f1bd73 1.4", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:N/E:F/RL:TF/RC:UC/CDP:H/TD:L/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(1.2), // exp base score
          temporal: Some(Score::from(0.9)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "90b62390 1.4", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:N/E:ND/RL:TF/RC:ND/CDP:L/TD:M/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(1.2), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "615f7151 3.1", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:N/E:POC/RL:U/RC:C/CDP:MH/TD:M/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(1.2), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(3.1)), // exp environmental score
        }, // exp
      ), (
        "fb8afe99 3.4", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:N/E:POC/RL:U/RC:UC/CDP:MH/TD:M/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(1.2), // exp base score
          temporal: Some(Score::from(1.0)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "30c14e78 2.6", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:P/E:H/RL:OF/RC:UC/CDP:N/TD:ND/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "a54ae968 5.3", // test name
        "AV:L/AC:H/Au:N/C:N/I:P/A:P/E:U/RL:ND/RC:C/CDP:MH/TD:ND/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "a877e491 6.9", // test name
        "AV:L/AC:H/Au:N/C:P/I:C/A:C/E:F/RL:ND/RC:UR/CDP:LM/TD:ND/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "13b87bd5 1.8", // test name
        "AV:L/AC:H/Au:N/C:P/I:C/A:C/E:H/RL:OF/RC:ND/CDP:H/TD:L/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "2e715ebb 1.4", // test name
        "AV:L/AC:H/Au:N/C:P/I:C/A:N/E:ND/RL:U/RC:C/CDP:MH/TD:L/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "2793a4eb 4.7", // test name
        "AV:L/AC:H/Au:N/C:P/I:C/A:N/E:U/RL:ND/RC:UC/CDP:N/TD:ND/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "78424c3e 6.0", // test name
        "AV:L/AC:H/Au:N/C:P/I:N/A:C/E:ND/RL:TF/RC:ND/CDP:L/TD:ND/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "997f2503 4.7", // test name
        "AV:L/AC:H/Au:N/C:P/I:N/A:P/E:ND/RL:W/RC:C/CDP:H/TD:M/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "5aa7cc30 7.1", // test name
        "AV:L/AC:H/Au:N/C:P/I:P/A:C/E:ND/RL:OF/RC:UR/CDP:MH/TD:H/CR:ND/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "24249085 5.2", // test name
        "AV:L/AC:H/Au:N/C:P/I:P/A:C/E:POC/RL:W/RC:C/CDP:L/TD:H/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "3dc04b3f 5.8", // test name
        "AV:L/AC:H/Au:N/C:P/I:P/A:N/E:H/RL:U/RC:C/CDP:LM/TD:H/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "ba0542bf 3.3", // test name
        "AV:L/AC:H/Au:N/C:P/I:P/A:N/E:U/RL:ND/RC:UC/CDP:L/TD:ND/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "aab6a961 5.8", // test name
        "AV:L/AC:H/Au:N/C:P/I:P/A:P/E:F/RL:ND/RC:C/CDP:MH/TD:H/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(3.7), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "46f7892c 5.9", // test name
        "AV:L/AC:H/Au:S/C:C/I:C/A:C/E:H/RL:W/RC:UR/CDP:L/TD:ND/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "ee086175 5.9", // test name
        "AV:L/AC:H/Au:S/C:C/I:C/A:N/E:H/RL:TF/RC:C/CDP:L/TD:ND/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "eafcea4c 7.4", // test name
        "AV:L/AC:H/Au:S/C:C/I:C/A:P/E:U/RL:ND/RC:UR/CDP:H/TD:H/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "47f19704 0.0", // test name
        "AV:L/AC:H/Au:S/C:C/I:N/A:C/E:U/RL:ND/RC:UR/CDP:H/TD:N/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "af91290b 0.4", // test name
        "AV:L/AC:H/Au:S/C:C/I:N/A:P/E:F/RL:OF/RC:UC/CDP:N/TD:L/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(0.4)), // exp environmental score
        }, // exp
      ), (
        "e11b6169 2.9", // test name
        "AV:L/AC:H/Au:S/C:C/I:N/A:P/E:F/RL:TF/RC:UC/CDP:L/TD:ND/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "b74d64f3 1.9", // test name
        "AV:L/AC:H/Au:S/C:C/I:P/A:P/E:H/RL:ND/RC:C/CDP:H/TD:L/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "4a4dc0c1 1.5", // test name
        "AV:L/AC:H/Au:S/C:N/I:C/A:C/E:F/RL:ND/RC:C/CDP:LM/TD:L/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "cfb8196c 5.1", // test name
        "AV:L/AC:H/Au:S/C:N/I:C/A:C/E:POC/RL:U/RC:UR/CDP:ND/TD:H/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "dbb95026 0.8", // test name
        "AV:L/AC:H/Au:S/C:N/I:C/A:N/E:F/RL:ND/RC:UC/CDP:ND/TD:L/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(0.8)), // exp environmental score
        }, // exp
      ), (
        "f37bd903 0.0", // test name
        "AV:L/AC:H/Au:S/C:N/I:C/A:P/E:U/RL:U/RC:UC/CDP:N/TD:N/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "5f9253fc 0.0", // test name
        "AV:L/AC:H/Au:S/C:N/I:N/A:N/E:H/RL:TF/RC:ND/CDP:ND/TD:N/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "a2d9194b 3.0", // test name
        "AV:L/AC:H/Au:S/C:N/I:N/A:N/E:POC/RL:ND/RC:ND/CDP:LM/TD:H/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "372264c3 3.0", // test name
        "AV:L/AC:H/Au:S/C:N/I:N/A:N/E:U/RL:OF/RC:C/CDP:LM/TD:ND/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "95923aae 5.0", // test name
        "AV:L/AC:H/Au:S/C:N/I:N/A:P/E:POC/RL:ND/RC:ND/CDP:H/TD:ND/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(1.0), // exp base score
          temporal: Some(Score::from(0.9)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "028bd862 1.5", // test name
        "AV:L/AC:H/Au:S/C:N/I:P/A:N/E:H/RL:TF/RC:ND/CDP:H/TD:L/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(1.0), // exp base score
          temporal: Some(Score::from(0.9)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "9c5dba34 0.0", // test name
        "AV:L/AC:H/Au:S/C:N/I:P/A:P/E:POC/RL:U/RC:UR/CDP:ND/TD:N/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(2.4), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8ca168fc 0.0", // test name
        "AV:L/AC:H/Au:S/C:P/I:C/A:C/E:ND/RL:U/RC:ND/CDP:LM/TD:N/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "6b375f1b 6.9", // test name
        "AV:L/AC:H/Au:S/C:P/I:C/A:C/E:U/RL:ND/RC:UC/CDP:H/TD:ND/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "be16fd58 3.3", // test name
        "AV:L/AC:H/Au:S/C:P/I:C/A:N/E:H/RL:TF/RC:C/CDP:ND/TD:M/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "19426625 2.6", // test name
        "AV:L/AC:H/Au:S/C:P/I:C/A:N/E:U/RL:TF/RC:ND/CDP:ND/TD:H/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "2aa4683d 0.0", // test name
        "AV:L/AC:H/Au:S/C:P/I:C/A:P/E:ND/RL:W/RC:C/CDP:L/TD:N/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "bb5b3f4e 3.7", // test name
        "AV:L/AC:H/Au:S/C:P/I:C/A:P/E:U/RL:OF/RC:UR/CDP:ND/TD:H/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "4e673429 3.2", // test name
        "AV:L/AC:H/Au:S/C:P/I:N/A:C/E:F/RL:OF/RC:C/CDP:L/TD:M/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(4.5), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "020e2fdf 0.7", // test name
        "AV:L/AC:H/Au:S/C:P/I:N/A:N/E:H/RL:ND/RC:UR/CDP:L/TD:L/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(1.0), // exp base score
          temporal: Some(Score::from(1.0)), // exp temporal score
          environmental: Some(Score::from(0.7)), // exp environmental score
        }, // exp
      ), (
        "219abb31 3.5", // test name
        "AV:L/AC:H/Au:S/C:P/I:N/A:N/E:ND/RL:TF/RC:UC/CDP:LM/TD:H/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(1.0), // exp base score
          temporal: Some(Score::from(0.8)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "3a2d5b3b 0.6", // test name
        "AV:L/AC:H/Au:S/C:P/I:N/A:P/E:U/RL:U/RC:UR/CDP:N/TD:L/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(2.4), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(0.6)), // exp environmental score
        }, // exp
      ), (
        "20237571 1.2", // test name
        "AV:L/AC:H/Au:S/C:P/I:P/A:N/E:F/RL:ND/RC:ND/CDP:MH/TD:L/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(2.4), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "2582cd69 5.3", // test name
        "AV:L/AC:H/Au:S/C:P/I:P/A:N/E:F/RL:U/RC:UR/CDP:MH/TD:ND/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(2.4), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "e5801148 2.3", // test name
        "AV:L/AC:H/Au:S/C:P/I:P/A:N/E:ND/RL:OF/RC:ND/CDP:L/TD:H/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(2.4), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(2.3)), // exp environmental score
        }, // exp
      ), (
        "32ed9cde 1.2", // test name
        "AV:L/AC:H/Au:S/C:P/I:P/A:N/E:U/RL:OF/RC:UR/CDP:MH/TD:L/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(2.4), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "13b643fe 1.7", // test name
        "AV:L/AC:H/Au:S/C:P/I:P/A:N/E:U/RL:U/RC:C/CDP:L/TD:M/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(2.4), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "37837160 5.5", // test name
        "AV:L/AC:H/Au:S/C:P/I:P/A:P/E:F/RL:U/RC:UR/CDP:LM/TD:H/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "28ecbee6 1.9", // test name
        "AV:L/AC:L/Au:M/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:LM/TD:L/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "a764a243 1.5", // test name
        "AV:L/AC:L/Au:M/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:N/TD:L/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "c0a33ded 6.5", // test name
        "AV:L/AC:L/Au:M/C:C/I:C/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "83f8daad 1.6", // test name
        "AV:L/AC:L/Au:M/C:C/I:C/A:C/E:U/RL:W/RC:C/CDP:LM/TD:L/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "a13ae151 7.4", // test name
        "AV:L/AC:L/Au:M/C:C/I:C/A:N/E:POC/RL:TF/RC:ND/CDP:H/TD:H/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "47e2bb73 7.0", // test name
        "AV:L/AC:L/Au:M/C:C/I:C/A:P/E:H/RL:TF/RC:C/CDP:MH/TD:H/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "8b73ad79 3.9", // test name
        "AV:L/AC:L/Au:M/C:C/I:N/A:C/E:U/RL:TF/RC:C/CDP:N/TD:H/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "f0f0b5cd 1.0", // test name
        "AV:L/AC:L/Au:M/C:C/I:N/A:N/E:POC/RL:ND/RC:UR/CDP:LM/TD:L/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "3837a798 4.1", // test name
        "AV:L/AC:L/Au:M/C:C/I:N/A:N/E:U/RL:U/RC:UC/CDP:L/TD:M/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "dd0b17f0 1.4", // test name
        "AV:L/AC:L/Au:M/C:C/I:N/A:P/E:U/RL:ND/RC:C/CDP:LM/TD:L/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "9fb85d9b 1.7", // test name
        "AV:L/AC:L/Au:M/C:C/I:P/A:C/E:F/RL:TF/RC:ND/CDP:H/TD:L/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "8356fdb0 6.1", // test name
        "AV:L/AC:L/Au:M/C:C/I:P/A:C/E:POC/RL:TF/RC:UC/CDP:LM/TD:ND/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "823c34cb 4.1", // test name
        "AV:L/AC:L/Au:M/C:C/I:P/A:P/E:POC/RL:U/RC:UR/CDP:ND/TD:M/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "150b8509 0.0", // test name
        "AV:L/AC:L/Au:M/C:N/I:C/A:C/E:H/RL:W/RC:UR/CDP:ND/TD:N/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "34cf1a8d 5.3", // test name
        "AV:L/AC:L/Au:M/C:N/I:C/A:N/E:ND/RL:OF/RC:UC/CDP:LM/TD:ND/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "04eddc8a 7.0", // test name
        "AV:L/AC:L/Au:M/C:N/I:C/A:N/E:U/RL:TF/RC:ND/CDP:MH/TD:ND/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "38af6bb8 4.8", // test name
        "AV:L/AC:L/Au:M/C:N/I:C/A:N/E:U/RL:TF/RC:UC/CDP:H/TD:M/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "4c3dbf33 0.0", // test name
        "AV:L/AC:L/Au:M/C:N/I:C/A:P/E:POC/RL:U/RC:ND/CDP:L/TD:N/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "c16db183 4.4", // test name
        "AV:L/AC:L/Au:M/C:N/I:N/A:C/E:H/RL:ND/RC:UC/CDP:H/TD:M/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "9a489b50 5.7", // test name
        "AV:L/AC:L/Au:M/C:N/I:N/A:C/E:U/RL:ND/RC:UR/CDP:L/TD:H/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "27a46cfb 0.8", // test name
        "AV:L/AC:L/Au:M/C:N/I:N/A:N/E:POC/RL:W/RC:UR/CDP:LM/TD:L/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.8)), // exp environmental score
        }, // exp
      ), (
        "cab0f49c 0.0", // test name
        "AV:L/AC:L/Au:M/C:N/I:N/A:P/E:H/RL:OF/RC:ND/CDP:L/TD:N/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d1903ae0 3.8", // test name
        "AV:L/AC:L/Au:M/C:N/I:N/A:P/E:H/RL:OF/RC:UR/CDP:LM/TD:H/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.2)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "d8a5c434 5.2", // test name
        "AV:L/AC:L/Au:M/C:N/I:N/A:P/E:ND/RL:U/RC:UC/CDP:H/TD:H/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.3)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "ed64849f 1.0", // test name
        "AV:L/AC:L/Au:M/C:N/I:N/A:P/E:POC/RL:U/RC:UC/CDP:LM/TD:L/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "250128f5 0.5", // test name
        "AV:L/AC:L/Au:M/C:N/I:N/A:P/E:U/RL:TF/RC:C/CDP:ND/TD:L/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(0.5)), // exp environmental score
        }, // exp
      ), (
        "b3d8e7bb 0.3", // test name
        "AV:L/AC:L/Au:M/C:N/I:N/A:P/E:U/RL:W/RC:UR/CDP:ND/TD:L/CR:L/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(0.3)), // exp environmental score
        }, // exp
      ), (
        "e38386db 4.5", // test name
        "AV:L/AC:L/Au:M/C:N/I:P/A:C/E:POC/RL:U/RC:C/CDP:N/TD:ND/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "e0a13640 2.6", // test name
        "AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:TF/RC:C/CDP:ND/TD:M/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "f118ced5 0.7", // test name
        "AV:L/AC:L/Au:M/C:N/I:P/A:P/E:U/RL:OF/RC:ND/CDP:ND/TD:M/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(0.7)), // exp environmental score
        }, // exp
      ), (
        "1d99a339 1.2", // test name
        "AV:L/AC:L/Au:M/C:P/I:C/A:C/E:POC/RL:TF/RC:UR/CDP:N/TD:L/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "a44e2161 4.8", // test name
        "AV:L/AC:L/Au:M/C:P/I:C/A:P/E:U/RL:TF/RC:UR/CDP:H/TD:M/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "12873707 2.8", // test name
        "AV:L/AC:L/Au:M/C:P/I:N/A:C/E:U/RL:OF/RC:UR/CDP:ND/TD:M/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "7241bedb 2.4", // test name
        "AV:L/AC:L/Au:M/C:P/I:N/A:N/E:POC/RL:OF/RC:ND/CDP:LM/TD:M/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "b844ed34 4.5", // test name
        "AV:L/AC:L/Au:M/C:P/I:N/A:N/E:U/RL:U/RC:C/CDP:LM/TD:ND/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(1.4), // exp base score
          temporal: Some(Score::from(1.2)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "2f82a085 2.6", // test name
        "AV:L/AC:L/Au:M/C:P/I:N/A:P/E:U/RL:W/RC:C/CDP:L/TD:H/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "62b6c840 7.3", // test name
        "AV:L/AC:L/Au:M/C:P/I:P/A:C/E:H/RL:OF/RC:C/CDP:H/TD:ND/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "f9a5e7f0 0.6", // test name
        "AV:L/AC:L/Au:M/C:P/I:P/A:N/E:H/RL:OF/RC:UC/CDP:N/TD:L/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(0.6)), // exp environmental score
        }, // exp
      ), (
        "9bd06214 1.6", // test name
        "AV:L/AC:L/Au:M/C:P/I:P/A:N/E:ND/RL:ND/RC:ND/CDP:H/TD:L/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(2.9), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "343de1a2 2.6", // test name
        "AV:L/AC:L/Au:N/C:C/I:C/A:N/E:F/RL:ND/RC:UC/CDP:ND/TD:M/CR:L/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(2.6)), // exp environmental score
        }, // exp
      ), (
        "24188ffd 5.7", // test name
        "AV:L/AC:L/Au:N/C:C/I:C/A:N/E:ND/RL:U/RC:UC/CDP:L/TD:H/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "d844eb39 0.0", // test name
        "AV:L/AC:L/Au:N/C:C/I:C/A:N/E:U/RL:TF/RC:ND/CDP:N/TD:N/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "c5ae2bc0 8.4", // test name
        "AV:L/AC:L/Au:N/C:C/I:C/A:P/E:ND/RL:W/RC:ND/CDP:H/TD:ND/CR:ND/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "09e80500 5.4", // test name
        "AV:L/AC:L/Au:N/C:C/I:C/A:P/E:POC/RL:OF/RC:UR/CDP:H/TD:M/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "32fa6322 5.5", // test name
        "AV:L/AC:L/Au:N/C:C/I:C/A:P/E:U/RL:TF/RC:C/CDP:N/TD:H/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "b749b42b 4.9", // test name
        "AV:L/AC:L/Au:N/C:C/I:N/A:C/E:F/RL:TF/RC:UC/CDP:LM/TD:M/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "f3d05044 4.2", // test name
        "AV:L/AC:L/Au:N/C:C/I:N/A:N/E:U/RL:U/RC:C/CDP:N/TD:ND/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "f69938ce 0.0", // test name
        "AV:L/AC:L/Au:N/C:C/I:P/A:C/E:U/RL:TF/RC:UC/CDP:MH/TD:N/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9f8327ce 0.0", // test name
        "AV:L/AC:L/Au:N/C:C/I:P/A:P/E:F/RL:ND/RC:C/CDP:L/TD:N/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d4a90096 0.0", // test name
        "AV:L/AC:L/Au:N/C:C/I:P/A:P/E:ND/RL:OF/RC:UC/CDP:ND/TD:N/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "5a110271 0.0", // test name
        "AV:L/AC:L/Au:N/C:N/I:C/A:C/E:U/RL:ND/RC:C/CDP:MH/TD:N/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "2ca82824 5.4", // test name
        "AV:L/AC:L/Au:N/C:N/I:C/A:P/E:F/RL:U/RC:ND/CDP:MH/TD:M/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "27559998 1.3", // test name
        "AV:L/AC:L/Au:N/C:N/I:C/A:P/E:U/RL:W/RC:UC/CDP:N/TD:L/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "c8adcb99 3.7", // test name
        "AV:L/AC:L/Au:N/C:N/I:N/A:P/E:F/RL:ND/RC:UR/CDP:LM/TD:M/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "ca672455 4.6", // test name
        "AV:L/AC:L/Au:N/C:N/I:N/A:P/E:ND/RL:U/RC:UR/CDP:MH/TD:ND/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "84cd79a0 0.7", // test name
        "AV:L/AC:L/Au:N/C:N/I:P/A:C/E:F/RL:ND/RC:UR/CDP:ND/TD:L/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(0.7)), // exp environmental score
        }, // exp
      ), (
        "a265e594 1.7", // test name
        "AV:L/AC:L/Au:N/C:N/I:P/A:N/E:F/RL:W/RC:UC/CDP:ND/TD:H/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "8d44f384 1.0", // test name
        "AV:L/AC:L/Au:N/C:N/I:P/A:P/E:ND/RL:W/RC:UC/CDP:LM/TD:L/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "fc4826ac 0.0", // test name
        "AV:L/AC:L/Au:N/C:P/I:C/A:C/E:POC/RL:U/RC:ND/CDP:LM/TD:N/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9b8cd3d5 6.5", // test name
        "AV:L/AC:L/Au:N/C:P/I:C/A:N/E:H/RL:W/RC:ND/CDP:H/TD:H/CR:L/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "2c8b6d5c 1.7", // test name
        "AV:L/AC:L/Au:N/C:P/I:C/A:N/E:U/RL:ND/RC:C/CDP:MH/TD:L/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "7a297e2c 6.2", // test name
        "AV:L/AC:L/Au:N/C:P/I:C/A:P/E:ND/RL:W/RC:C/CDP:LM/TD:H/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "24032999 0.5", // test name
        "AV:L/AC:L/Au:N/C:P/I:N/A:N/E:H/RL:ND/RC:C/CDP:N/TD:L/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(0.5)), // exp environmental score
        }, // exp
      ), (
        "38912edb 5.2", // test name
        "AV:L/AC:L/Au:N/C:P/I:N/A:N/E:H/RL:W/RC:ND/CDP:MH/TD:ND/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "d0bcd0bf 6.4", // test name
        "AV:L/AC:L/Au:N/C:P/I:N/A:P/E:F/RL:OF/RC:UR/CDP:H/TD:ND/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "89e977d4 1.4", // test name
        "AV:L/AC:L/Au:N/C:P/I:N/A:P/E:H/RL:OF/RC:UC/CDP:MH/TD:L/CR:M/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "6fe46f32 1.9", // test name
        "AV:L/AC:L/Au:N/C:P/I:N/A:P/E:H/RL:W/RC:ND/CDP:N/TD:H/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "a0bb472e 0.0", // test name
        "AV:L/AC:L/Au:N/C:P/I:P/A:C/E:H/RL:TF/RC:C/CDP:H/TD:N/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "758cbb55 1.1", // test name
        "AV:L/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:TF/RC:C/CDP:LM/TD:L/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "ea1d9627 0.0", // test name
        "AV:L/AC:L/Au:N/C:P/I:P/A:N/E:POC/RL:ND/RC:UR/CDP:MH/TD:N/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "c917318c 1.1", // test name
        "AV:L/AC:L/Au:N/C:P/I:P/A:N/E:U/RL:W/RC:UR/CDP:L/TD:L/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "8f496e43 6.0", // test name
        "AV:L/AC:L/Au:N/C:P/I:P/A:N/E:U/RL:W/RC:UR/CDP:MH/TD:ND/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "87fe8f5e 2.0", // test name
        "AV:L/AC:L/Au:N/C:P/I:P/A:P/E:F/RL:TF/RC:UC/CDP:ND/TD:M/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "d10ea3df 6.8", // test name
        "AV:L/AC:L/Au:N/C:P/I:P/A:P/E:ND/RL:OF/RC:C/CDP:H/TD:H/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "76e5820d 6.4", // test name
        "AV:L/AC:L/Au:S/C:C/I:C/A:C/E:ND/RL:ND/RC:UR/CDP:ND/TD:H/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "8c193854 6.8", // test name
        "AV:L/AC:L/Au:S/C:C/I:C/A:N/E:H/RL:ND/RC:ND/CDP:LM/TD:ND/CR:L/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "fae0a598 5.3", // test name
        "AV:L/AC:L/Au:S/C:C/I:C/A:P/E:H/RL:U/RC:C/CDP:LM/TD:M/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "5e2eb7b6 6.8", // test name
        "AV:L/AC:L/Au:S/C:C/I:N/A:C/E:POC/RL:TF/RC:ND/CDP:LM/TD:ND/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "98bc9396 3.2", // test name
        "AV:L/AC:L/Au:S/C:C/I:N/A:C/E:U/RL:ND/RC:ND/CDP:N/TD:H/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(3.2)), // exp environmental score
        }, // exp
      ), (
        "c2184b8d 7.6", // test name
        "AV:L/AC:L/Au:S/C:C/I:P/A:C/E:U/RL:W/RC:UR/CDP:H/TD:ND/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "a6afb74c 6.5", // test name
        "AV:L/AC:L/Au:S/C:C/I:P/A:N/E:F/RL:U/RC:UR/CDP:L/TD:ND/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "2f721fff 4.2", // test name
        "AV:L/AC:L/Au:S/C:C/I:P/A:N/E:H/RL:W/RC:UR/CDP:LM/TD:M/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "21847ffd 0.0", // test name
        "AV:L/AC:L/Au:S/C:C/I:P/A:N/E:U/RL:TF/RC:C/CDP:MH/TD:N/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "cda119c1 5.2", // test name
        "AV:L/AC:L/Au:S/C:C/I:P/A:P/E:H/RL:ND/RC:ND/CDP:MH/TD:M/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "a3c2068c 0.0", // test name
        "AV:L/AC:L/Au:S/C:C/I:P/A:P/E:U/RL:ND/RC:C/CDP:L/TD:N/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "13f3d4ac 5.9", // test name
        "AV:L/AC:L/Au:S/C:N/I:C/A:C/E:POC/RL:W/RC:C/CDP:H/TD:M/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "68b6fe9c 3.3", // test name
        "AV:L/AC:L/Au:S/C:N/I:C/A:P/E:ND/RL:U/RC:UC/CDP:ND/TD:M/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(3.3)), // exp environmental score
        }, // exp
      ), (
        "80ef304e 6.2", // test name
        "AV:L/AC:L/Au:S/C:N/I:N/A:C/E:POC/RL:TF/RC:C/CDP:MH/TD:ND/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "2fa147d2 3.0", // test name
        "AV:L/AC:L/Au:S/C:N/I:N/A:N/E:F/RL:U/RC:UC/CDP:LM/TD:H/CR:ND/IR:H/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "c355e46e 5.0", // test name
        "AV:L/AC:L/Au:S/C:N/I:N/A:N/E:POC/RL:U/RC:UC/CDP:H/TD:ND/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "2feef482 4.5", // test name
        "AV:L/AC:L/Au:S/C:N/I:P/A:C/E:F/RL:W/RC:UR/CDP:N/TD:ND/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "5104f5fb 4.4", // test name
        "AV:L/AC:L/Au:S/C:N/I:P/A:C/E:H/RL:OF/RC:C/CDP:ND/TD:M/CR:L/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "d9d2fe76 0.0", // test name
        "AV:L/AC:L/Au:S/C:N/I:P/A:C/E:POC/RL:OF/RC:C/CDP:L/TD:N/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "c2d7d363 6.6", // test name
        "AV:L/AC:L/Au:S/C:N/I:P/A:C/E:POC/RL:OF/RC:ND/CDP:MH/TD:H/CR:M/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "0258716b 0.0", // test name
        "AV:L/AC:L/Au:S/C:N/I:P/A:C/E:U/RL:ND/RC:C/CDP:N/TD:N/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "c588c4bb 6.8", // test name
        "AV:L/AC:L/Au:S/C:P/I:C/A:P/E:F/RL:U/RC:UC/CDP:MH/TD:ND/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "f6346fda 5.2", // test name
        "AV:L/AC:L/Au:S/C:P/I:C/A:P/E:H/RL:OF/RC:UR/CDP:MH/TD:M/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "674c07bc 6.9", // test name
        "AV:L/AC:L/Au:S/C:P/I:C/A:P/E:ND/RL:ND/RC:UR/CDP:H/TD:ND/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "07e821f9 1.9", // test name
        "AV:L/AC:L/Au:S/C:P/I:N/A:C/E:H/RL:TF/RC:ND/CDP:MH/TD:L/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "5f3fb459 0.0", // test name
        "AV:L/AC:L/Au:S/C:P/I:N/A:C/E:ND/RL:ND/RC:ND/CDP:LM/TD:N/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "f35fa306 3.6", // test name
        "AV:L/AC:L/Au:S/C:P/I:N/A:C/E:U/RL:W/RC:UC/CDP:N/TD:ND/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.2), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "94e5baf5 4.0", // test name
        "AV:L/AC:L/Au:S/C:P/I:N/A:N/E:F/RL:TF/RC:ND/CDP:LM/TD:H/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.5)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "675be3b5 0.0", // test name
        "AV:L/AC:L/Au:S/C:P/I:N/A:N/E:POC/RL:ND/RC:UR/CDP:MH/TD:N/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "08498b9e 4.2", // test name
        "AV:L/AC:L/Au:S/C:P/I:N/A:N/E:POC/RL:TF/RC:UC/CDP:H/TD:M/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.2)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "2f77f0ed 5.2", // test name
        "AV:L/AC:L/Au:S/C:P/I:N/A:N/E:U/RL:OF/RC:UC/CDP:H/TD:H/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "2692890d 4.3", // test name
        "AV:L/AC:L/Au:S/C:P/I:P/A:C/E:F/RL:TF/RC:C/CDP:N/TD:M/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "d94577f2 5.4", // test name
        "AV:L/AC:L/Au:S/C:P/I:P/A:C/E:ND/RL:OF/RC:C/CDP:ND/TD:ND/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "01f7e2cd 4.5", // test name
        "AV:L/AC:L/Au:S/C:P/I:P/A:C/E:ND/RL:U/RC:ND/CDP:ND/TD:H/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "3498cbf3 7.8", // test name
        "AV:L/AC:L/Au:S/C:P/I:P/A:C/E:ND/RL:U/RC:UR/CDP:H/TD:ND/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "bb5b0169 2.1", // test name
        "AV:L/AC:L/Au:S/C:P/I:P/A:N/E:H/RL:OF/RC:C/CDP:ND/TD:H/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "6afe5d33 0.0", // test name
        "AV:L/AC:L/Au:S/C:P/I:P/A:N/E:POC/RL:TF/RC:UC/CDP:L/TD:N/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d99ac94d 0.0", // test name
        "AV:L/AC:L/Au:S/C:P/I:P/A:P/E:H/RL:ND/RC:C/CDP:ND/TD:N/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8342239b 1.7", // test name
        "AV:L/AC:L/Au:S/C:P/I:P/A:P/E:H/RL:OF/RC:UC/CDP:H/TD:L/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "cb8fe5af 0.0", // test name
        "AV:L/AC:L/Au:S/C:P/I:P/A:P/E:U/RL:W/RC:UR/CDP:LM/TD:N/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8c2fc6dd 1.4", // test name
        "AV:L/AC:M/Au:M/C:C/I:C/A:C/E:F/RL:U/RC:UC/CDP:N/TD:L/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "70f4cbee 7.2", // test name
        "AV:L/AC:M/Au:M/C:C/I:C/A:C/E:H/RL:W/RC:ND/CDP:LM/TD:H/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "2e3724a1 1.7", // test name
        "AV:L/AC:M/Au:M/C:C/I:C/A:C/E:POC/RL:W/RC:ND/CDP:LM/TD:L/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "96bd8b05 0.0", // test name
        "AV:L/AC:M/Au:M/C:C/I:C/A:P/E:POC/RL:TF/RC:C/CDP:ND/TD:N/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "7fa749fb 4.1", // test name
        "AV:L/AC:M/Au:M/C:C/I:N/A:C/E:ND/RL:OF/RC:UR/CDP:ND/TD:ND/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "a371a432 5.4", // test name
        "AV:L/AC:M/Au:M/C:C/I:N/A:C/E:ND/RL:TF/RC:UR/CDP:L/TD:H/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "9d381a08 6.3", // test name
        "AV:L/AC:M/Au:M/C:C/I:N/A:C/E:POC/RL:W/RC:UR/CDP:H/TD:ND/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "ac7e3147 1.9", // test name
        "AV:L/AC:M/Au:M/C:C/I:P/A:C/E:H/RL:TF/RC:ND/CDP:MH/TD:L/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "a146511a 6.7", // test name
        "AV:L/AC:M/Au:M/C:C/I:P/A:C/E:U/RL:TF/RC:ND/CDP:MH/TD:ND/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "08838128 4.6", // test name
        "AV:L/AC:M/Au:M/C:C/I:P/A:P/E:H/RL:TF/RC:C/CDP:L/TD:M/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "5ff48f49 6.0", // test name
        "AV:L/AC:M/Au:M/C:N/I:C/A:C/E:ND/RL:ND/RC:UR/CDP:ND/TD:ND/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "94051b1c 1.7", // test name
        "AV:L/AC:M/Au:M/C:N/I:C/A:C/E:U/RL:TF/RC:ND/CDP:MH/TD:L/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "4a13d50e 6.2", // test name
        "AV:L/AC:M/Au:M/C:N/I:C/A:N/E:F/RL:W/RC:C/CDP:MH/TD:ND/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "da2327f5 6.4", // test name
        "AV:L/AC:M/Au:M/C:N/I:C/A:N/E:POC/RL:W/RC:UC/CDP:LM/TD:H/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "d5f0cba7 1.5", // test name
        "AV:L/AC:M/Au:M/C:N/I:C/A:P/E:H/RL:W/RC:C/CDP:H/TD:L/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "469307e5 0.0", // test name
        "AV:L/AC:M/Au:M/C:N/I:C/A:P/E:POC/RL:ND/RC:C/CDP:ND/TD:N/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "43498776 0.0", // test name
        "AV:L/AC:M/Au:M/C:N/I:C/A:P/E:POC/RL:TF/RC:UR/CDP:L/TD:N/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9dc68585 1.2", // test name
        "AV:L/AC:M/Au:M/C:N/I:N/A:P/E:F/RL:ND/RC:C/CDP:L/TD:ND/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(1.3), // exp base score
          temporal: Some(Score::from(1.2)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "97fb78b2 2.4", // test name
        "AV:L/AC:M/Au:M/C:N/I:N/A:P/E:H/RL:OF/RC:C/CDP:LM/TD:M/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(1.3), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "b6483cab 0.0", // test name
        "AV:L/AC:M/Au:M/C:N/I:N/A:P/E:U/RL:U/RC:C/CDP:H/TD:N/CR:M/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(1.3), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "140b07ea 5.7", // test name
        "AV:L/AC:M/Au:M/C:N/I:P/A:C/E:F/RL:U/RC:C/CDP:MH/TD:H/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "a5e79564 0.0", // test name
        "AV:L/AC:M/Au:M/C:N/I:P/A:C/E:POC/RL:OF/RC:UR/CDP:MH/TD:N/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d3a94de3 0.0", // test name
        "AV:L/AC:M/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:UC/CDP:H/TD:N/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "29ed8b96 1.6", // test name
        "AV:L/AC:M/Au:M/C:N/I:P/A:P/E:ND/RL:TF/RC:UC/CDP:ND/TD:H/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "5135ffc5 5.6", // test name
        "AV:L/AC:M/Au:M/C:N/I:P/A:P/E:U/RL:TF/RC:ND/CDP:MH/TD:ND/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.1)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "6180ae65 0.0", // test name
        "AV:L/AC:M/Au:M/C:N/I:P/A:P/E:U/RL:W/RC:C/CDP:LM/TD:N/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "38ed210b 1.7", // test name
        "AV:L/AC:M/Au:M/C:P/I:C/A:C/E:F/RL:W/RC:UC/CDP:MH/TD:L/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "a3da822a 4.6", // test name
        "AV:L/AC:M/Au:M/C:P/I:C/A:C/E:U/RL:U/RC:UC/CDP:N/TD:ND/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "bfd53eb4 7.2", // test name
        "AV:L/AC:M/Au:M/C:P/I:C/A:N/E:F/RL:TF/RC:ND/CDP:MH/TD:H/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "ac65e2c7 5.9", // test name
        "AV:L/AC:M/Au:M/C:P/I:C/A:P/E:ND/RL:OF/RC:ND/CDP:LM/TD:H/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "66135e6f 1.4", // test name
        "AV:L/AC:M/Au:M/C:P/I:N/A:C/E:F/RL:ND/RC:C/CDP:LM/TD:L/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(4.8), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "65ac0412 1.0", // test name
        "AV:L/AC:M/Au:M/C:P/I:N/A:N/E:F/RL:TF/RC:UC/CDP:N/TD:H/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(1.3), // exp base score
          temporal: Some(Score::from(1.0)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "bf01a45b 0.9", // test name
        "AV:L/AC:M/Au:M/C:P/I:N/A:N/E:U/RL:TF/RC:UC/CDP:LM/TD:L/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(1.3), // exp base score
          temporal: Some(Score::from(0.9)), // exp temporal score
          environmental: Some(Score::from(0.9)), // exp environmental score
        }, // exp
      ), (
        "48b5d570 5.4", // test name
        "AV:L/AC:M/Au:M/C:P/I:P/A:N/E:F/RL:W/RC:UR/CDP:MH/TD:H/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(2.7), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "c3567fbc 0.7", // test name
        "AV:L/AC:M/Au:M/C:P/I:P/A:P/E:H/RL:U/RC:ND/CDP:N/TD:L/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(3.8), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(0.7)), // exp environmental score
        }, // exp
      ), (
        "c2a828dc 7.7", // test name
        "AV:L/AC:M/Au:N/C:C/I:C/A:C/E:POC/RL:ND/RC:C/CDP:MH/TD:ND/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "f84ef08f 6.9", // test name
        "AV:L/AC:M/Au:N/C:C/I:C/A:N/E:H/RL:ND/RC:C/CDP:N/TD:ND/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "5bc5f9cf 1.5", // test name
        "AV:L/AC:M/Au:N/C:C/I:C/A:N/E:POC/RL:ND/RC:UR/CDP:L/TD:L/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "8399fa06 6.2", // test name
        "AV:L/AC:M/Au:N/C:C/I:C/A:P/E:F/RL:W/RC:ND/CDP:N/TD:ND/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "bca971ff 8.0", // test name
        "AV:L/AC:M/Au:N/C:C/I:C/A:P/E:ND/RL:OF/RC:C/CDP:H/TD:H/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(8.0)), // exp environmental score
        }, // exp
      ), (
        "0b0aa7ff 5.6", // test name
        "AV:L/AC:M/Au:N/C:C/I:C/A:P/E:POC/RL:OF/RC:UR/CDP:H/TD:M/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "22f6b18e 1.1", // test name
        "AV:L/AC:M/Au:N/C:C/I:N/A:N/E:H/RL:TF/RC:UR/CDP:LM/TD:L/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "3620ccbc 0.0", // test name
        "AV:L/AC:M/Au:N/C:C/I:N/A:N/E:U/RL:ND/RC:ND/CDP:H/TD:N/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "7e2fe3bd 5.0", // test name
        "AV:L/AC:M/Au:N/C:C/I:N/A:N/E:U/RL:TF/RC:ND/CDP:MH/TD:ND/CR:L/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "74ccd39b 4.8", // test name
        "AV:L/AC:M/Au:N/C:C/I:N/A:P/E:ND/RL:U/RC:UC/CDP:N/TD:ND/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "b3100d55 1.2", // test name
        "AV:L/AC:M/Au:N/C:C/I:N/A:P/E:POC/RL:ND/RC:UC/CDP:L/TD:L/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "e36ca553 6.9", // test name
        "AV:L/AC:M/Au:N/C:C/I:N/A:P/E:U/RL:W/RC:UR/CDP:H/TD:H/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "eabbb3b2 2.0", // test name
        "AV:L/AC:M/Au:N/C:C/I:P/A:C/E:ND/RL:TF/RC:ND/CDP:H/TD:L/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "ac349869 4.9", // test name
        "AV:L/AC:M/Au:N/C:C/I:P/A:P/E:F/RL:U/RC:ND/CDP:ND/TD:M/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "2ac35016 1.7", // test name
        "AV:L/AC:M/Au:N/C:C/I:P/A:P/E:H/RL:U/RC:UR/CDP:MH/TD:L/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "37fd0d97 8.4", // test name
        "AV:L/AC:M/Au:N/C:C/I:P/A:P/E:ND/RL:ND/RC:ND/CDP:H/TD:ND/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "1bc50346 1.9", // test name
        "AV:L/AC:M/Au:N/C:C/I:P/A:P/E:POC/RL:OF/RC:UR/CDP:H/TD:L/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "c94138ee 0.0", // test name
        "AV:L/AC:M/Au:N/C:C/I:P/A:P/E:U/RL:U/RC:UC/CDP:LM/TD:N/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "e1a7e38b 6.0", // test name
        "AV:L/AC:M/Au:N/C:N/I:C/A:N/E:POC/RL:U/RC:ND/CDP:H/TD:H/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "1cadaba0 1.8", // test name
        "AV:L/AC:M/Au:N/C:N/I:C/A:N/E:POC/RL:W/RC:UR/CDP:ND/TD:ND/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "9196b23a 4.6", // test name
        "AV:L/AC:M/Au:N/C:N/I:C/A:P/E:H/RL:W/RC:UC/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.6)), // exp temporal score
          environmental: None, // exp environmental score
        }, // exp
      ), (
        "723ae5bc 1.6", // test name
        "AV:L/AC:M/Au:N/C:N/I:C/A:P/E:POC/RL:W/RC:UR/CDP:MH/TD:L/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "df9fb1b2 4.6", // test name
        "AV:L/AC:M/Au:N/C:N/I:N/A:C/E:F/RL:ND/RC:ND/CDP:H/TD:M/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "e61fbdb5 7.7", // test name
        "AV:L/AC:M/Au:N/C:N/I:N/A:C/E:ND/RL:TF/RC:ND/CDP:MH/TD:ND/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "97914325 1.4", // test name
        "AV:L/AC:M/Au:N/C:N/I:N/A:C/E:ND/RL:TF/RC:UC/CDP:N/TD:M/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "e30a3cda 1.1", // test name
        "AV:L/AC:M/Au:N/C:N/I:N/A:C/E:POC/RL:ND/RC:ND/CDP:N/TD:L/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "8d32eb00 7.8", // test name
        "AV:L/AC:M/Au:N/C:N/I:P/A:C/E:H/RL:OF/RC:UR/CDP:H/TD:H/CR:ND/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "b38b8802 5.0", // test name
        "AV:L/AC:M/Au:N/C:N/I:P/A:C/E:U/RL:W/RC:UR/CDP:MH/TD:M/CR:M/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "bc8f42d3 1.7", // test name
        "AV:L/AC:M/Au:N/C:N/I:P/A:N/E:H/RL:ND/RC:UR/CDP:L/TD:H/CR:L/IR:L/AR:H", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.8)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "68b0b58a 0.0", // test name
        "AV:L/AC:M/Au:N/C:N/I:P/A:P/E:H/RL:W/RC:UR/CDP:MH/TD:N/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "519ac220 6.4", // test name
        "AV:L/AC:M/Au:N/C:N/I:P/A:P/E:ND/RL:U/RC:C/CDP:MH/TD:ND/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "d8e51dc2 1.3", // test name
        "AV:L/AC:M/Au:N/C:P/I:C/A:C/E:POC/RL:OF/RC:UC/CDP:L/TD:L/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "1a597fc6 7.4", // test name
        "AV:L/AC:M/Au:N/C:P/I:C/A:N/E:H/RL:OF/RC:UR/CDP:H/TD:H/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "33169e11 6.5", // test name
        "AV:L/AC:M/Au:N/C:P/I:C/A:P/E:U/RL:U/RC:C/CDP:LM/TD:H/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "4520e7d0 5.3", // test name
        "AV:L/AC:M/Au:N/C:P/I:C/A:P/E:U/RL:U/RC:UR/CDP:L/TD:ND/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "5385bfc6 6.5", // test name
        "AV:L/AC:M/Au:N/C:P/I:N/A:C/E:U/RL:ND/RC:UR/CDP:H/TD:ND/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(6.5)), // exp environmental score
        }, // exp
      ), (
        "533d3008 5.7", // test name
        "AV:L/AC:M/Au:N/C:P/I:N/A:C/E:U/RL:W/RC:UR/CDP:LM/TD:H/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "2d96898c 0.0", // test name
        "AV:L/AC:M/Au:N/C:P/I:N/A:N/E:H/RL:ND/RC:UC/CDP:LM/TD:N/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "479212af 0.0", // test name
        "AV:L/AC:M/Au:N/C:P/I:N/A:N/E:H/RL:U/RC:C/CDP:LM/TD:N/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(1.9), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "be48b37e 1.7", // test name
        "AV:L/AC:M/Au:N/C:P/I:N/A:P/E:H/RL:ND/RC:ND/CDP:H/TD:L/CR:M/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "44b68758 0.0", // test name
        "AV:L/AC:M/Au:N/C:P/I:N/A:P/E:POC/RL:TF/RC:ND/CDP:N/TD:N/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "336a95c3 2.0", // test name
        "AV:L/AC:M/Au:N/C:P/I:P/A:C/E:H/RL:ND/RC:UR/CDP:MH/TD:L/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "dc596433 0.0", // test name
        "AV:L/AC:M/Au:N/C:P/I:P/A:C/E:ND/RL:OF/RC:ND/CDP:ND/TD:N/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "e25fb173 3.6", // test name
        "AV:L/AC:M/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:UR/CDP:N/TD:M/CR:ND/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.9), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "24636955 4.4", // test name
        "AV:L/AC:M/Au:N/C:P/I:P/A:P/E:U/RL:U/RC:ND/CDP:LM/TD:M/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "293da2bc 5.7", // test name
        "AV:L/AC:M/Au:S/C:C/I:C/A:C/E:H/RL:TF/RC:ND/CDP:MH/TD:M/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "c81f1e0e 6.2", // test name
        "AV:L/AC:M/Au:S/C:C/I:C/A:C/E:ND/RL:W/RC:ND/CDP:N/TD:ND/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "c8873511 0.0", // test name
        "AV:L/AC:M/Au:S/C:C/I:C/A:C/E:U/RL:TF/RC:UC/CDP:ND/TD:N/CR:L/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "3bf11cea 4.4", // test name
        "AV:L/AC:M/Au:S/C:C/I:C/A:N/E:POC/RL:ND/RC:C/CDP:ND/TD:M/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "746d06d9 0.0", // test name
        "AV:L/AC:M/Au:S/C:C/I:N/A:N/E:U/RL:OF/RC:UR/CDP:MH/TD:N/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "4940feae 0.9", // test name
        "AV:L/AC:M/Au:S/C:C/I:N/A:P/E:U/RL:U/RC:ND/CDP:L/TD:L/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(0.9)), // exp environmental score
        }, // exp
      ), (
        "cd86d2b7 5.5", // test name
        "AV:L/AC:M/Au:S/C:C/I:P/A:C/E:F/RL:ND/RC:UR/CDP:ND/TD:ND/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "56dda9e8 4.0", // test name
        "AV:L/AC:M/Au:S/C:C/I:P/A:C/E:F/RL:W/RC:UR/CDP:N/TD:M/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "11db858b 6.3", // test name
        "AV:L/AC:M/Au:S/C:C/I:P/A:N/E:H/RL:ND/RC:ND/CDP:LM/TD:ND/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "79aaab55 0.0", // test name
        "AV:L/AC:M/Au:S/C:C/I:P/A:P/E:ND/RL:ND/RC:UC/CDP:H/TD:N/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "72776578 7.3", // test name
        "AV:L/AC:M/Au:S/C:N/I:C/A:C/E:F/RL:U/RC:UR/CDP:MH/TD:ND/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.0), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "22df987b 1.7", // test name
        "AV:L/AC:M/Au:S/C:N/I:C/A:N/E:POC/RL:ND/RC:ND/CDP:N/TD:H/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "ef9cce92 6.3", // test name
        "AV:L/AC:M/Au:S/C:N/I:C/A:P/E:F/RL:W/RC:C/CDP:L/TD:H/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "4cb19f7c 0.0", // test name
        "AV:L/AC:M/Au:S/C:N/I:C/A:P/E:ND/RL:OF/RC:UC/CDP:L/TD:N/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d5b088a5 7.2", // test name
        "AV:L/AC:M/Au:S/C:N/I:C/A:P/E:POC/RL:ND/RC:UC/CDP:H/TD:ND/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "501ca4fb 3.0", // test name
        "AV:L/AC:M/Au:S/C:N/I:N/A:C/E:F/RL:TF/RC:UC/CDP:L/TD:M/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.4), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "9c0022dd 0.0", // test name
        "AV:L/AC:M/Au:S/C:N/I:N/A:N/E:F/RL:W/RC:ND/CDP:ND/TD:L/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9e11825d 0.0", // test name
        "AV:L/AC:M/Au:S/C:N/I:N/A:N/E:H/RL:OF/RC:UR/CDP:N/TD:M/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "de1d7f66 1.4", // test name
        "AV:L/AC:M/Au:S/C:N/I:N/A:P/E:F/RL:ND/RC:C/CDP:H/TD:L/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(1.5), // exp base score
          temporal: Some(Score::from(1.4)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "a694fd9a 1.6", // test name
        "AV:L/AC:M/Au:S/C:N/I:P/A:C/E:H/RL:OF/RC:UR/CDP:MH/TD:L/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "24e4739e 1.6", // test name
        "AV:L/AC:M/Au:S/C:N/I:P/A:C/E:U/RL:U/RC:C/CDP:MH/TD:L/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "e0a4f94d 0.9", // test name
        "AV:L/AC:M/Au:S/C:N/I:P/A:N/E:ND/RL:TF/RC:UC/CDP:N/TD:M/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(1.5), // exp base score
          temporal: Some(Score::from(1.2)), // exp temporal score
          environmental: Some(Score::from(0.9)), // exp environmental score
        }, // exp
      ), (
        "0bea0c0b 1.9", // test name
        "AV:L/AC:M/Au:S/C:N/I:P/A:P/E:ND/RL:TF/RC:UR/CDP:ND/TD:ND/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(3.0), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "831a4479 1.7", // test name
        "AV:L/AC:M/Au:S/C:N/I:P/A:P/E:U/RL:TF/RC:ND/CDP:ND/TD:M/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(3.0), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "093728eb 6.1", // test name
        "AV:L/AC:M/Au:S/C:P/I:C/A:N/E:ND/RL:W/RC:C/CDP:H/TD:M/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "ff8fdf09 7.2", // test name
        "AV:L/AC:M/Au:S/C:P/I:C/A:P/E:F/RL:TF/RC:UR/CDP:MH/TD:H/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "f1f31947 0.0", // test name
        "AV:L/AC:M/Au:S/C:P/I:C/A:P/E:POC/RL:U/RC:ND/CDP:ND/TD:N/CR:L/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "73a98acb 1.9", // test name
        "AV:L/AC:M/Au:S/C:P/I:N/A:C/E:H/RL:W/RC:UR/CDP:H/TD:L/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "08f60166 2.8", // test name
        "AV:L/AC:M/Au:S/C:P/I:N/A:N/E:F/RL:OF/RC:UC/CDP:LM/TD:M/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(1.5), // exp base score
          temporal: Some(Score::from(1.1)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "c6920ce7 6.0", // test name
        "AV:L/AC:M/Au:S/C:P/I:N/A:P/E:ND/RL:TF/RC:ND/CDP:H/TD:H/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(3.0), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "e114533d 5.4", // test name
        "AV:L/AC:M/Au:S/C:P/I:P/A:C/E:F/RL:W/RC:ND/CDP:LM/TD:H/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "09660f19 0.0", // test name
        "AV:L/AC:M/Au:S/C:P/I:P/A:C/E:ND/RL:W/RC:UR/CDP:H/TD:N/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8e3a5c55 0.0", // test name
        "AV:L/AC:M/Au:S/C:P/I:P/A:N/E:F/RL:OF/RC:UC/CDP:N/TD:N/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(3.0), // exp base score
          temporal: Some(Score::from(2.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "4a98c8dc 4.0", // test name
        "AV:L/AC:M/Au:S/C:P/I:P/A:N/E:F/RL:U/RC:UR/CDP:L/TD:H/CR:ND/IR:H/AR:H", // vec
        Scores {
          base: Score::from(3.0), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "6c51dc9b 1.5", // test name
        "AV:L/AC:M/Au:S/C:P/I:P/A:P/E:ND/RL:U/RC:ND/CDP:MH/TD:L/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "d2eb2f9c 0.0", // test name
        "AV:L/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:C/CDP:H/TD:N/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "69d43d1d 3.7", // test name
        "AV:L/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:ND/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(3.7)), // exp environmental score
        }, // exp
      ), (
        "b6defe2b 0.0", // test name
        "AV:L/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:U/RC:UC/CDP:ND/TD:N/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(4.1), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "1c2ab02f 1.5", // test name
        "AV:N/AC:H/Au:M/C:C/I:C/A:C/E:ND/RL:TF/RC:UR/CDP:ND/TD:L/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "51e918f7 4.5", // test name
        "AV:N/AC:H/Au:M/C:C/I:C/A:C/E:POC/RL:W/RC:UR/CDP:L/TD:M/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "b2828ff0 5.0", // test name
        "AV:N/AC:H/Au:M/C:C/I:C/A:P/E:U/RL:U/RC:C/CDP:ND/TD:H/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "cd438dde 7.1", // test name
        "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:ND/RL:TF/RC:UR/CDP:LM/TD:H/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "8af58d09 3.4", // test name
        "AV:N/AC:H/Au:M/C:C/I:N/A:N/E:H/RL:TF/RC:UR/CDP:L/TD:M/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(3.4)), // exp environmental score
        }, // exp
      ), (
        "9f4974a4 0.0", // test name
        "AV:N/AC:H/Au:M/C:C/I:N/A:N/E:POC/RL:W/RC:C/CDP:H/TD:N/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "30a9453e 6.6", // test name
        "AV:N/AC:H/Au:M/C:C/I:N/A:N/E:U/RL:TF/RC:C/CDP:LM/TD:H/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "247a7074 6.1", // test name
        "AV:N/AC:H/Au:M/C:C/I:P/A:C/E:F/RL:U/RC:C/CDP:N/TD:H/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "5b9f41f1 5.3", // test name
        "AV:N/AC:H/Au:M/C:C/I:P/A:C/E:H/RL:ND/RC:ND/CDP:L/TD:M/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "08134b6d 0.0", // test name
        "AV:N/AC:H/Au:M/C:N/I:C/A:C/E:F/RL:W/RC:ND/CDP:N/TD:N/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "416f491c 0.0", // test name
        "AV:N/AC:H/Au:M/C:N/I:C/A:C/E:POC/RL:W/RC:ND/CDP:LM/TD:N/CR:L/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.2), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "35f04341 0.0", // test name
        "AV:N/AC:H/Au:M/C:N/I:C/A:N/E:U/RL:OF/RC:ND/CDP:L/TD:N/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "a793f8fd 5.0", // test name
        "AV:N/AC:H/Au:M/C:N/I:C/A:N/E:U/RL:TF/RC:ND/CDP:LM/TD:M/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.5)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "4b8f0ba4 6.6", // test name
        "AV:N/AC:H/Au:M/C:N/I:N/A:C/E:F/RL:U/RC:ND/CDP:MH/TD:ND/CR:L/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "6b17fd97 1.1", // test name
        "AV:N/AC:H/Au:M/C:N/I:N/A:C/E:H/RL:TF/RC:UR/CDP:LM/TD:L/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "5ce712b2 0.0", // test name
        "AV:N/AC:H/Au:M/C:N/I:N/A:N/E:ND/RL:OF/RC:UR/CDP:H/TD:N/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "7e880201 0.0", // test name
        "AV:N/AC:H/Au:M/C:N/I:N/A:N/E:ND/RL:U/RC:ND/CDP:ND/TD:H/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "42937edf 4.0", // test name
        "AV:N/AC:H/Au:M/C:N/I:N/A:P/E:H/RL:U/RC:UC/CDP:H/TD:M/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.5)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "8980908e 0.6", // test name
        "AV:N/AC:H/Au:M/C:N/I:N/A:P/E:ND/RL:TF/RC:ND/CDP:L/TD:L/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.5)), // exp temporal score
          environmental: Some(Score::from(0.6)), // exp environmental score
        }, // exp
      ), (
        "65cf6b62 5.5", // test name
        "AV:N/AC:H/Au:M/C:N/I:P/A:C/E:ND/RL:W/RC:ND/CDP:L/TD:H/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "62f01c1c 1.4", // test name
        "AV:N/AC:H/Au:M/C:N/I:P/A:C/E:U/RL:U/RC:UC/CDP:MH/TD:L/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "14bf34ad 5.3", // test name
        "AV:N/AC:H/Au:M/C:N/I:P/A:P/E:F/RL:U/RC:UC/CDP:MH/TD:ND/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "5c704628 1.4", // test name
        "AV:N/AC:H/Au:M/C:N/I:P/A:P/E:POC/RL:W/RC:UC/CDP:ND/TD:M/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "28d4bd83 0.0", // test name
        "AV:N/AC:H/Au:M/C:P/I:C/A:N/E:ND/RL:TF/RC:ND/CDP:N/TD:N/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "502ff5ff 4.7", // test name
        "AV:N/AC:H/Au:M/C:P/I:C/A:N/E:POC/RL:U/RC:ND/CDP:LM/TD:M/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "54d6207b 5.8", // test name
        "AV:N/AC:H/Au:M/C:P/I:C/A:N/E:U/RL:OF/RC:UR/CDP:LM/TD:ND/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "21962c22 6.4", // test name
        "AV:N/AC:H/Au:M/C:P/I:N/A:C/E:POC/RL:OF/RC:ND/CDP:H/TD:H/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "6bcd206a 4.8", // test name
        "AV:N/AC:H/Au:M/C:P/I:N/A:C/E:POC/RL:OF/RC:UR/CDP:LM/TD:H/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.3), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "b89687fb 1.2", // test name
        "AV:N/AC:H/Au:M/C:P/I:N/A:N/E:F/RL:ND/RC:ND/CDP:LM/TD:L/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.6)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "50ee1d57 1.1", // test name
        "AV:N/AC:H/Au:M/C:P/I:N/A:N/E:H/RL:W/RC:UC/CDP:N/TD:M/CR:M/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.5)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "945d1eba 0.0", // test name
        "AV:N/AC:H/Au:M/C:P/I:N/A:N/E:ND/RL:TF/RC:C/CDP:LM/TD:N/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(1.7), // exp base score
          temporal: Some(Score::from(1.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "bd536703 0.0", // test name
        "AV:N/AC:H/Au:M/C:P/I:N/A:P/E:H/RL:U/RC:ND/CDP:MH/TD:N/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "03a8dd38 1.1", // test name
        "AV:N/AC:H/Au:M/C:P/I:P/A:C/E:POC/RL:TF/RC:UR/CDP:ND/TD:L/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(1.1)), // exp environmental score
        }, // exp
      ), (
        "a0fbdc48 4.3", // test name
        "AV:N/AC:H/Au:M/C:P/I:P/A:N/E:H/RL:TF/RC:UR/CDP:LM/TD:M/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "e0dfb134 4.1", // test name
        "AV:N/AC:H/Au:M/C:P/I:P/A:N/E:H/RL:U/RC:UC/CDP:ND/TD:ND/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(4.1)), // exp environmental score
        }, // exp
      ), (
        "496169dc 6.4", // test name
        "AV:N/AC:H/Au:M/C:P/I:P/A:N/E:ND/RL:W/RC:UC/CDP:H/TD:H/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(3.2), // exp base score
          temporal: Some(Score::from(2.7)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "ca6cbda2 6.7", // test name
        "AV:N/AC:H/Au:M/C:P/I:P/A:P/E:F/RL:ND/RC:UR/CDP:H/TD:ND/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "23bc5e70 1.6", // test name
        "AV:N/AC:H/Au:M/C:P/I:P/A:P/E:H/RL:ND/RC:ND/CDP:LM/TD:L/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "94c5fbb5 4.7", // test name
        "AV:N/AC:H/Au:M/C:P/I:P/A:P/E:H/RL:OF/RC:ND/CDP:MH/TD:M/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "4a5387b4 2.0", // test name
        "AV:N/AC:H/Au:N/C:C/I:C/A:C/E:ND/RL:TF/RC:ND/CDP:MH/TD:L/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.6), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "25331c1e 0.0", // test name
        "AV:N/AC:H/Au:N/C:C/I:C/A:P/E:ND/RL:OF/RC:UR/CDP:N/TD:N/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "bd3fe5af 1.7", // test name
        "AV:N/AC:H/Au:N/C:C/I:N/A:C/E:H/RL:U/RC:UC/CDP:ND/TD:L/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "06dd4a96 0.0", // test name
        "AV:N/AC:H/Au:N/C:C/I:N/A:N/E:F/RL:OF/RC:UR/CDP:H/TD:N/CR:L/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "705d3493 6.6", // test name
        "AV:N/AC:H/Au:N/C:C/I:N/A:N/E:POC/RL:W/RC:UR/CDP:MH/TD:H/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "4316b5c0 1.8", // test name
        "AV:N/AC:H/Au:N/C:C/I:N/A:P/E:ND/RL:ND/RC:UC/CDP:H/TD:L/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "77716b7c 5.4", // test name
        "AV:N/AC:H/Au:N/C:C/I:N/A:P/E:POC/RL:ND/RC:UC/CDP:L/TD:ND/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "a5e95e1c 4.4", // test name
        "AV:N/AC:H/Au:N/C:C/I:N/A:P/E:U/RL:U/RC:UC/CDP:L/TD:ND/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(4.4)), // exp environmental score
        }, // exp
      ), (
        "c25372d5 3.5", // test name
        "AV:N/AC:H/Au:N/C:C/I:P/A:C/E:POC/RL:W/RC:C/CDP:N/TD:M/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "3c856182 6.8", // test name
        "AV:N/AC:H/Au:N/C:C/I:P/A:N/E:ND/RL:TF/RC:ND/CDP:N/TD:H/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "70b3a452 0.0", // test name
        "AV:N/AC:H/Au:N/C:C/I:P/A:P/E:F/RL:OF/RC:UC/CDP:L/TD:N/CR:ND/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "a0680e67 0.0", // test name
        "AV:N/AC:H/Au:N/C:C/I:P/A:P/E:POC/RL:W/RC:C/CDP:ND/TD:N/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "f4289f6f 3.6", // test name
        "AV:N/AC:H/Au:N/C:C/I:P/A:P/E:U/RL:U/RC:UC/CDP:ND/TD:M/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "3a0525fa 5.2", // test name
        "AV:N/AC:H/Au:N/C:C/I:P/A:P/E:U/RL:W/RC:C/CDP:H/TD:M/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "aa0b3cce 4.2", // test name
        "AV:N/AC:H/Au:N/C:N/I:C/A:C/E:F/RL:W/RC:C/CDP:ND/TD:M/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "ea5f3a4f 5.7", // test name
        "AV:N/AC:H/Au:N/C:N/I:N/A:C/E:U/RL:OF/RC:UR/CDP:LM/TD:ND/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "c20c2027 1.0", // test name
        "AV:N/AC:H/Au:N/C:N/I:N/A:N/E:F/RL:U/RC:UR/CDP:MH/TD:L/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "621e5cfc 1.3", // test name
        "AV:N/AC:H/Au:N/C:N/I:N/A:N/E:H/RL:OF/RC:UC/CDP:H/TD:L/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "df532c56 0.0", // test name
        "AV:N/AC:H/Au:N/C:N/I:N/A:N/E:U/RL:U/RC:UC/CDP:N/TD:N/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "ba19cb32 5.8", // test name
        "AV:N/AC:H/Au:N/C:N/I:P/A:C/E:ND/RL:ND/RC:UR/CDP:ND/TD:H/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "9fc2cdc6 0.0", // test name
        "AV:N/AC:H/Au:N/C:N/I:P/A:N/E:F/RL:ND/RC:UR/CDP:MH/TD:N/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "afaee09c 0.0", // test name
        "AV:N/AC:H/Au:N/C:P/I:C/A:C/E:F/RL:TF/RC:UR/CDP:LM/TD:N/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "b342f5ab 0.0", // test name
        "AV:N/AC:H/Au:N/C:P/I:C/A:C/E:POC/RL:W/RC:ND/CDP:ND/TD:N/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "10999431 7.3", // test name
        "AV:N/AC:H/Au:N/C:P/I:C/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "fc8edb35 0.0", // test name
        "AV:N/AC:H/Au:N/C:P/I:C/A:P/E:ND/RL:TF/RC:UR/CDP:N/TD:N/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "a42bb651 5.9", // test name
        "AV:N/AC:H/Au:N/C:P/I:N/A:C/E:POC/RL:ND/RC:UR/CDP:MH/TD:ND/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "8308f1db 0.0", // test name
        "AV:N/AC:H/Au:N/C:P/I:N/A:N/E:F/RL:ND/RC:C/CDP:H/TD:N/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "605abb6f 0.7", // test name
        "AV:N/AC:H/Au:N/C:P/I:N/A:N/E:POC/RL:W/RC:UC/CDP:L/TD:L/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(2.6), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(0.7)), // exp environmental score
        }, // exp
      ), (
        "8a57cef6 5.0", // test name
        "AV:N/AC:H/Au:N/C:P/I:N/A:P/E:F/RL:OF/RC:UR/CDP:H/TD:M/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "d929f2f7 4.9", // test name
        "AV:N/AC:H/Au:N/C:P/I:N/A:P/E:F/RL:U/RC:UR/CDP:L/TD:ND/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "7e50685c 0.0", // test name
        "AV:N/AC:H/Au:N/C:P/I:N/A:P/E:ND/RL:U/RC:C/CDP:H/TD:N/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "fa365256 1.9", // test name
        "AV:N/AC:H/Au:N/C:P/I:P/A:C/E:ND/RL:W/RC:C/CDP:LM/TD:L/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "cbef0d37 6.0", // test name
        "AV:N/AC:H/Au:N/C:P/I:P/A:C/E:U/RL:W/RC:UC/CDP:LM/TD:H/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "f9e1a91c 0.9", // test name
        "AV:N/AC:H/Au:N/C:P/I:P/A:N/E:ND/RL:TF/RC:ND/CDP:L/TD:L/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(0.9)), // exp environmental score
        }, // exp
      ), (
        "5a4482a0 2.9", // test name
        "AV:N/AC:H/Au:N/C:P/I:P/A:N/E:U/RL:TF/RC:ND/CDP:L/TD:M/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.1)), // exp temporal score
          environmental: Some(Score::from(2.9)), // exp environmental score
        }, // exp
      ), (
        "d39f2ba0 4.5", // test name
        "AV:N/AC:H/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:UR/CDP:MH/TD:M/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(5.1), // exp base score
          temporal: Some(Score::from(3.8)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "6127e463 8.2", // test name
        "AV:N/AC:H/Au:S/C:C/I:C/A:C/E:POC/RL:U/RC:ND/CDP:H/TD:H/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(8.2)), // exp environmental score
        }, // exp
      ), (
        "bbf77e6d 2.0", // test name
        "AV:N/AC:H/Au:S/C:C/I:C/A:C/E:U/RL:U/RC:UR/CDP:H/TD:L/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "bae482a5 7.4", // test name
        "AV:N/AC:H/Au:S/C:C/I:C/A:N/E:H/RL:U/RC:C/CDP:MH/TD:H/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "993fd254 0.0", // test name
        "AV:N/AC:H/Au:S/C:C/I:C/A:P/E:ND/RL:ND/RC:ND/CDP:LM/TD:N/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "ce63f082 5.9", // test name
        "AV:N/AC:H/Au:S/C:C/I:N/A:C/E:F/RL:U/RC:UR/CDP:N/TD:ND/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "72978e2f 0.0", // test name
        "AV:N/AC:H/Au:S/C:C/I:N/A:C/E:ND/RL:W/RC:UR/CDP:H/TD:N/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "1140c7ad 7.8", // test name
        "AV:N/AC:H/Au:S/C:C/I:N/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "f86fdda5 1.3", // test name
        "AV:N/AC:H/Au:S/C:C/I:N/A:C/E:POC/RL:U/RC:C/CDP:N/TD:L/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "768ce338 4.7", // test name
        "AV:N/AC:H/Au:S/C:C/I:N/A:N/E:U/RL:OF/RC:UC/CDP:N/TD:ND/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(3.3)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "5e6c48e6 0.0", // test name
        "AV:N/AC:H/Au:S/C:C/I:P/A:C/E:ND/RL:ND/RC:UR/CDP:LM/TD:N/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "0630eea5 5.3", // test name
        "AV:N/AC:H/Au:S/C:C/I:P/A:C/E:ND/RL:OF/RC:UR/CDP:LM/TD:M/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "88042403 1.6", // test name
        "AV:N/AC:H/Au:S/C:C/I:P/A:C/E:POC/RL:TF/RC:UC/CDP:LM/TD:L/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "def98501 0.0", // test name
        "AV:N/AC:H/Au:S/C:C/I:P/A:C/E:U/RL:TF/RC:C/CDP:N/TD:N/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "bcfadc6d 5.2", // test name
        "AV:N/AC:H/Au:S/C:C/I:P/A:P/E:F/RL:TF/RC:C/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: None, // exp environmental score
        }, // exp
      ), (
        "0caf639e 0.0", // test name
        "AV:N/AC:H/Au:S/C:C/I:P/A:P/E:POC/RL:W/RC:UC/CDP:L/TD:N/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "7d85f0e9 6.8", // test name
        "AV:N/AC:H/Au:S/C:N/I:C/A:C/E:H/RL:W/RC:C/CDP:N/TD:H/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.6), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "25b8e110 7.0", // test name
        "AV:N/AC:H/Au:S/C:N/I:C/A:N/E:H/RL:TF/RC:UC/CDP:H/TD:ND/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(7.0)), // exp environmental score
        }, // exp
      ), (
        "72b2299f 7.8", // test name
        "AV:N/AC:H/Au:S/C:N/I:C/A:P/E:H/RL:U/RC:C/CDP:H/TD:H/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "b2d17fa0 4.8", // test name
        "AV:N/AC:H/Au:S/C:N/I:N/A:C/E:H/RL:ND/RC:UC/CDP:N/TD:M/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(4.8)), // exp environmental score
        }, // exp
      ), (
        "3f4967aa 2.1", // test name
        "AV:N/AC:H/Au:S/C:N/I:N/A:C/E:ND/RL:TF/RC:ND/CDP:H/TD:L/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "e1d9e6f1 0.8", // test name
        "AV:N/AC:H/Au:S/C:N/I:N/A:C/E:ND/RL:W/RC:ND/CDP:L/TD:L/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(0.8)), // exp environmental score
        }, // exp
      ), (
        "92c41a7e 6.0", // test name
        "AV:N/AC:H/Au:S/C:N/I:N/A:C/E:POC/RL:ND/RC:UC/CDP:H/TD:ND/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "0f0a7a68 0.0", // test name
        "AV:N/AC:H/Au:S/C:N/I:N/A:N/E:POC/RL:OF/RC:C/CDP:L/TD:N/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "04607c0f 1.0", // test name
        "AV:N/AC:H/Au:S/C:N/I:N/A:N/E:U/RL:OF/RC:UC/CDP:L/TD:H/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "bc3828be 1.9", // test name
        "AV:N/AC:H/Au:S/C:N/I:N/A:P/E:F/RL:ND/RC:ND/CDP:L/TD:ND/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "ef7c8ab2 2.8", // test name
        "AV:N/AC:H/Au:S/C:N/I:N/A:P/E:F/RL:U/RC:C/CDP:L/TD:M/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(2.0)), // exp temporal score
          environmental: Some(Score::from(2.8)), // exp environmental score
        }, // exp
      ), (
        "80fe17c6 1.5", // test name
        "AV:N/AC:H/Au:S/C:N/I:P/A:C/E:POC/RL:U/RC:UR/CDP:ND/TD:L/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "2152d1d9 0.0", // test name
        "AV:N/AC:H/Au:S/C:N/I:P/A:C/E:U/RL:U/RC:ND/CDP:MH/TD:N/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "75aa9fc2 0.0", // test name
        "AV:N/AC:H/Au:S/C:P/I:C/A:N/E:F/RL:OF/RC:UC/CDP:H/TD:N/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "41d9dd00 5.8", // test name
        "AV:N/AC:H/Au:S/C:P/I:C/A:N/E:F/RL:TF/RC:UC/CDP:LM/TD:H/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(4.3)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "56b875fd 4.2", // test name
        "AV:N/AC:H/Au:S/C:P/I:C/A:N/E:F/RL:W/RC:ND/CDP:L/TD:M/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "da37c96b 4.7", // test name
        "AV:N/AC:H/Au:S/C:P/I:C/A:N/E:U/RL:OF/RC:UC/CDP:ND/TD:ND/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "8f83ebe0 3.6", // test name
        "AV:N/AC:H/Au:S/C:P/I:C/A:P/E:F/RL:OF/RC:ND/CDP:N/TD:ND/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(3.6)), // exp environmental score
        }, // exp
      ), (
        "12c02c38 0.0", // test name
        "AV:N/AC:H/Au:S/C:P/I:C/A:P/E:H/RL:ND/RC:ND/CDP:MH/TD:N/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8746d309 6.9", // test name
        "AV:N/AC:H/Au:S/C:P/I:N/A:C/E:ND/RL:ND/RC:C/CDP:LM/TD:ND/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "53cdd2a4 4.2", // test name
        "AV:N/AC:H/Au:S/C:P/I:N/A:C/E:POC/RL:OF/RC:UC/CDP:ND/TD:ND/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(5.6), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "b5953565 4.5", // test name
        "AV:N/AC:H/Au:S/C:P/I:N/A:N/E:F/RL:W/RC:ND/CDP:H/TD:M/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(2.1), // exp base score
          temporal: Some(Score::from(1.9)), // exp temporal score
          environmental: Some(Score::from(4.5)), // exp environmental score
        }, // exp
      ), (
        "3a9ee25f 1.0", // test name
        "AV:N/AC:H/Au:S/C:P/I:N/A:P/E:F/RL:W/RC:C/CDP:L/TD:L/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "f9594689 6.8", // test name
        "AV:N/AC:H/Au:S/C:P/I:N/A:P/E:U/RL:TF/RC:UR/CDP:H/TD:ND/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(3.6), // exp base score
          temporal: Some(Score::from(2.6)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "bd7339ac 1.6", // test name
        "AV:N/AC:H/Au:S/C:P/I:P/A:P/E:H/RL:TF/RC:ND/CDP:MH/TD:L/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(4.6), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "e5b5646e 0.0", // test name
        "AV:N/AC:L/Au:M/C:C/I:C/A:C/E:F/RL:OF/RC:UR/CDP:MH/TD:N/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "cd5b6197 8.0", // test name
        "AV:N/AC:L/Au:M/C:C/I:C/A:N/E:POC/RL:W/RC:C/CDP:LM/TD:H/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(8.0)), // exp environmental score
        }, // exp
      ), (
        "928a7277 0.0", // test name
        "AV:N/AC:L/Au:M/C:C/I:C/A:P/E:H/RL:ND/RC:C/CDP:H/TD:N/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(8.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "272718ff 5.6", // test name
        "AV:N/AC:L/Au:M/C:C/I:C/A:P/E:POC/RL:TF/RC:C/CDP:LM/TD:M/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "8a321636 5.1", // test name
        "AV:N/AC:L/Au:M/C:C/I:N/A:C/E:U/RL:OF/RC:ND/CDP:ND/TD:H/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "206608e7 3.5", // test name
        "AV:N/AC:L/Au:M/C:C/I:N/A:N/E:H/RL:W/RC:ND/CDP:ND/TD:ND/CR:L/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "81dbe837 0.0", // test name
        "AV:N/AC:L/Au:M/C:C/I:N/A:P/E:U/RL:TF/RC:ND/CDP:L/TD:N/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "7ed88b96 9.0", // test name
        "AV:N/AC:L/Au:M/C:C/I:P/A:C/E:ND/RL:U/RC:C/CDP:H/TD:H/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(8.0)), // exp temporal score
          environmental: Some(Score::from(9.0)), // exp environmental score
        }, // exp
      ), (
        "6e063383 0.0", // test name
        "AV:N/AC:L/Au:M/C:C/I:P/A:C/E:U/RL:OF/RC:C/CDP:ND/TD:N/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "bd696993 1.2", // test name
        "AV:N/AC:L/Au:M/C:C/I:P/A:P/E:F/RL:OF/RC:C/CDP:ND/TD:L/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(1.2)), // exp environmental score
        }, // exp
      ), (
        "9f05ad29 7.9", // test name
        "AV:N/AC:L/Au:M/C:C/I:P/A:P/E:H/RL:ND/RC:C/CDP:LM/TD:H/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "767fa87c 0.0", // test name
        "AV:N/AC:L/Au:M/C:N/I:C/A:C/E:POC/RL:TF/RC:UR/CDP:L/TD:N/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(7.7), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "3c3ef620 1.8", // test name
        "AV:N/AC:L/Au:M/C:N/I:C/A:N/E:F/RL:TF/RC:ND/CDP:L/TD:L/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "16dffd18 1.6", // test name
        "AV:N/AC:L/Au:M/C:N/I:C/A:N/E:ND/RL:OF/RC:UC/CDP:ND/TD:L/CR:M/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "014078c3 5.0", // test name
        "AV:N/AC:L/Au:M/C:N/I:C/A:N/E:POC/RL:W/RC:UR/CDP:ND/TD:H/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "1fe7b8f2 3.9", // test name
        "AV:N/AC:L/Au:M/C:N/I:C/A:N/E:U/RL:ND/RC:ND/CDP:ND/TD:M/CR:L/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "e2205ebb 4.9", // test name
        "AV:N/AC:L/Au:M/C:N/I:C/A:N/E:U/RL:TF/RC:UC/CDP:MH/TD:M/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "146dd58e 5.9", // test name
        "AV:N/AC:L/Au:M/C:N/I:C/A:P/E:ND/RL:OF/RC:C/CDP:N/TD:ND/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "e86a542b 3.5", // test name
        "AV:N/AC:L/Au:M/C:N/I:N/A:C/E:F/RL:ND/RC:ND/CDP:ND/TD:H/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(3.5)), // exp environmental score
        }, // exp
      ), (
        "3ca05a68 1.6", // test name
        "AV:N/AC:L/Au:M/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:LM/TD:L/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "ef6c175e 0.0", // test name
        "AV:N/AC:L/Au:M/C:N/I:N/A:C/E:H/RL:TF/RC:UC/CDP:LM/TD:N/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "409a7622 0.0", // test name
        "AV:N/AC:L/Au:M/C:N/I:N/A:C/E:H/RL:W/RC:UC/CDP:ND/TD:N/CR:L/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(6.1), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "518adf06 0.0", // test name
        "AV:N/AC:L/Au:M/C:N/I:N/A:N/E:F/RL:W/RC:ND/CDP:L/TD:N/CR:L/IR:L/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "41d4c67f 1.0", // test name
        "AV:N/AC:L/Au:M/C:N/I:N/A:N/E:ND/RL:U/RC:ND/CDP:MH/TD:L/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "8e1ce8a3 3.8", // test name
        "AV:N/AC:L/Au:M/C:N/I:N/A:N/E:POC/RL:U/RC:UC/CDP:H/TD:M/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(3.8)), // exp environmental score
        }, // exp
      ), (
        "88e2b31a 7.3", // test name
        "AV:N/AC:L/Au:M/C:N/I:P/A:C/E:H/RL:U/RC:UR/CDP:LM/TD:ND/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "89746d12 4.9", // test name
        "AV:N/AC:L/Au:M/C:N/I:P/A:N/E:ND/RL:ND/RC:ND/CDP:L/TD:ND/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "64053720 4.0", // test name
        "AV:N/AC:L/Au:M/C:N/I:P/A:P/E:H/RL:OF/RC:C/CDP:L/TD:M/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "1429649d 5.7", // test name
        "AV:N/AC:L/Au:M/C:P/I:C/A:N/E:POC/RL:TF/RC:UR/CDP:L/TD:H/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "c6b55454 6.4", // test name
        "AV:N/AC:L/Au:M/C:P/I:N/A:C/E:F/RL:U/RC:UR/CDP:MH/TD:M/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "336e5d3c 1.5", // test name
        "AV:N/AC:L/Au:M/C:P/I:N/A:C/E:H/RL:OF/RC:ND/CDP:N/TD:L/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "4d99659c 5.2", // test name
        "AV:N/AC:L/Au:M/C:P/I:N/A:N/E:H/RL:W/RC:UR/CDP:H/TD:M/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(3.3), // exp base score
          temporal: Some(Score::from(3.0)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "efbb589f 2.3", // test name
        "AV:N/AC:L/Au:M/C:P/I:N/A:P/E:F/RL:TF/RC:UC/CDP:N/TD:M/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.6)), // exp temporal score
          environmental: Some(Score::from(2.3)), // exp environmental score
        }, // exp
      ), (
        "5bb6a5f0 0.0", // test name
        "AV:N/AC:L/Au:M/C:P/I:N/A:P/E:ND/RL:ND/RC:ND/CDP:MH/TD:N/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "e44ccf06 1.5", // test name
        "AV:N/AC:L/Au:M/C:P/I:N/A:P/E:U/RL:TF/RC:UC/CDP:MH/TD:L/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "3bafa989 1.7", // test name
        "AV:N/AC:L/Au:M/C:P/I:P/A:C/E:F/RL:U/RC:UR/CDP:L/TD:L/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "dcb4a1c2 0.0", // test name
        "AV:N/AC:L/Au:M/C:P/I:P/A:C/E:ND/RL:W/RC:C/CDP:N/TD:N/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "c71ec92d 6.3", // test name
        "AV:N/AC:L/Au:M/C:P/I:P/A:C/E:POC/RL:ND/RC:UC/CDP:N/TD:ND/CR:H/IR:H/AR:M", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "03892993 5.6", // test name
        "AV:N/AC:L/Au:M/C:P/I:P/A:C/E:U/RL:ND/RC:UC/CDP:ND/TD:H/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "9cbf6b5b 0.0", // test name
        "AV:N/AC:L/Au:M/C:P/I:P/A:N/E:F/RL:OF/RC:UR/CDP:L/TD:N/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "27dd2a10 0.0", // test name
        "AV:N/AC:L/Au:M/C:P/I:P/A:N/E:U/RL:TF/RC:UC/CDP:L/TD:N/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(4.7), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "60773ca1 4.9", // test name
        "AV:N/AC:L/Au:M/C:P/I:P/A:P/E:U/RL:U/RC:C/CDP:ND/TD:ND/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "334648da 1.9", // test name
        "AV:N/AC:L/Au:N/C:C/I:C/A:N/E:F/RL:TF/RC:UC/CDP:L/TD:L/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(9.4), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "6c82ae5f 2.2", // test name
        "AV:N/AC:L/Au:N/C:C/I:C/A:N/E:U/RL:U/RC:UR/CDP:MH/TD:L/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(9.4), // exp base score
          temporal: Some(Score::from(7.6)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "24a0384b 1.8", // test name
        "AV:N/AC:L/Au:N/C:C/I:C/A:P/E:F/RL:W/RC:UC/CDP:N/TD:L/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(9.7), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "8722399e 8.6", // test name
        "AV:N/AC:L/Au:N/C:C/I:N/A:C/E:H/RL:ND/RC:C/CDP:N/TD:ND/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(9.4), // exp base score
          temporal: Some(Score::from(9.4)), // exp temporal score
          environmental: Some(Score::from(8.6)), // exp environmental score
        }, // exp
      ), (
        "247c2dcf 9.1", // test name
        "AV:N/AC:L/Au:N/C:C/I:N/A:P/E:F/RL:TF/RC:UR/CDP:H/TD:H/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(9.1)), // exp environmental score
        }, // exp
      ), (
        "74c1f2fd 6.2", // test name
        "AV:N/AC:L/Au:N/C:C/I:N/A:P/E:H/RL:TF/RC:UC/CDP:L/TD:M/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "26f6447b 1.5", // test name
        "AV:N/AC:L/Au:N/C:C/I:N/A:P/E:U/RL:OF/RC:C/CDP:L/TD:L/CR:L/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "97157a82 2.2", // test name
        "AV:N/AC:L/Au:N/C:C/I:P/A:P/E:U/RL:W/RC:C/CDP:H/TD:L/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(2.2)), // exp environmental score
        }, // exp
      ), (
        "5b63e2ad 8.2", // test name
        "AV:N/AC:L/Au:N/C:N/I:C/A:C/E:U/RL:OF/RC:UR/CDP:MH/TD:H/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(9.4), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(8.2)), // exp environmental score
        }, // exp
      ), (
        "dafb7552 6.3", // test name
        "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:W/RC:UR/CDP:N/TD:ND/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "af62ccd3 0.0", // test name
        "AV:N/AC:L/Au:N/C:N/I:N/A:N/E:H/RL:ND/RC:C/CDP:ND/TD:H/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "29befc97 0.8", // test name
        "AV:N/AC:L/Au:N/C:N/I:N/A:N/E:POC/RL:ND/RC:ND/CDP:L/TD:M/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.8)), // exp environmental score
        }, // exp
      ), (
        "aacc68d2 1.0", // test name
        "AV:N/AC:L/Au:N/C:N/I:N/A:N/E:U/RL:W/RC:C/CDP:L/TD:ND/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(1.0)), // exp environmental score
        }, // exp
      ), (
        "3513bc8a 6.1", // test name
        "AV:N/AC:L/Au:N/C:N/I:N/A:P/E:F/RL:W/RC:ND/CDP:LM/TD:H/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "3c7329cf 6.4", // test name
        "AV:N/AC:L/Au:N/C:N/I:N/A:P/E:H/RL:TF/RC:UC/CDP:MH/TD:ND/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "4dd2ca47 8.4", // test name
        "AV:N/AC:L/Au:N/C:N/I:P/A:C/E:F/RL:ND/RC:ND/CDP:LM/TD:ND/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(8.1)), // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "a8011fba 5.3", // test name
        "AV:N/AC:L/Au:N/C:N/I:P/A:C/E:F/RL:U/RC:UR/CDP:L/TD:M/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "5d2109ca 7.7", // test name
        "AV:N/AC:L/Au:N/C:N/I:P/A:C/E:POC/RL:ND/RC:UC/CDP:H/TD:ND/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "4ad0dec1 5.4", // test name
        "AV:N/AC:L/Au:N/C:N/I:P/A:N/E:POC/RL:ND/RC:C/CDP:H/TD:M/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "570fc0bf 1.6", // test name
        "AV:N/AC:L/Au:N/C:N/I:P/A:N/E:U/RL:W/RC:C/CDP:MH/TD:L/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(5.0), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(1.6)), // exp environmental score
        }, // exp
      ), (
        "5f6aedb5 5.9", // test name
        "AV:N/AC:L/Au:N/C:N/I:P/A:P/E:ND/RL:OF/RC:C/CDP:H/TD:M/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "f24f91de 8.2", // test name
        "AV:N/AC:L/Au:N/C:P/I:C/A:C/E:H/RL:TF/RC:UR/CDP:ND/TD:H/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(9.7), // exp base score
          temporal: Some(Score::from(8.3)), // exp temporal score
          environmental: Some(Score::from(8.2)), // exp environmental score
        }, // exp
      ), (
        "691e09bc 1.9", // test name
        "AV:N/AC:L/Au:N/C:P/I:C/A:N/E:H/RL:W/RC:UR/CDP:N/TD:L/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "2c1a3998 6.7", // test name
        "AV:N/AC:L/Au:N/C:P/I:C/A:N/E:ND/RL:U/RC:ND/CDP:ND/TD:ND/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(8.5)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "e8b1623e 8.3", // test name
        "AV:N/AC:L/Au:N/C:P/I:C/A:P/E:F/RL:ND/RC:UR/CDP:L/TD:H/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(8.1)), // exp temporal score
          environmental: Some(Score::from(8.3)), // exp environmental score
        }, // exp
      ), (
        "4528c927 5.0", // test name
        "AV:N/AC:L/Au:N/C:P/I:C/A:P/E:ND/RL:TF/RC:UC/CDP:L/TD:M/CR:L/IR:L/AR:H", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "e9c323ab 7.8", // test name
        "AV:N/AC:L/Au:N/C:P/I:N/A:C/E:U/RL:U/RC:ND/CDP:LM/TD:ND/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "fecde767 0.0", // test name
        "AV:N/AC:L/Au:N/C:P/I:N/A:P/E:F/RL:U/RC:UC/CDP:L/TD:N/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "c33ff61d 0.0", // test name
        "AV:N/AC:L/Au:N/C:P/I:N/A:P/E:POC/RL:OF/RC:UR/CDP:N/TD:N/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9610e3dc 8.1", // test name
        "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:F/RL:U/RC:ND/CDP:H/TD:H/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "633ec09d 0.0", // test name
        "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:F/RL:U/RC:UR/CDP:ND/TD:N/CR:L/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d202071b 7.9", // test name
        "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:POC/RL:ND/RC:UC/CDP:H/TD:H/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(7.9)), // exp environmental score
        }, // exp
      ), (
        "b7e703eb 5.8", // test name
        "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:POC/RL:TF/RC:ND/CDP:N/TD:ND/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.8)), // exp environmental score
        }, // exp
      ), (
        "948f8663 6.3", // test name
        "AV:N/AC:L/Au:N/C:P/I:P/A:P/E:H/RL:ND/RC:ND/CDP:N/TD:ND/CR:ND/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "a8d9d7e4 4.3", // test name
        "AV:N/AC:L/Au:N/C:P/I:P/A:P/E:H/RL:OF/RC:UR/CDP:ND/TD:M/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(4.3)), // exp environmental score
        }, // exp
      ), (
        "76671b3d 7.3", // test name
        "AV:N/AC:L/Au:N/C:P/I:P/A:P/E:POC/RL:W/RC:UR/CDP:LM/TD:ND/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "ede4d6e3 0.0", // test name
        "AV:N/AC:L/Au:S/C:C/I:C/A:C/E:ND/RL:OF/RC:UC/CDP:N/TD:N/CR:H/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8559ed56 2.0", // test name
        "AV:N/AC:L/Au:S/C:C/I:C/A:N/E:ND/RL:ND/RC:UC/CDP:L/TD:L/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "069fe975 8.7", // test name
        "AV:N/AC:L/Au:S/C:C/I:C/A:N/E:ND/RL:TF/RC:UC/CDP:H/TD:ND/CR:M/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(8.7)), // exp environmental score
        }, // exp
      ), (
        "dfdf7e14 0.0", // test name
        "AV:N/AC:L/Au:S/C:C/I:C/A:N/E:ND/RL:W/RC:UR/CDP:LM/TD:N/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "ae40f76b 5.5", // test name
        "AV:N/AC:L/Au:S/C:C/I:C/A:P/E:F/RL:W/RC:UC/CDP:ND/TD:M/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "b32dd7a4 6.6", // test name
        "AV:N/AC:L/Au:S/C:C/I:N/A:C/E:U/RL:OF/RC:UC/CDP:LM/TD:H/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(6.6)), // exp environmental score
        }, // exp
      ), (
        "df243eb0 1.7", // test name
        "AV:N/AC:L/Au:S/C:C/I:N/A:N/E:F/RL:OF/RC:UR/CDP:LM/TD:L/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "1b6ba0bc 6.4", // test name
        "AV:N/AC:L/Au:S/C:C/I:N/A:N/E:U/RL:OF/RC:UR/CDP:LM/TD:ND/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(4.8)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "1e4239a7 7.8", // test name
        "AV:N/AC:L/Au:S/C:C/I:P/A:C/E:F/RL:OF/RC:UR/CDP:MH/TD:ND/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "5f949232 5.4", // test name
        "AV:N/AC:L/Au:S/C:C/I:P/A:C/E:ND/RL:TF/RC:UR/CDP:LM/TD:M/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(5.4)), // exp environmental score
        }, // exp
      ), (
        "ef65dc6b 2.1", // test name
        "AV:N/AC:L/Au:S/C:C/I:P/A:N/E:F/RL:ND/RC:UR/CDP:H/TD:L/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "430c39ff 6.4", // test name
        "AV:N/AC:L/Au:S/C:C/I:P/A:N/E:POC/RL:TF/RC:UR/CDP:H/TD:M/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "4a7ea594 1.8", // test name
        "AV:N/AC:L/Au:S/C:C/I:P/A:N/E:U/RL:W/RC:UC/CDP:MH/TD:L/CR:ND/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "505b252b 6.4", // test name
        "AV:N/AC:L/Au:S/C:C/I:P/A:P/E:F/RL:W/RC:C/CDP:MH/TD:M/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "9b71db05 8.3", // test name
        "AV:N/AC:L/Au:S/C:C/I:P/A:P/E:POC/RL:U/RC:UR/CDP:MH/TD:H/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(8.3)), // exp environmental score
        }, // exp
      ), (
        "050c9137 5.9", // test name
        "AV:N/AC:L/Au:S/C:N/I:C/A:N/E:ND/RL:W/RC:UC/CDP:ND/TD:ND/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "65b726c4 0.0", // test name
        "AV:N/AC:L/Au:S/C:N/I:C/A:N/E:U/RL:ND/RC:ND/CDP:N/TD:N/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "ed4d8f23 0.0", // test name
        "AV:N/AC:L/Au:S/C:N/I:N/A:N/E:F/RL:U/RC:UC/CDP:LM/TD:N/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "73d1dd37 3.9", // test name
        "AV:N/AC:L/Au:S/C:N/I:N/A:P/E:F/RL:W/RC:UC/CDP:L/TD:H/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.2)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "88ae0f35 0.0", // test name
        "AV:N/AC:L/Au:S/C:N/I:N/A:P/E:POC/RL:TF/RC:UC/CDP:LM/TD:N/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8fbc0796 9.3", // test name
        "AV:N/AC:L/Au:S/C:N/I:P/A:C/E:H/RL:U/RC:ND/CDP:LM/TD:ND/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(9.3)), // exp environmental score
        }, // exp
      ), (
        "25b8653a 0.0", // test name
        "AV:N/AC:L/Au:S/C:N/I:P/A:C/E:U/RL:U/RC:UR/CDP:LM/TD:N/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "dfeaf424 1.8", // test name
        "AV:N/AC:L/Au:S/C:N/I:P/A:P/E:F/RL:W/RC:UC/CDP:H/TD:L/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.5)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "bedaa0f6 5.6", // test name
        "AV:N/AC:L/Au:S/C:N/I:P/A:P/E:POC/RL:U/RC:C/CDP:N/TD:ND/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "550da05f 0.0", // test name
        "AV:N/AC:L/Au:S/C:P/I:C/A:C/E:F/RL:W/RC:ND/CDP:H/TD:N/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(7.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "a18c842c 1.8", // test name
        "AV:N/AC:L/Au:S/C:P/I:C/A:C/E:U/RL:OF/RC:UC/CDP:LM/TD:L/CR:ND/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(8.7), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "d4fafa49 8.2", // test name
        "AV:N/AC:L/Au:S/C:P/I:C/A:N/E:H/RL:W/RC:UR/CDP:H/TD:H/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(8.2)), // exp environmental score
        }, // exp
      ), (
        "258fe15e 0.0", // test name
        "AV:N/AC:L/Au:S/C:P/I:C/A:N/E:ND/RL:OF/RC:C/CDP:N/TD:N/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "4135fedf 0.0", // test name
        "AV:N/AC:L/Au:S/C:P/I:C/A:P/E:F/RL:TF/RC:UR/CDP:ND/TD:N/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "70f716f6 0.0", // test name
        "AV:N/AC:L/Au:S/C:P/I:C/A:P/E:U/RL:U/RC:C/CDP:L/TD:N/CR:H/IR:L/AR:H", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "b8b84d69 6.2", // test name
        "AV:N/AC:L/Au:S/C:P/I:N/A:C/E:U/RL:U/RC:UR/CDP:L/TD:ND/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "ceea1a85 1.8", // test name
        "AV:N/AC:L/Au:S/C:P/I:N/A:N/E:ND/RL:W/RC:UC/CDP:H/TD:L/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "3477cd2e 0.0", // test name
        "AV:N/AC:L/Au:S/C:P/I:N/A:N/E:POC/RL:ND/RC:UR/CDP:L/TD:N/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.0), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "6a2bb2ff 1.5", // test name
        "AV:N/AC:L/Au:S/C:P/I:N/A:P/E:ND/RL:ND/RC:ND/CDP:L/TD:L/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "1778a449 8.1", // test name
        "AV:N/AC:L/Au:S/C:P/I:P/A:C/E:ND/RL:U/RC:UC/CDP:LM/TD:H/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "0771b359 2.1", // test name
        "AV:N/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:ND/RC:C/CDP:MH/TD:L/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(7.2)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "fa306728 5.9", // test name
        "AV:N/AC:L/Au:S/C:P/I:P/A:C/E:U/RL:TF/RC:UR/CDP:N/TD:ND/CR:L/IR:H/AR:M", // vec
        Scores {
          base: Score::from(8.0), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "550f4125 3.9", // test name
        "AV:N/AC:L/Au:S/C:P/I:P/A:N/E:POC/RL:OF/RC:UR/CDP:L/TD:M/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(5.5), // exp base score
          temporal: Some(Score::from(4.1)), // exp temporal score
          environmental: Some(Score::from(3.9)), // exp environmental score
        }, // exp
      ), (
        "0c00849f 5.6", // test name
        "AV:N/AC:L/Au:S/C:P/I:P/A:P/E:F/RL:TF/RC:UR/CDP:H/TD:M/CR:L/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(5.6)), // exp environmental score
        }, // exp
      ), (
        "f02e1cb6 0.0", // test name
        "AV:N/AC:L/Au:S/C:P/I:P/A:P/E:ND/RL:W/RC:ND/CDP:LM/TD:N/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.5), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8e7a269a 1.9", // test name
        "AV:N/AC:M/Au:M/C:C/I:C/A:C/E:F/RL:ND/RC:C/CDP:L/TD:L/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "67ace2b4 6.7", // test name
        "AV:N/AC:M/Au:M/C:C/I:C/A:N/E:POC/RL:W/RC:ND/CDP:ND/TD:H/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "aeaf7207 0.0", // test name
        "AV:N/AC:M/Au:M/C:C/I:C/A:P/E:U/RL:U/RC:UC/CDP:LM/TD:N/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9b585bb9 5.3", // test name
        "AV:N/AC:M/Au:M/C:C/I:N/A:P/E:H/RL:OF/RC:UC/CDP:H/TD:M/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(5.3)), // exp environmental score
        }, // exp
      ), (
        "e45d2977 6.1", // test name
        "AV:N/AC:M/Au:M/C:C/I:N/A:P/E:ND/RL:TF/RC:C/CDP:L/TD:H/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "0f4d2fac 0.0", // test name
        "AV:N/AC:M/Au:M/C:C/I:P/A:C/E:H/RL:U/RC:ND/CDP:N/TD:N/CR:L/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(7.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "33c07760 1.9", // test name
        "AV:N/AC:M/Au:M/C:C/I:P/A:C/E:ND/RL:TF/RC:UC/CDP:LM/TD:L/CR:H/IR:M/AR:M", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "508cda34 0.0", // test name
        "AV:N/AC:M/Au:M/C:C/I:P/A:P/E:F/RL:W/RC:UR/CDP:LM/TD:N/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(5.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "a22144aa 5.5", // test name
        "AV:N/AC:M/Au:M/C:N/I:C/A:C/E:H/RL:U/RC:C/CDP:ND/TD:M/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(7.3)), // exp temporal score
          environmental: Some(Score::from(5.5)), // exp environmental score
        }, // exp
      ), (
        "e098cf0a 0.0", // test name
        "AV:N/AC:M/Au:M/C:N/I:C/A:C/E:POC/RL:ND/RC:UR/CDP:MH/TD:N/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d394fe40 4.9", // test name
        "AV:N/AC:M/Au:M/C:N/I:C/A:C/E:U/RL:TF/RC:ND/CDP:LM/TD:M/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(7.3), // exp base score
          temporal: Some(Score::from(5.6)), // exp temporal score
          environmental: Some(Score::from(4.9)), // exp environmental score
        }, // exp
      ), (
        "3bb9758b 0.8", // test name
        "AV:N/AC:M/Au:M/C:N/I:C/A:N/E:POC/RL:OF/RC:UC/CDP:L/TD:L/CR:L/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.7), // exp base score
          temporal: Some(Score::from(4.0)), // exp temporal score
          environmental: Some(Score::from(0.8)), // exp environmental score
        }, // exp
      ), (
        "0863eb9c 4.6", // test name
        "AV:N/AC:M/Au:M/C:N/I:C/A:P/E:ND/RL:OF/RC:UC/CDP:MH/TD:M/CR:L/IR:L/AR:M", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(4.6)), // exp environmental score
        }, // exp
      ), (
        "f8a670a8 5.1", // test name
        "AV:N/AC:M/Au:M/C:N/I:C/A:P/E:ND/RL:W/RC:UR/CDP:MH/TD:M/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "b3edc417 2.0", // test name
        "AV:N/AC:M/Au:M/C:N/I:C/A:P/E:POC/RL:U/RC:UC/CDP:H/TD:L/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "0c8f0206 3.0", // test name
        "AV:N/AC:M/Au:M/C:N/I:N/A:N/E:U/RL:U/RC:UR/CDP:LM/TD:ND/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "5c521b65 6.9", // test name
        "AV:N/AC:M/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:UR/CDP:MH/TD:H/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "e38d42d1 5.9", // test name
        "AV:N/AC:M/Au:M/C:N/I:P/A:N/E:H/RL:OF/RC:UR/CDP:MH/TD:H/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.3)), // exp temporal score
          environmental: Some(Score::from(5.9)), // exp environmental score
        }, // exp
      ), (
        "908bdb65 0.0", // test name
        "AV:N/AC:M/Au:M/C:N/I:P/A:N/E:ND/RL:W/RC:UC/CDP:N/TD:N/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "e14405b8 3.0", // test name
        "AV:N/AC:M/Au:M/C:N/I:P/A:P/E:F/RL:OF/RC:UR/CDP:N/TD:M/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.4)), // exp temporal score
          environmental: Some(Score::from(3.0)), // exp environmental score
        }, // exp
      ), (
        "d4a4987d 5.0", // test name
        "AV:N/AC:M/Au:M/C:N/I:P/A:P/E:H/RL:OF/RC:ND/CDP:L/TD:H/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(5.0)), // exp environmental score
        }, // exp
      ), (
        "29528d3f 6.1", // test name
        "AV:N/AC:M/Au:M/C:P/I:C/A:C/E:F/RL:ND/RC:UR/CDP:H/TD:M/CR:M/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "aec57930 5.1", // test name
        "AV:N/AC:M/Au:M/C:P/I:C/A:C/E:ND/RL:W/RC:UC/CDP:ND/TD:M/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(5.1)), // exp environmental score
        }, // exp
      ), (
        "698291cd 7.1", // test name
        "AV:N/AC:M/Au:M/C:P/I:C/A:C/E:POC/RL:ND/RC:C/CDP:ND/TD:ND/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(7.5), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(7.1)), // exp environmental score
        }, // exp
      ), (
        "6917c9f0 5.2", // test name
        "AV:N/AC:M/Au:M/C:P/I:C/A:N/E:F/RL:TF/RC:UR/CDP:N/TD:H/CR:ND/IR:M/AR:L", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(5.2)), // exp environmental score
        }, // exp
      ), (
        "f00cad80 1.3", // test name
        "AV:N/AC:M/Au:M/C:P/I:C/A:P/E:U/RL:OF/RC:ND/CDP:N/TD:L/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(1.3)), // exp environmental score
        }, // exp
      ), (
        "d3e29ffa 0.0", // test name
        "AV:N/AC:M/Au:M/C:P/I:N/A:C/E:F/RL:ND/RC:UR/CDP:MH/TD:N/CR:ND/IR:M/AR:M", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8ddd2827 1.9", // test name
        "AV:N/AC:M/Au:M/C:P/I:N/A:C/E:ND/RL:OF/RC:UR/CDP:H/TD:L/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.3)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "8a82fede 8.4", // test name
        "AV:N/AC:M/Au:M/C:P/I:N/A:C/E:ND/RL:U/RC:ND/CDP:H/TD:ND/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(8.4)), // exp environmental score
        }, // exp
      ), (
        "5e79cc15 1.5", // test name
        "AV:N/AC:M/Au:M/C:P/I:N/A:C/E:U/RL:U/RC:ND/CDP:L/TD:L/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.4), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "26b9eabe 0.8", // test name
        "AV:N/AC:M/Au:M/C:P/I:N/A:N/E:ND/RL:TF/RC:UR/CDP:L/TD:L/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(2.8), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(0.8)), // exp environmental score
        }, // exp
      ), (
        "704281d3 5.7", // test name
        "AV:N/AC:M/Au:M/C:P/I:P/A:C/E:H/RL:ND/RC:C/CDP:MH/TD:M/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.9), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(5.7)), // exp environmental score
        }, // exp
      ), (
        "89252e22 6.2", // test name
        "AV:N/AC:M/Au:M/C:P/I:P/A:N/E:ND/RL:TF/RC:UR/CDP:MH/TD:ND/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(6.2)), // exp environmental score
        }, // exp
      ), (
        "d2c258e7 0.8", // test name
        "AV:N/AC:M/Au:M/C:P/I:P/A:N/E:U/RL:OF/RC:UC/CDP:ND/TD:L/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(0.8)), // exp environmental score
        }, // exp
      ), (
        "96b30e43 7.6", // test name
        "AV:N/AC:M/Au:M/C:P/I:P/A:P/E:H/RL:ND/RC:UR/CDP:MH/TD:ND/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(7.6)), // exp environmental score
        }, // exp
      ), (
        "70d6981c 0.0", // test name
        "AV:N/AC:M/Au:M/C:P/I:P/A:P/E:ND/RL:ND/RC:C/CDP:H/TD:N/CR:ND/IR:H/AR:M", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "ff442cfb 4.2", // test name
        "AV:N/AC:M/Au:M/C:P/I:P/A:P/E:ND/RL:U/RC:C/CDP:N/TD:H/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(5.4), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(4.2)), // exp environmental score
        }, // exp
      ), (
        "cf55f9ca 6.7", // test name
        "AV:N/AC:M/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:UC/CDP:N/TD:ND/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(9.3), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "d38f1214 0.0", // test name
        "AV:N/AC:M/Au:N/C:C/I:C/A:C/E:H/RL:W/RC:UR/CDP:MH/TD:N/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(9.3), // exp base score
          temporal: Some(Score::from(8.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "fd8107cb 6.7", // test name
        "AV:N/AC:M/Au:N/C:C/I:C/A:C/E:ND/RL:U/RC:UC/CDP:MH/TD:M/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(9.3), // exp base score
          temporal: Some(Score::from(8.4)), // exp temporal score
          environmental: Some(Score::from(6.7)), // exp environmental score
        }, // exp
      ), (
        "eb868527 6.0", // test name
        "AV:N/AC:M/Au:N/C:C/I:C/A:N/E:F/RL:OF/RC:UC/CDP:H/TD:M/CR:L/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(8.8), // exp base score
          temporal: Some(Score::from(6.5)), // exp temporal score
          environmental: Some(Score::from(6.0)), // exp environmental score
        }, // exp
      ), (
        "ae3d323c 2.4", // test name
        "AV:N/AC:M/Au:N/C:C/I:C/A:P/E:ND/RL:U/RC:C/CDP:H/TD:L/CR:ND/IR:H/AR:H", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(9.0)), // exp temporal score
          environmental: Some(Score::from(2.4)), // exp environmental score
        }, // exp
      ), (
        "77617d71 0.0", // test name
        "AV:N/AC:M/Au:N/C:C/I:C/A:P/E:ND/RL:W/RC:ND/CDP:L/TD:N/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(8.5)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8df5843e 0.0", // test name
        "AV:N/AC:M/Au:N/C:C/I:C/A:P/E:U/RL:TF/RC:UC/CDP:L/TD:N/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(6.2)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "8db0289e 6.8", // test name
        "AV:N/AC:M/Au:N/C:C/I:N/A:N/E:F/RL:U/RC:ND/CDP:ND/TD:H/CR:M/IR:H/AR:L", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "bd0d74d1 1.9", // test name
        "AV:N/AC:M/Au:N/C:C/I:N/A:N/E:U/RL:TF/RC:UR/CDP:H/TD:L/CR:M/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(5.2)), // exp temporal score
          environmental: Some(Score::from(1.9)), // exp environmental score
        }, // exp
      ), (
        "d2b16181 8.5", // test name
        "AV:N/AC:M/Au:N/C:C/I:P/A:C/E:H/RL:OF/RC:UC/CDP:H/TD:H/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(8.5)), // exp environmental score
        }, // exp
      ), (
        "28a17708 8.6", // test name
        "AV:N/AC:M/Au:N/C:C/I:P/A:C/E:POC/RL:U/RC:C/CDP:L/TD:H/CR:H/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(8.1)), // exp temporal score
          environmental: Some(Score::from(8.6)), // exp environmental score
        }, // exp
      ), (
        "9a189195 7.7", // test name
        "AV:N/AC:M/Au:N/C:C/I:P/A:N/E:H/RL:W/RC:ND/CDP:L/TD:ND/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(7.4)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "e44ff48e 7.2", // test name
        "AV:N/AC:M/Au:N/C:C/I:P/A:N/E:ND/RL:U/RC:ND/CDP:MH/TD:H/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(7.8)), // exp temporal score
          environmental: Some(Score::from(7.2)), // exp environmental score
        }, // exp
      ), (
        "2b2f49fd 6.9", // test name
        "AV:N/AC:M/Au:N/C:C/I:P/A:N/E:POC/RL:OF/RC:UR/CDP:ND/TD:H/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(6.9)), // exp environmental score
        }, // exp
      ), (
        "c8a18c7e 1.8", // test name
        "AV:N/AC:M/Au:N/C:C/I:P/A:P/E:F/RL:OF/RC:ND/CDP:ND/TD:L/CR:M/IR:M/AR:H", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "5a674560 8.1", // test name
        "AV:N/AC:M/Au:N/C:C/I:P/A:P/E:POC/RL:W/RC:UC/CDP:H/TD:H/CR:M/IR:L/AR:M", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(6.4)), // exp temporal score
          environmental: Some(Score::from(8.1)), // exp environmental score
        }, // exp
      ), (
        "5a4108cc 0.0", // test name
        "AV:N/AC:M/Au:N/C:N/I:C/A:C/E:F/RL:TF/RC:UC/CDP:ND/TD:N/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(8.8), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9b093025 0.0", // test name
        "AV:N/AC:M/Au:N/C:N/I:C/A:C/E:ND/RL:TF/RC:UC/CDP:L/TD:N/CR:M/IR:M/AR:M", // vec
        Scores {
          base: Score::from(8.8), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "1e048aff 2.0", // test name
        "AV:N/AC:M/Au:N/C:N/I:C/A:N/E:ND/RL:U/RC:ND/CDP:LM/TD:L/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "44ca6779 0.0", // test name
        "AV:N/AC:M/Au:N/C:N/I:C/A:N/E:U/RL:U/RC:UC/CDP:MH/TD:N/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "b25c7fed 4.0", // test name
        "AV:N/AC:M/Au:N/C:N/I:N/A:C/E:F/RL:TF/RC:C/CDP:ND/TD:ND/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(7.1), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(4.0)), // exp environmental score
        }, // exp
      ), (
        "7c93fa38 0.0", // test name
        "AV:N/AC:M/Au:N/C:N/I:N/A:N/E:H/RL:U/RC:ND/CDP:ND/TD:M/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(0.0), // exp base score
          temporal: Some(Score::from(0.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "90746377 2.1", // test name
        "AV:N/AC:M/Au:N/C:N/I:P/A:C/E:POC/RL:ND/RC:UR/CDP:H/TD:L/CR:M/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "99fa55e6 4.7", // test name
        "AV:N/AC:M/Au:N/C:N/I:P/A:N/E:F/RL:W/RC:C/CDP:MH/TD:M/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.3), // exp base score
          temporal: Some(Score::from(3.9)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "5b951700 6.3", // test name
        "AV:N/AC:M/Au:N/C:N/I:P/A:P/E:ND/RL:ND/RC:UR/CDP:LM/TD:H/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(5.8), // exp base score
          temporal: Some(Score::from(5.5)), // exp temporal score
          environmental: Some(Score::from(6.3)), // exp environmental score
        }, // exp
      ), (
        "3df9b2e8 9.5", // test name
        "AV:N/AC:M/Au:N/C:P/I:C/A:C/E:ND/RL:U/RC:ND/CDP:LM/TD:H/CR:ND/IR:M/AR:H", // vec
        Scores {
          base: Score::from(9.0), // exp base score
          temporal: Some(Score::from(9.0)), // exp temporal score
          environmental: Some(Score::from(9.5)), // exp environmental score
        }, // exp
      ), (
        "c784aa3d 0.0", // test name
        "AV:N/AC:M/Au:N/C:P/I:C/A:N/E:ND/RL:TF/RC:UR/CDP:L/TD:N/CR:H/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "9f7c8f40 8.7", // test name
        "AV:N/AC:M/Au:N/C:P/I:C/A:N/E:POC/RL:OF/RC:ND/CDP:H/TD:H/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.1)), // exp temporal score
          environmental: Some(Score::from(8.7)), // exp environmental score
        }, // exp
      ), (
        "33b7d69c 0.0", // test name
        "AV:N/AC:M/Au:N/C:P/I:C/A:P/E:ND/RL:ND/RC:C/CDP:MH/TD:N/CR:L/IR:H/AR:H", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(8.3)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "22d0e5c2 8.7", // test name
        "AV:N/AC:M/Au:N/C:P/I:N/A:C/E:ND/RL:ND/RC:ND/CDP:H/TD:ND/CR:L/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: None, // exp temporal score
          environmental: Some(Score::from(8.7)), // exp environmental score
        }, // exp
      ), (
        "051bb82d 1.4", // test name
        "AV:N/AC:M/Au:N/C:P/I:N/A:C/E:ND/RL:OF/RC:C/CDP:L/TD:L/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(7.8), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "c7fa9eba 0.0", // test name
        "AV:N/AC:M/Au:N/C:P/I:P/A:C/E:U/RL:U/RC:ND/CDP:ND/TD:N/CR:M/IR:M/AR:L", // vec
        Scores {
          base: Score::from(8.3), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "09435799 0.0", // test name
        "AV:N/AC:M/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C/CDP:N/TD:N/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(6.8), // exp base score
          temporal: Some(Score::from(5.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "eb354942 2.1", // test name
        "AV:N/AC:M/Au:S/C:C/I:C/A:C/E:ND/RL:TF/RC:ND/CDP:MH/TD:L/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(2.1)), // exp environmental score
        }, // exp
      ), (
        "2d273ba3 1.8", // test name
        "AV:N/AC:M/Au:S/C:C/I:C/A:C/E:POC/RL:U/RC:ND/CDP:ND/TD:L/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(8.5), // exp base score
          temporal: Some(Score::from(7.7)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "7f9411ee 0.0", // test name
        "AV:N/AC:M/Au:S/C:C/I:C/A:N/E:ND/RL:OF/RC:C/CDP:L/TD:N/CR:ND/IR:ND/AR:H", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(6.9)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "1b26f8c7 0.0", // test name
        "AV:N/AC:M/Au:S/C:C/I:C/A:P/E:F/RL:OF/RC:ND/CDP:L/TD:N/CR:L/IR:M/AR:M", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d60ff2ee 6.8", // test name
        "AV:N/AC:M/Au:S/C:C/I:N/A:C/E:F/RL:TF/RC:ND/CDP:ND/TD:H/CR:M/IR:ND/AR:M", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(6.8)), // exp temporal score
          environmental: Some(Score::from(6.8)), // exp environmental score
        }, // exp
      ), (
        "1cacb4d6 0.0", // test name
        "AV:N/AC:M/Au:S/C:C/I:N/A:N/E:F/RL:U/RC:UR/CDP:MH/TD:N/CR:ND/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "43273ad0 8.0", // test name
        "AV:N/AC:M/Au:S/C:C/I:N/A:N/E:POC/RL:OF/RC:ND/CDP:MH/TD:H/CR:H/IR:H/AR:L", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(8.0)), // exp environmental score
        }, // exp
      ), (
        "da3e711c 0.0", // test name
        "AV:N/AC:M/Au:S/C:C/I:N/A:N/E:POC/RL:TF/RC:C/CDP:N/TD:N/CR:M/IR:L/AR:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "d0318ad3 7.4", // test name
        "AV:N/AC:M/Au:S/C:C/I:N/A:P/E:POC/RL:U/RC:UR/CDP:LM/TD:ND/CR:M/IR:H/AR:H", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "d3f8e510 7.3", // test name
        "AV:N/AC:M/Au:S/C:C/I:P/A:C/E:F/RL:U/RC:UC/CDP:N/TD:ND/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "90b11fa6 9.1", // test name
        "AV:N/AC:M/Au:S/C:C/I:P/A:N/E:ND/RL:U/RC:C/CDP:MH/TD:H/CR:H/IR:M/AR:H", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(7.0)), // exp temporal score
          environmental: Some(Score::from(9.1)), // exp environmental score
        }, // exp
      ), (
        "a3802ce5 0.0", // test name
        "AV:N/AC:M/Au:S/C:C/I:P/A:N/E:ND/RL:W/RC:C/CDP:N/TD:N/CR:ND/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "67848cee 0.0", // test name
        "AV:N/AC:M/Au:S/C:C/I:P/A:N/E:U/RL:ND/RC:C/CDP:LM/TD:N/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "5f92932c 2.0", // test name
        "AV:N/AC:M/Au:S/C:N/I:C/A:C/E:H/RL:TF/RC:C/CDP:L/TD:L/CR:M/IR:H/AR:M", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "b3c90f1f 0.0", // test name
        "AV:N/AC:M/Au:S/C:N/I:C/A:C/E:U/RL:OF/RC:ND/CDP:L/TD:N/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(5.8)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "790eeee3 7.7", // test name
        "AV:N/AC:M/Au:S/C:N/I:C/A:C/E:U/RL:TF/RC:UC/CDP:H/TD:ND/CR:H/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(7.9), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(7.7)), // exp environmental score
        }, // exp
      ), (
        "a2a3ce8b 2.0", // test name
        "AV:N/AC:M/Au:S/C:N/I:C/A:N/E:F/RL:TF/RC:UR/CDP:MH/TD:L/CR:H/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "bfacf127 1.8", // test name
        "AV:N/AC:M/Au:S/C:N/I:C/A:N/E:ND/RL:U/RC:UC/CDP:MH/TD:L/CR:L/IR:M/AR:H", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.7)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "da3ee7cc 0.0", // test name
        "AV:N/AC:M/Au:S/C:N/I:C/A:N/E:POC/RL:W/RC:ND/CDP:L/TD:N/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "5cb14f4f 0.0", // test name
        "AV:N/AC:M/Au:S/C:N/I:N/A:C/E:ND/RL:TF/RC:UC/CDP:H/TD:N/CR:M/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(6.3), // exp base score
          temporal: Some(Score::from(5.1)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "1f20ec64 7.8", // test name
        "AV:N/AC:M/Au:S/C:N/I:P/A:C/E:H/RL:ND/RC:UC/CDP:MH/TD:H/CR:L/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.3)), // exp temporal score
          environmental: Some(Score::from(7.8)), // exp environmental score
        }, // exp
      ), (
        "e297c380 4.7", // test name
        "AV:N/AC:M/Au:S/C:N/I:P/A:C/E:U/RL:OF/RC:UR/CDP:ND/TD:ND/CR:H/IR:L/AR:M", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(4.7)), // exp environmental score
        }, // exp
      ), (
        "ea598510 2.0", // test name
        "AV:N/AC:M/Au:S/C:N/I:P/A:N/E:H/RL:OF/RC:UR/CDP:ND/TD:H/CR:H/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(2.9)), // exp temporal score
          environmental: Some(Score::from(2.0)), // exp environmental score
        }, // exp
      ), (
        "ac93ee15 1.8", // test name
        "AV:N/AC:M/Au:S/C:N/I:P/A:P/E:ND/RL:U/RC:C/CDP:LM/TD:L/CR:H/IR:H/AR:H", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.9)), // exp temporal score
          environmental: Some(Score::from(1.8)), // exp environmental score
        }, // exp
      ), (
        "05614ab0 1.4", // test name
        "AV:N/AC:M/Au:S/C:N/I:P/A:P/E:POC/RL:W/RC:C/CDP:LM/TD:L/CR:H/IR:M/AR:L", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.2)), // exp temporal score
          environmental: Some(Score::from(1.4)), // exp environmental score
        }, // exp
      ), (
        "f8d602a7 0.0", // test name
        "AV:N/AC:M/Au:S/C:N/I:P/A:P/E:U/RL:U/RC:UC/CDP:ND/TD:N/CR:H/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "eb6f970c 7.4", // test name
        "AV:N/AC:M/Au:S/C:P/I:C/A:C/E:ND/RL:OF/RC:ND/CDP:ND/TD:H/CR:ND/IR:H/AR:ND", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(7.1)), // exp temporal score
          environmental: Some(Score::from(7.4)), // exp environmental score
        }, // exp
      ), (
        "c7654f7a 6.1", // test name
        "AV:N/AC:M/Au:S/C:P/I:C/A:C/E:POC/RL:TF/RC:ND/CDP:H/TD:M/CR:H/IR:ND/AR:L", // vec
        Scores {
          base: Score::from(8.2), // exp base score
          temporal: Some(Score::from(6.6)), // exp temporal score
          environmental: Some(Score::from(6.1)), // exp environmental score
        }, // exp
      ), (
        "017e7a8c 0.0", // test name
        "AV:N/AC:M/Au:S/C:P/I:C/A:N/E:POC/RL:TF/RC:UR/CDP:N/TD:N/CR:ND/IR:L/AR:M", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(5.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "027a13c3 7.3", // test name
        "AV:N/AC:M/Au:S/C:P/I:C/A:N/E:U/RL:OF/RC:UC/CDP:H/TD:ND/CR:M/IR:ND/AR:ND", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(7.3)), // exp environmental score
        }, // exp
      ), (
        "ae619836 1.7", // test name
        "AV:N/AC:M/Au:S/C:P/I:N/A:C/E:POC/RL:W/RC:ND/CDP:MH/TD:L/CR:M/IR:L/AR:L", // vec
        Scores {
          base: Score::from(7.0), // exp base score
          temporal: Some(Score::from(6.0)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "159384a6 6.4", // test name
        "AV:N/AC:M/Au:S/C:P/I:N/A:N/E:POC/RL:ND/RC:UC/CDP:H/TD:H/CR:ND/IR:M/AR:ND", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(2.8)), // exp temporal score
          environmental: Some(Score::from(6.4)), // exp environmental score
        }, // exp
      ), (
        "4f7a5c0b 1.7", // test name
        "AV:N/AC:M/Au:S/C:P/I:N/A:N/E:U/RL:TF/RC:UC/CDP:N/TD:H/CR:L/IR:M/AR:L", // vec
        Scores {
          base: Score::from(3.5), // exp base score
          temporal: Some(Score::from(2.4)), // exp temporal score
          environmental: Some(Score::from(1.7)), // exp environmental score
        }, // exp
      ), (
        "e291d9a4 0.0", // test name
        "AV:N/AC:M/Au:S/C:P/I:N/A:P/E:ND/RL:ND/RC:UR/CDP:MH/TD:N/CR:ND/IR:H/AR:L", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.7)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ), (
        "6b487782 1.5", // test name
        "AV:N/AC:M/Au:S/C:P/I:N/A:P/E:U/RL:TF/RC:C/CDP:LM/TD:L/CR:ND/IR:L/AR:H", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(3.7)), // exp temporal score
          environmental: Some(Score::from(1.5)), // exp environmental score
        }, // exp
      ), (
        "35d13f0a 0.0", // test name
        "AV:N/AC:M/Au:S/C:P/I:P/A:N/E:F/RL:U/RC:UR/CDP:ND/TD:N/CR:M/IR:L/AR:ND", // vec
        Scores {
          base: Score::from(4.9), // exp base score
          temporal: Some(Score::from(4.4)), // exp temporal score
          environmental: Some(Score::from(0.0)), // exp environmental score
        }, // exp
      ));

      for (name, vs, exp) in tests {
        let vec: Vector = vs.parse().unwrap(); // parse vector
        let got = Scores::from(vec); // get scores
        assert_eq!(got, exp, "{}, {}", name, vec); // check result
      }
    }
  }
}
