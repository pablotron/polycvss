//! [CVSS v2][doc] vector parser.
//!
//! Parse a [CVSS v2 vector string][vector-string] into a [`Vector`][].
//!
//! # Examples
//!
//! Parse [vector string][vector-string], then get a [`Metric`][] by [`Name`][]:
//!
//! ```
//! # use polycvss::cvss::{Err, v2::{AccessVector, Vector, Metric, Name}};
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
//! Parse [vector string][vector-string], then build a list of metric
//! [`Name`s][Name]:
//!
//! ```
//! # use polycvss::cvss::{Err, v2::{Name, Vector}};
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
//! Get base score for [CVSS v2][doc] vector:
//!
//! ```
//! # use polycvss::cvss::{Err, Score, v2::Vector};
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

use serde::{self,Deserialize,Serialize};
use super::{Err, Score, round1, Version, encode::{EncodedVal, EncodedMetric}};

// TODO:
// - remove panic() from masks (marked w/FIXME)
// - remove ajusted fields from Scores?
// - non-v2.3 vectors (e.g. Vector::new_with_version)

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
/// # use polycvss::cvss::{Err, v2::{AccessVector, Metric}};
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
/// # use polycvss::cvss::v2::{AccessVector, Metric};
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
/// # use polycvss::cvss::v2::{AccessVector, Metric, Name};
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
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
#[serde(rename_all = "UPPERCASE")]
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
/// # use polycvss::cvss::{Err, v2::{AccessComplexity, Metric}};
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
/// # use polycvss::cvss::v2::{AccessComplexity, Metric};
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
/// # use polycvss::cvss::v2::{AccessComplexity, Metric, Name};
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
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
#[serde(rename_all = "UPPERCASE")]
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
/// # use polycvss::cvss::{Err, v2::{Authentication, Metric}};
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
/// # use polycvss::cvss::v2::{Authentication, Metric};
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
/// # use polycvss::cvss::v2::{Authentication, Metric, Name};
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
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
#[serde(rename_all = "UPPERCASE")]
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
/// # use polycvss::cvss::{Err, v2::{Impact, Metric}};
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
/// # use polycvss::cvss::v2::{Impact, Metric};
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
/// # use polycvss::cvss::v2::{Impact, Metric, Name};
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
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
#[serde(rename_all = "UPPERCASE")]
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
/// # use polycvss::cvss::{Err, v2::{Exploitability, Metric}};
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
/// # use polycvss::cvss::v2::{Exploitability, Metric};
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
/// # use polycvss::cvss::v2::{Exploitability, Metric, Name};
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
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
#[serde(rename_all = "UPPERCASE")]
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
/// # use polycvss::cvss::{Err, v2::{RemediationLevel, Metric}};
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
/// # use polycvss::cvss::v2::{RemediationLevel, Metric};
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
/// # use polycvss::cvss::v2::{RemediationLevel, Metric, Name};
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
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
#[serde(rename_all = "UPPERCASE")]
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
/// # use polycvss::cvss::{Err, v2::{ReportConfidence, Metric}};
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
/// # use polycvss::cvss::v2::{ReportConfidence, Metric};
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
/// # use polycvss::cvss::v2::{ReportConfidence, Metric, Name};
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
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
#[serde(rename_all = "UPPERCASE")]
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
/// # use polycvss::cvss::{Err, v2::{CollateralDamagePotential, Metric}};
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
/// # use polycvss::cvss::v2::{CollateralDamagePotential, Metric};
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
/// # use polycvss::cvss::v2::{CollateralDamagePotential, Metric, Name};
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
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
#[serde(rename_all = "UPPERCASE")]
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
/// # use polycvss::cvss::{Err, v2::{TargetDistribution, Metric}};
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
/// # use polycvss::cvss::v2::{TargetDistribution, Metric};
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
/// # use polycvss::cvss::v2::{TargetDistribution, Metric, Name};
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
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
#[serde(rename_all = "UPPERCASE")]
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
/// # use polycvss::cvss::{Err, v2::{Requirement, Metric}};
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
/// # use polycvss::cvss::v2::{Requirement, Metric};
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
/// # use polycvss::cvss::v2::{Requirement, Metric, Name};
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
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
#[serde(rename_all = "UPPERCASE")]
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
/// # use polycvss::cvss::v2::{Group, Name};
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
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
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
/// # use polycvss::cvss::v2::{AccessVector, Metric, Name};
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
/// # use polycvss::cvss::v2::{AccessVector, Name};
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
  /// # use polycvss::cvss::v2::{AccessVector, Name};
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
/// # use polycvss::cvss::{Err, v2::{AccessVector, Metric}};
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
/// # use polycvss::cvss::v2::{AccessVector, Metric};
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
/// # use polycvss::cvss::v2::{AccessVector, Metric, Name};
/// # fn main() {
/// // get metric name
/// let name = Name::from(Metric::AccessVector(AccessVector::Local));
///
/// // check result
/// assert_eq!(name, Name::AccessVector);
/// # }
/// ```
#[derive(Clone,Copy,Debug,Deserialize,PartialEq,Serialize)]
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
  /// # use polycvss::cvss::{Err, v2::{AccessVector, Metric}};
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
  /// # use polycvss::cvss::v2::{AccessVector, Metric};
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
  /// # use polycvss::cvss::v2::{AccessVector, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{AccessComplexity, Metric}};
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
  /// # use polycvss::cvss::v2::{AccessComplexity, Metric};
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
  /// # use polycvss::cvss::v2::{AccessComplexity, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{Authentication, Metric}};
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
  /// # use polycvss::cvss::v2::{Authentication, Metric};
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
  /// # use polycvss::cvss::v2::{Authentication, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{Impact, Metric}};
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
  /// # use polycvss::cvss::v2::{Impact, Metric};
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
  /// # use polycvss::cvss::v2::{Impact, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{Impact, Metric}};
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
  /// # use polycvss::cvss::v2::{Impact, Metric};
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
  /// # use polycvss::cvss::v2::{Impact, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{Impact, Metric}};
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
  /// # use polycvss::cvss::v2::{Impact, Metric};
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
  /// # use polycvss::cvss::v2::{Impact, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{Exploitability, Metric}};
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
  /// # use polycvss::cvss::v2::{Exploitability, Metric};
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
  /// # use polycvss::cvss::v2::{Exploitability, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{RemediationLevel, Metric}};
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
  /// # use polycvss::cvss::v2::{RemediationLevel, Metric};
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
  /// # use polycvss::cvss::v2::{RemediationLevel, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{ReportConfidence, Metric}};
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
  /// # use polycvss::cvss::v2::{ReportConfidence, Metric};
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
  /// # use polycvss::cvss::v2::{ReportConfidence, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{CollateralDamagePotential, Metric}};
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
  /// # use polycvss::cvss::v2::{CollateralDamagePotential, Metric};
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
  /// # use polycvss::cvss::v2::{CollateralDamagePotential, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{TargetDistribution, Metric}};
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
  /// # use polycvss::cvss::v2::{TargetDistribution, Metric};
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
  /// # use polycvss::cvss::v2::{TargetDistribution, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{Requirement, Metric}};
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
  /// # use polycvss::cvss::v2::{Requirement, Metric};
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
  /// # use polycvss::cvss::v2::{Requirement, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{Requirement, Metric}};
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
  /// # use polycvss::cvss::v2::{Requirement, Metric};
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
  /// # use polycvss::cvss::v2::{Requirement, Metric, Name};
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
  /// # use polycvss::cvss::{Err, v2::{Requirement, Metric}};
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
  /// # use polycvss::cvss::v2::{Requirement, Metric};
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
  /// # use polycvss::cvss::v2::{Requirement, Metric, Name};
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
/// # use polycvss::cvss::{Err, v2::{AccessVector, AccessComplexity, Authentication, Impact, Metric, Vector}};
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
/// # use polycvss::cvss::{Err, v2::{AccessVector, AccessComplexity, Authentication, Impact, Metric, Vector}};
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
/// # use polycvss::cvss::{Err, v2::{AccessVector, Metric, Vector}};
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
            _ => panic!("invalid length"),
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
/// # use polycvss::cvss::{Err, v2::Vector};
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
/// # use polycvss::cvss::{Err, v2::{Scores, Vector}};
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
/// # use polycvss::cvss::{Err, v2::Vector};
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
/// # use polycvss::cvss::{Err, v2::{AccessVector, Vector, Metric, Name}};
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
/// # use polycvss::cvss::{Err, v2::Vector};
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
/// # use polycvss::cvss::{Err, v2::Vector};
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
/// # use polycvss::cvss::v2::Vector;
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
// #[derive(Debug,Deserialize,PartialEq,Serialize)]
// #[serde(try_from = "String")]
#[derive(Clone,Copy,Debug,PartialEq)]
pub struct Vector(u64);

impl Vector {
  /// Get [`Metric`][] from [`Vector`][] by [`Name`][].
  ///
  /// # Examples
  ///
  /// Get metric from vector:
  ///
  /// ```
  /// # use polycvss::cvss::{Err, v2::{AccessVector, Vector, Metric, Name}};
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
  /// # use polycvss::cvss::{Err, v2::{Requirement, Vector, Metric, Name}};
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
          _ => panic!("invalid length"), // FIXME
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
        EncodedVal::Shift(v) => val |= v, // PoT value
        _ => unreachable!(), // non-PoT value FIXME
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
            _ => panic!("invalid length"), // FIXME
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
/// # use polycvss::cvss::{Err, v2::{Scores, Vector}};
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

  /// Adjusted Impact.  Intermediate value used to calculate Environmental Score.
  ///
  /// See [CVSS v2.0 Documentation, Section 3.2.3. Environmental Equation][doc].
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#3-2-3-Environmental-Equation
  ///   "CVSS v2.0 Documentation, Section 3.2.3. Environmental Equation"
  pub adjusted_impact: Score,

  /// Adjusted Base Score.  Intermediate value used to calculate Environmental Score.
  ///
  /// See [CVSS v2.0 Documentation, Section 3.2.3. Environmental Equation][doc].
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#3-2-3-Environmental-Equation
  ///   "CVSS v2.0 Documentation, Section 3.2.3. Environmental Equation"
  pub adjusted_base: Score,

  /// Adjusted Base Temporal Score.
  ///
  /// Intermediate value used to calculate Environmental Score.
  ///
  /// See [CVSS v2.0 Documentation, Section 3.2.3. Environmental Equation][doc].
  ///
  /// [doc]: https://www.first.org/cvss/v2/guide#3-2-3-Environmental-Equation
  ///   "CVSS v2.0 Documentation, Section 3.2.3. Environmental Equation"
  pub adjusted_temporal: Option<Score>,

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
    let adj_base_score = round1(((0.6 * adj_impact) + (0.4 * exploitability) - 1.5) * f_adj_impact);

    // AdjustedTemporal = TemporalScore recomputed with the BaseScore's Impact sub-
    // equation replaced with the AdjustedImpact equation
    let adj_temporal_score = if has_temporal_metrics {
      Some(round1(adj_base_score * e * rl * rc))
    } else {
      None
    };

    // EnvironmentalScore = round_to_1_decimal((AdjustedTemporal+
    // (10-AdjustedTemporal)*CollateralDamagePotential)*TargetDistribution)
    let env_score = adj_temporal_score.map(|val| round1((val + (10.0 - val)*cdp)*td));

    Scores {
      base: Score::from(base_score),
      temporal: temporal_score.map(Score::from),
      adjusted_impact: Score::from(adj_impact),
      adjusted_base: Score::from(adj_base_score),
      adjusted_temporal: adj_temporal_score.map(Score::from),
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

        // TODO
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
            adjusted_impact: Score(100),
            adjusted_base: Score(100),
            adjusted_temporal: Some(Score(83)),
            environmental: Some(Score(0)),
          }, // exp
        ),

        (
          "3.3.1, CVE-2002-0392, high", // name
          "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H", // val
          Scores {
            base: Score(78),
            temporal: Some(Score(64)),
            adjusted_impact: Score(100),
            adjusted_base: Score(100),
            adjusted_temporal: Some(Score(83)),
            environmental: Some(Score(92)),
          }, // exp
        ),

        (
          "3.3.2. CVE-2003-0818, low", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:L", // val
          Scores {
            base: Score(100),
            temporal: Some(Score(83)),
            adjusted_impact: Score(96),
            adjusted_base: Score(97),
            adjusted_temporal: Some(Score(80)),
            environmental: Some(Score(0)),
          }, // exp
        ),

        (
          "3.3.2. CVE-2003-0818, high", // name
          "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L", // val
          Scores {
            base: Score(100),
            temporal: Some(Score(83)),
            adjusted_impact: Score(96),
            adjusted_base: Score(97),
            adjusted_temporal: Some(Score(80)),
            environmental: Some(Score(90)),
          }, // exp
        ),

        (
          "3.3.3. CVE-2003-0062, low", // name
          "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:M", // val
          Scores {
            base: Score(62),
            temporal: Some(Score(49)),
            adjusted_impact: Score(100),
            adjusted_base: Score(62),
            adjusted_temporal: Some(Score(49)),
            environmental: Some(Score(0)),
          }, // exp
        ),

        (
          "3.3.3. CVE-2003-0062, high", // name
          "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M", // val
          Scores {
            base: Score(62),
            temporal: Some(Score(49)),
            adjusted_impact: Score(100),
            adjusted_base: Score(62),
            adjusted_temporal: Some(Score(49)),
            environmental: Some(Score(75)),
          }, // exp
        ),
      );

      for (name, vs, exp) in tests {
        let vec: Vector = vs.parse().unwrap(); // parse vector
        let got = Scores::from(vec); // get scores
        assert_eq!(got, exp, "{}, {}", name, vec); // check result
      }
    }
  }
}
