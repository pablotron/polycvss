//! CVSS v2 tests.
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
