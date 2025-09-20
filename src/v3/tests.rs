//! CVSS v3 tests

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
    // TODO: get more (and test temporal and env vectors)
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
    // TODO: get more (and test temporal and env vectors)
    let tests = vec!(
      (
        "CVE-2024-12345", // name
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", // val
        Scores {
          base: Score::from(4.4),
          temporal: None,
          environmental: Score::from(4.4),
        }, // exp
      ),

      (
        "CVE-2025-33053", // name
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", // val
        Scores {
          base: Score::from(8.8),
          temporal: None,
          environmental: Score::from(8.8),
        }, // exp
      ),
    );

    for (name, vs, exp) in tests {
      let vec: Vector = vs.parse().unwrap(); // parse vector
      let got = Scores::from(vec); // get scores
      assert_eq!(got, exp, "{name}, {vec}"); // check result
    }
  }
}
