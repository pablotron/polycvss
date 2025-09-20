//! CVSS v4 tests.

mod group {
  use super::super::{Name, Group};

  #[test]
  fn test_from_name() {
    let tests = vec!(
      (Name::AttackVector, Group::Base),
      (Name::ExploitMaturity, Group::Threat),
      (Name::ConfidentialityRequirement, Group::Environmental),
      (Name::Safety, Group::Supplementary),
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
      (Group::Supplementary, "Supplementary"),
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

    for t in tests {
      assert_eq!(t.1.parse::<Name>(), Err(t.2), "{}", t.0);
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

    for t in tests {
      assert_eq!(t.0.parse::<Name>(), Ok(t.1), "{}", t.0);
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

    for t in tests {
      assert_eq!(t.0.to_string(), t.1, "{}", t.1);
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

    for t in tests {
      assert_eq!(t.1.parse::<Metric>(), Err(t.2), "{}", t.0);
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

    for t in tests {
      assert_eq!(t.0.parse::<Metric>().unwrap(), t.1);
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

    for t in tests {
      assert_eq!(t.0.to_string(), t.1);
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

    for t in tests {
      assert_eq!(t.1.parse::<Vector>(), Err(t.2), "{}", t.0);
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

    for t in tests {
      assert_eq!(t.1.parse::<Vector>().expect(t.0).to_string(), t.2, "{}", t.0);
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

    for t in tests {
      let got: Vec<Metric> = t.1.parse::<Vector>().unwrap().into_iter().collect();
      assert_eq!(got, t.2, "{}", t.0);
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

    for t in tests {
      let mut got: Vec<Metric> = Vec::new();
      for c in t.1.parse::<Vector>().unwrap() {
        got.push(c);
      }
      assert_eq!(got, t.2, "{}", t.0);
    }
  }

  #[test]
  fn test_from_vector() {
    let vec: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".parse().unwrap();
    assert_eq!(Version::from(vec), Version::V40);
  }

  #[test]
  fn test_distance() {
    let tests = vec!((
      "empty mask", // name
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // a
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // b
      0b00, // mask
      0, // exp
    ), (
      "AV:N to AV:N (same)", // name
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // a
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // b
      0b01, // mask
      0, // exp
    ), (
      "AV:N to AV:A (one)", // name
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // a
      "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // b
      0b01, // mask
      1, // exp
    ), (
      "AV:N to AV:L (two)", // name
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // a
      "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // b
      0b01, // mask
      2, // exp
    ), (
      "AV:N/AC:L to AV:N/AC:L (same)", // name
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // a
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // b
      0b11, // mask
      0, // exp
    ), (
      "AV:N/AC:L to AV:L/AC:H", // name
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // a
      "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // b
      0b11, // mask
      3, // exp
    ));

    for (name, avs, bvs, mask, exp) in tests {
      let a: Vector = avs.parse().unwrap();
      let b: Vector = bvs.parse().unwrap();
      let got = a.distance(&b, mask);
      assert_eq!(got, exp, "{name}");
    }
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
