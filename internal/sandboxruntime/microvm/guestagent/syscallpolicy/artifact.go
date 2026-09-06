package syscallpolicy

const (
	MaxVerifiedPolicyArtifactBytes         = 4194304
	MaxPolicyCatalogEntries                = 512
	MaxPolicyRules                         = 8192
	MaxPolicyRulesPerRole                  = 2048
	MaxPolicyStagesPerRole                 = 16
	MaxPolicyTransitionsPerRole            = 64
	MaxPolicyScalarClausesPerRule          = 6
	MaxPolicyDescriptorRequirementsPerRule = 6
	MaxPolicyPointerRequirementsPerRule    = 6
	MaxPolicyObjectRequirementsPerRule     = 6
	MaxPinnedCallsiteRequirementsPerRule   = 6
	MaxPinnedCallsiteEvidenceBytes         = 16777216
	MaxPinnedCallsiteEvidenceRecords       = 49152
	MaxPinnedBinaryBindings                = 32
	MaxPolicyScalarValuesPerClause         = 8
	MaxPolicyNameBytes                     = 64
	MaxScalarPredicateSearchStates         = 4194304
	MaxAdapterBindings                     = 32
)

type expectedIssuer struct{ issued bool }

// ExpectedPolicyArtifact is constructible only by a generated same-package D7
// issuer or package tests.
type ExpectedPolicyArtifact struct {
	sha256 [32]byte
	issuer expectedIssuer
}

type artifactSection struct {
	typ       uint8
	itemCount uint16
	sha256    [32]byte
	body      []byte
}

type mandatoryEvidence struct {
	kind            EvidenceKind
	attachmentIndex uint16
	requiredChecks  CheckSet
}

type catalogEntry struct {
	number            SyscallNumber
	name              string
	class             SyscallClass
	mandatoryEvidence []*mandatoryEvidence
}

type ancestryRecord struct {
	ancestorRole Role
	unionSHA256  [32]byte
	descendants  []Role
}

type roleStage struct {
	role            Role
	stage           Stage
	requiredFacts   StateFact
	prohibitedFacts StateFact
}

type verifiedTransition struct {
	role            Role
	from            Stage
	toRole          Role
	to              Stage
	requiredFacts   StateFact
	prohibitedFacts StateFact
	setFacts        StateFact
	clearFacts      StateFact
	sha256          [32]byte
}

type descriptorRequirement struct {
	argumentIndex    uint8
	kind             DescriptorKind
	access           DescriptorAccess
	fixed            bool
	requiredChecks   CheckSet
	generationSHA256 [32]byte
	generationMode   GenerationMode
	bindingSlot      uint8
}

type pointerRequirement struct {
	argumentIndex  uint8
	class          PointerClass
	minimumBytes   uint32
	maximumBytes   uint32
	requiredChecks CheckSet
}

type objectRequirement struct {
	argumentIndex    uint8
	source           ObjectSource
	kind             DescriptorKind
	access           DescriptorAccess
	fixed            bool
	requiredChecks   CheckSet
	generationSHA256 [32]byte
	generationMode   GenerationMode
	bindingSlot      uint8
}

type verifiedRule struct {
	role            Role
	stage           Stage
	origin          RuleOrigin
	enforcementPath EnforcementPath
	requiredFacts   StateFact
	prohibitedFacts StateFact
	stateChecks     CheckSet
	syscallNumber   SyscallNumber
	scalarClauses   []*scalarClause
	descriptors     []*descriptorRequirement
	pointers        []*pointerRequirement
	objects         []*objectRequirement
	pinnedCallsites []*pinnedCallsiteRequirement
	adapterFailure  AdapterOutcome
	sha256          [32]byte
	encoded         []byte
}

type RuleView struct{ rule *verifiedRule }
type TransitionView struct{ transition *verifiedTransition }
type DescriptorRequirementView struct{ requirement *descriptorRequirement }
type PointerRequirementView struct{ requirement *pointerRequirement }
type ObjectRequirementView struct{ requirement *objectRequirement }
type WorkloadRuleView struct{ rule RuleView }
type WorkloadSnapshot struct {
	sha256     [32]byte
	sourceLock [32]byte
	l4         [32]byte
	l7         [32]byte
	rules      []WorkloadRuleView
}
type RuntimeProfileView struct {
	goVersion  string
	sha256     [32]byte
	source     [32]byte
	sourceLock [32]byte
	rules      []RuleView
}

type MandatoryEvidenceView struct{ evidence *mandatoryEvidence }
type CatalogEntryView struct{ entry *catalogEntry }

type verifiedArtifact struct {
	verified            bool
	encoded             []byte
	sha256              [32]byte
	catalogSourceSHA256 [32]byte
	sourceLockSHA256    [32]byte
	sections            [6]artifactSection
	catalog             []*catalogEntry
	ancestry            [2]ancestryRecord
	workload            WorkloadSnapshot
	workloadRuleIndexes []uint32
	runtime             RuntimeProfileView
	runtimeRuleIndexes  []uint32
	provenance          [11][32]byte
	pinnedCallsites     []*pinnedCallsiteRequirement
	stages              map[Role]map[Stage]roleStage
	rules               []*verifiedRule
	transitions         []*verifiedTransition
	roleSections        map[Role][]byte
}

type pinnedCallsiteRequirement struct {
	role                      Role
	origin                    RuleOrigin
	callsiteOrdinal           uint16
	pointerClass              PointerClass
	minimumBytes              uint32
	maximumBytes              uint32
	requiredChecks            CheckSet
	instructionLength         uint16
	sourceUnitSHA256          [32]byte
	argumentTemplateSHA256    [32]byte
	instructionTemplateSHA256 [32]byte
	toolchainSHA256           [32]byte
	sha256                    [32]byte
}

type PinnedCallsiteRequirementView struct{ requirement *pinnedCallsiteRequirement }

func (requirement PinnedCallsiteRequirementView) CallsiteOrdinal() uint16 {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.callsiteOrdinal
}
func (requirement PinnedCallsiteRequirementView) PointerClass() PointerClass {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.pointerClass
}
func (requirement PinnedCallsiteRequirementView) MinimumBytes() uint32 {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.minimumBytes
}
func (requirement PinnedCallsiteRequirementView) MaximumBytes() uint32 {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.maximumBytes
}
func (requirement PinnedCallsiteRequirementView) RequiredChecks() CheckSet {
	if requirement.requirement == nil {
		return CheckSet{}
	}
	return requirement.requirement.requiredChecks
}
func (requirement PinnedCallsiteRequirementView) InstructionLength() uint16 {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.instructionLength
}
func (requirement PinnedCallsiteRequirementView) SourceUnitSHA256() [32]byte {
	if requirement.requirement == nil {
		return [32]byte{}
	}
	return requirement.requirement.sourceUnitSHA256
}
func (requirement PinnedCallsiteRequirementView) ArgumentTemplateSHA256() [32]byte {
	if requirement.requirement == nil {
		return [32]byte{}
	}
	return requirement.requirement.argumentTemplateSHA256
}
func (requirement PinnedCallsiteRequirementView) InstructionTemplateSHA256() [32]byte {
	if requirement.requirement == nil {
		return [32]byte{}
	}
	return requirement.requirement.instructionTemplateSHA256
}
func (requirement PinnedCallsiteRequirementView) ToolchainSHA256() [32]byte {
	if requirement.requirement == nil {
		return [32]byte{}
	}
	return requirement.requirement.toolchainSHA256
}
func (requirement PinnedCallsiteRequirementView) SHA256() [32]byte {
	if requirement.requirement == nil {
		return [32]byte{}
	}
	return requirement.requirement.sha256
}

// VerifiedPolicyArtifact is a closed issuance value. The full D7 canonical
// artifact importer owns creation; zero remains invalid.
type VerifiedPolicyArtifact struct {
	sha256   [32]byte
	artifact *verifiedArtifact
}

func (expected ExpectedPolicyArtifact) SHA256() [32]byte { return expected.sha256 }
func (artifact VerifiedPolicyArtifact) SHA256() [32]byte { return artifact.sha256 }

// SourceLockSHA256 returns the verified source-lock authority bound by the
// canonical artifact header. A zero or foreign artifact returns zero.
func (artifact VerifiedPolicyArtifact) SourceLockSHA256() [32]byte {
	if artifact.artifact == nil {
		return [32]byte{}
	}
	return artifact.artifact.sourceLockSHA256
}

// Catalog returns defensive immutable views over the verified pinned catalog.
func (artifact VerifiedPolicyArtifact) Catalog() []CatalogEntryView {
	if artifact.artifact == nil {
		return nil
	}
	result := make([]CatalogEntryView, len(artifact.artifact.catalog))
	for index, entry := range artifact.artifact.catalog {
		result[index] = CatalogEntryView{entry: entry}
	}
	return result
}

func (artifact VerifiedPolicyArtifact) Rules() []RuleView {
	if artifact.artifact == nil {
		return nil
	}
	result := make([]RuleView, len(artifact.artifact.rules))
	for index, rule := range artifact.artifact.rules {
		result[index] = RuleView{rule: rule}
	}
	return result
}

func (artifact VerifiedPolicyArtifact) Transitions() []TransitionView {
	if artifact.artifact == nil {
		return nil
	}
	result := make([]TransitionView, len(artifact.artifact.transitions))
	for index, transition := range artifact.artifact.transitions {
		result[index] = TransitionView{transition: transition}
	}
	return result
}

func (artifact VerifiedPolicyArtifact) Workload() WorkloadSnapshot {
	if artifact.artifact == nil {
		return WorkloadSnapshot{}
	}
	result := artifact.artifact.workload
	result.rules = append([]WorkloadRuleView(nil), artifact.artifact.workload.rules...)
	return result
}

func (artifact VerifiedPolicyArtifact) Runtime() RuntimeProfileView {
	if artifact.artifact == nil {
		return RuntimeProfileView{}
	}
	result := artifact.artifact.runtime
	result.rules = append([]RuleView(nil), artifact.artifact.runtime.rules...)
	return result
}

func (snapshot WorkloadSnapshot) SHA256() [32]byte           { return snapshot.sha256 }
func (snapshot WorkloadSnapshot) SourceLockSHA256() [32]byte { return snapshot.sourceLock }
func (snapshot WorkloadSnapshot) L4SHA256() [32]byte         { return snapshot.l4 }
func (snapshot WorkloadSnapshot) L7SHA256() [32]byte         { return snapshot.l7 }
func (snapshot WorkloadSnapshot) Rules() []WorkloadRuleView {
	return append([]WorkloadRuleView(nil), snapshot.rules...)
}
func (rule WorkloadRuleView) Rule() RuleView { return rule.rule }

func (profile RuntimeProfileView) GoVersion() string          { return profile.goVersion }
func (profile RuntimeProfileView) SHA256() [32]byte           { return profile.sha256 }
func (profile RuntimeProfileView) SourceSHA256() [32]byte     { return profile.source }
func (profile RuntimeProfileView) SourceLockSHA256() [32]byte { return profile.sourceLock }
func (profile RuntimeProfileView) Rules() []RuleView {
	return append([]RuleView(nil), profile.rules...)
}

func (rule RuleView) Role() Role {
	if rule.rule == nil {
		return 0
	}
	return rule.rule.role
}
func (rule RuleView) Stage() Stage {
	if rule.rule == nil {
		return 0
	}
	return rule.rule.stage
}
func (rule RuleView) Origin() RuleOrigin {
	if rule.rule == nil {
		return 0
	}
	return rule.rule.origin
}
func (rule RuleView) EnforcementPath() EnforcementPath {
	if rule.rule == nil {
		return 0
	}
	return rule.rule.enforcementPath
}
func (rule RuleView) RequiredFacts() StateFact {
	if rule.rule == nil {
		return 0
	}
	return rule.rule.requiredFacts
}
func (rule RuleView) ProhibitedFacts() StateFact {
	if rule.rule == nil {
		return 0
	}
	return rule.rule.prohibitedFacts
}
func (rule RuleView) StateChecks() CheckSet {
	if rule.rule == nil {
		return CheckSet{}
	}
	return rule.rule.stateChecks
}
func (rule RuleView) SyscallNumber() SyscallNumber {
	if rule.rule == nil {
		return 0
	}
	return rule.rule.syscallNumber
}
func (rule RuleView) ScalarClauses() []ScalarClauseView {
	if rule.rule == nil {
		return nil
	}
	result := make([]ScalarClauseView, len(rule.rule.scalarClauses))
	for index, clause := range rule.rule.scalarClauses {
		result[index] = ScalarClauseView{clause: clause}
	}
	return result
}
func (rule RuleView) DescriptorRequirements() []DescriptorRequirementView {
	if rule.rule == nil {
		return nil
	}
	result := make([]DescriptorRequirementView, len(rule.rule.descriptors))
	for index, requirement := range rule.rule.descriptors {
		result[index] = DescriptorRequirementView{requirement: requirement}
	}
	return result
}
func (rule RuleView) PointerRequirements() []PointerRequirementView {
	if rule.rule == nil {
		return nil
	}
	result := make([]PointerRequirementView, len(rule.rule.pointers))
	for index, requirement := range rule.rule.pointers {
		result[index] = PointerRequirementView{requirement: requirement}
	}
	return result
}
func (rule RuleView) ObjectRequirements() []ObjectRequirementView {
	if rule.rule == nil {
		return nil
	}
	result := make([]ObjectRequirementView, len(rule.rule.objects))
	for index, requirement := range rule.rule.objects {
		result[index] = ObjectRequirementView{requirement: requirement}
	}
	return result
}
func (rule RuleView) PinnedCallsiteRequirements() []PinnedCallsiteRequirementView {
	if rule.rule == nil {
		return nil
	}
	result := make([]PinnedCallsiteRequirementView, len(rule.rule.pinnedCallsites))
	for index, requirement := range rule.rule.pinnedCallsites {
		result[index] = PinnedCallsiteRequirementView{requirement: requirement}
	}
	return result
}
func (rule RuleView) AdapterFailure() AdapterOutcome {
	if rule.rule == nil {
		return 0
	}
	return rule.rule.adapterFailure
}
func (rule RuleView) SHA256() [32]byte {
	if rule.rule == nil {
		return [32]byte{}
	}
	return rule.rule.sha256
}

func (requirement DescriptorRequirementView) ArgumentIndex() uint8 {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.argumentIndex
}
func (requirement DescriptorRequirementView) Kind() DescriptorKind {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.kind
}
func (requirement DescriptorRequirementView) Access() DescriptorAccess {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.access
}
func (requirement DescriptorRequirementView) Fixed() bool {
	return requirement.requirement != nil && requirement.requirement.fixed
}
func (requirement DescriptorRequirementView) RequiredChecks() CheckSet {
	if requirement.requirement == nil {
		return CheckSet{}
	}
	return requirement.requirement.requiredChecks
}
func (requirement DescriptorRequirementView) GenerationSHA256() [32]byte {
	if requirement.requirement == nil {
		return [32]byte{}
	}
	return requirement.requirement.generationSHA256
}
func (requirement DescriptorRequirementView) GenerationMode() GenerationMode {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.generationMode
}
func (requirement DescriptorRequirementView) BindingSlot() uint8 {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.bindingSlot
}

func (requirement PointerRequirementView) ArgumentIndex() uint8 {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.argumentIndex
}
func (requirement PointerRequirementView) Class() PointerClass {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.class
}
func (requirement PointerRequirementView) MinimumBytes() uint32 {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.minimumBytes
}
func (requirement PointerRequirementView) MaximumBytes() uint32 {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.maximumBytes
}
func (requirement PointerRequirementView) RequiredChecks() CheckSet {
	if requirement.requirement == nil {
		return CheckSet{}
	}
	return requirement.requirement.requiredChecks
}

func (requirement ObjectRequirementView) ArgumentIndex() uint8 {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.argumentIndex
}
func (requirement ObjectRequirementView) Source() ObjectSource {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.source
}
func (requirement ObjectRequirementView) Kind() DescriptorKind {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.kind
}
func (requirement ObjectRequirementView) Access() DescriptorAccess {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.access
}
func (requirement ObjectRequirementView) Fixed() bool {
	return requirement.requirement != nil && requirement.requirement.fixed
}
func (requirement ObjectRequirementView) RequiredChecks() CheckSet {
	if requirement.requirement == nil {
		return CheckSet{}
	}
	return requirement.requirement.requiredChecks
}
func (requirement ObjectRequirementView) GenerationSHA256() [32]byte {
	if requirement.requirement == nil {
		return [32]byte{}
	}
	return requirement.requirement.generationSHA256
}
func (requirement ObjectRequirementView) GenerationMode() GenerationMode {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.generationMode
}
func (requirement ObjectRequirementView) BindingSlot() uint8 {
	if requirement.requirement == nil {
		return 0
	}
	return requirement.requirement.bindingSlot
}

func (transition TransitionView) Role() Role {
	if transition.transition == nil {
		return 0
	}
	return transition.transition.role
}
func (transition TransitionView) From() Stage {
	if transition.transition == nil {
		return 0
	}
	return transition.transition.from
}
func (transition TransitionView) ToRole() Role {
	if transition.transition == nil {
		return 0
	}
	return transition.transition.toRole
}
func (transition TransitionView) To() Stage {
	if transition.transition == nil {
		return 0
	}
	return transition.transition.to
}
func (transition TransitionView) RequiredFacts() StateFact {
	if transition.transition == nil {
		return 0
	}
	return transition.transition.requiredFacts
}
func (transition TransitionView) ProhibitedFacts() StateFact {
	if transition.transition == nil {
		return 0
	}
	return transition.transition.prohibitedFacts
}
func (transition TransitionView) SetFacts() StateFact {
	if transition.transition == nil {
		return 0
	}
	return transition.transition.setFacts
}
func (transition TransitionView) ClearFacts() StateFact {
	if transition.transition == nil {
		return 0
	}
	return transition.transition.clearFacts
}
func (transition TransitionView) SHA256() [32]byte {
	if transition.transition == nil {
		return [32]byte{}
	}
	return transition.transition.sha256
}

func (entry CatalogEntryView) Number() SyscallNumber {
	if entry.entry == nil {
		return 0
	}
	return entry.entry.number
}

func (entry CatalogEntryView) Name() string {
	if entry.entry == nil {
		return ""
	}
	return entry.entry.name
}

func (entry CatalogEntryView) Class() SyscallClass {
	if entry.entry == nil {
		return 0
	}
	return entry.entry.class
}

func (entry CatalogEntryView) MandatoryEvidence() []MandatoryEvidenceView {
	if entry.entry == nil {
		return nil
	}
	result := make([]MandatoryEvidenceView, len(entry.entry.mandatoryEvidence))
	for index, evidence := range entry.entry.mandatoryEvidence {
		result[index] = MandatoryEvidenceView{evidence: evidence}
	}
	return result
}

func (evidence MandatoryEvidenceView) Kind() EvidenceKind {
	if evidence.evidence == nil {
		return 0
	}
	return evidence.evidence.kind
}

func (evidence MandatoryEvidenceView) AttachmentIndex() uint16 {
	if evidence.evidence == nil {
		return 0
	}
	return evidence.evidence.attachmentIndex
}

func (evidence MandatoryEvidenceView) RequiredChecks() CheckSet {
	if evidence.evidence == nil {
		return CheckSet{}
	}
	return evidence.evidence.requiredChecks
}
