package syscallpolicy

import "fmt"

func (WorkloadSnapshot) String() string                 { return opaqueFormat }
func (WorkloadSnapshot) GoString() string               { return opaqueFormat }
func (WorkloadSnapshot) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (WorkloadSnapshot) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (WorkloadSnapshot) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (WorkloadSnapshot) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*WorkloadSnapshot) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*WorkloadSnapshot) UnmarshalText([]byte) error    { return opaqueError() }
func (*WorkloadSnapshot) UnmarshalBinary([]byte) error  { return opaqueError() }

func (WorkloadRuleView) String() string                 { return opaqueFormat }
func (WorkloadRuleView) GoString() string               { return opaqueFormat }
func (WorkloadRuleView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (WorkloadRuleView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (WorkloadRuleView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (WorkloadRuleView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*WorkloadRuleView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*WorkloadRuleView) UnmarshalText([]byte) error    { return opaqueError() }
func (*WorkloadRuleView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (RuntimeProfileView) String() string                 { return opaqueFormat }
func (RuntimeProfileView) GoString() string               { return opaqueFormat }
func (RuntimeProfileView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (RuntimeProfileView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (RuntimeProfileView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (RuntimeProfileView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*RuntimeProfileView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*RuntimeProfileView) UnmarshalText([]byte) error    { return opaqueError() }
func (*RuntimeProfileView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (CatalogEntryView) String() string                 { return opaqueFormat }
func (CatalogEntryView) GoString() string               { return opaqueFormat }
func (CatalogEntryView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (CatalogEntryView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (CatalogEntryView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (CatalogEntryView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*CatalogEntryView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*CatalogEntryView) UnmarshalText([]byte) error    { return opaqueError() }
func (*CatalogEntryView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (MandatoryEvidenceView) String() string                 { return opaqueFormat }
func (MandatoryEvidenceView) GoString() string               { return opaqueFormat }
func (MandatoryEvidenceView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (MandatoryEvidenceView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (MandatoryEvidenceView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (MandatoryEvidenceView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*MandatoryEvidenceView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*MandatoryEvidenceView) UnmarshalText([]byte) error    { return opaqueError() }
func (*MandatoryEvidenceView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (RuleView) String() string                 { return opaqueFormat }
func (RuleView) GoString() string               { return opaqueFormat }
func (RuleView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (RuleView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (RuleView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (RuleView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*RuleView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*RuleView) UnmarshalText([]byte) error    { return opaqueError() }
func (*RuleView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (FilterRuleView) String() string                 { return opaqueFormat }
func (FilterRuleView) GoString() string               { return opaqueFormat }
func (FilterRuleView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (FilterRuleView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (FilterRuleView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (FilterRuleView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*FilterRuleView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*FilterRuleView) UnmarshalText([]byte) error    { return opaqueError() }
func (*FilterRuleView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (FilterProfile) String() string                 { return opaqueFormat }
func (FilterProfile) GoString() string               { return opaqueFormat }
func (FilterProfile) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (FilterProfile) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (FilterProfile) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (FilterProfile) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*FilterProfile) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*FilterProfile) UnmarshalText([]byte) error    { return opaqueError() }
func (*FilterProfile) UnmarshalBinary([]byte) error  { return opaqueError() }

func (ScalarClauseView) String() string                 { return opaqueFormat }
func (ScalarClauseView) GoString() string               { return opaqueFormat }
func (ScalarClauseView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (ScalarClauseView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (ScalarClauseView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (ScalarClauseView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*ScalarClauseView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*ScalarClauseView) UnmarshalText([]byte) error    { return opaqueError() }
func (*ScalarClauseView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (DescriptorRequirementView) String() string                 { return opaqueFormat }
func (DescriptorRequirementView) GoString() string               { return opaqueFormat }
func (DescriptorRequirementView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (DescriptorRequirementView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (DescriptorRequirementView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (DescriptorRequirementView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*DescriptorRequirementView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*DescriptorRequirementView) UnmarshalText([]byte) error    { return opaqueError() }
func (*DescriptorRequirementView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (PointerRequirementView) String() string                 { return opaqueFormat }
func (PointerRequirementView) GoString() string               { return opaqueFormat }
func (PointerRequirementView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (PointerRequirementView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (PointerRequirementView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (PointerRequirementView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*PointerRequirementView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*PointerRequirementView) UnmarshalText([]byte) error    { return opaqueError() }
func (*PointerRequirementView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (ObjectRequirementView) String() string                 { return opaqueFormat }
func (ObjectRequirementView) GoString() string               { return opaqueFormat }
func (ObjectRequirementView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (ObjectRequirementView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (ObjectRequirementView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (ObjectRequirementView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*ObjectRequirementView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*ObjectRequirementView) UnmarshalText([]byte) error    { return opaqueError() }
func (*ObjectRequirementView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (TransitionView) String() string                 { return opaqueFormat }
func (TransitionView) GoString() string               { return opaqueFormat }
func (TransitionView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (TransitionView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (TransitionView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (TransitionView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*TransitionView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*TransitionView) UnmarshalText([]byte) error    { return opaqueError() }
func (*TransitionView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (PinnedCallsiteRequirementView) String() string                 { return opaqueFormat }
func (PinnedCallsiteRequirementView) GoString() string               { return opaqueFormat }
func (PinnedCallsiteRequirementView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (PinnedCallsiteRequirementView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (PinnedCallsiteRequirementView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (PinnedCallsiteRequirementView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*PinnedCallsiteRequirementView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*PinnedCallsiteRequirementView) UnmarshalText([]byte) error    { return opaqueError() }
func (*PinnedCallsiteRequirementView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (PinnedBinaryBindingView) String() string                 { return opaqueFormat }
func (PinnedBinaryBindingView) GoString() string               { return opaqueFormat }
func (PinnedBinaryBindingView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (PinnedBinaryBindingView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (PinnedBinaryBindingView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (PinnedBinaryBindingView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*PinnedBinaryBindingView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*PinnedBinaryBindingView) UnmarshalText([]byte) error    { return opaqueError() }
func (*PinnedBinaryBindingView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (PinnedCallsiteEvidenceView) String() string                 { return opaqueFormat }
func (PinnedCallsiteEvidenceView) GoString() string               { return opaqueFormat }
func (PinnedCallsiteEvidenceView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (PinnedCallsiteEvidenceView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (PinnedCallsiteEvidenceView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (PinnedCallsiteEvidenceView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*PinnedCallsiteEvidenceView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*PinnedCallsiteEvidenceView) UnmarshalText([]byte) error    { return opaqueError() }
func (*PinnedCallsiteEvidenceView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (Policy) String() string                 { return opaqueFormat }
func (Policy) GoString() string               { return opaqueFormat }
func (Policy) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (Policy) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (Policy) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (Policy) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*Policy) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*Policy) UnmarshalText([]byte) error    { return opaqueError() }
func (*Policy) UnmarshalBinary([]byte) error  { return opaqueError() }

func (Classification) String() string                 { return opaqueFormat }
func (Classification) GoString() string               { return opaqueFormat }
func (Classification) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (Classification) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (Classification) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (Classification) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*Classification) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*Classification) UnmarshalText([]byte) error    { return opaqueError() }
func (*Classification) UnmarshalBinary([]byte) error  { return opaqueError() }

func (FilterDecision) String() string                 { return opaqueFormat }
func (FilterDecision) GoString() string               { return opaqueFormat }
func (FilterDecision) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (FilterDecision) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (FilterDecision) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (FilterDecision) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*FilterDecision) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*FilterDecision) UnmarshalText([]byte) error    { return opaqueError() }
func (*FilterDecision) UnmarshalBinary([]byte) error  { return opaqueError() }

func (Decision) String() string                 { return opaqueFormat }
func (Decision) GoString() string               { return opaqueFormat }
func (Decision) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (Decision) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (Decision) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (Decision) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*Decision) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*Decision) UnmarshalText([]byte) error    { return opaqueError() }
func (*Decision) UnmarshalBinary([]byte) error  { return opaqueError() }

func (AdapterDecision) String() string                 { return opaqueFormat }
func (AdapterDecision) GoString() string               { return opaqueFormat }
func (AdapterDecision) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (AdapterDecision) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (AdapterDecision) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (AdapterDecision) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*AdapterDecision) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*AdapterDecision) UnmarshalText([]byte) error    { return opaqueError() }
func (*AdapterDecision) UnmarshalBinary([]byte) error  { return opaqueError() }

func (AdapterTicket) String() string                 { return opaqueFormat }
func (AdapterTicket) GoString() string               { return opaqueFormat }
func (AdapterTicket) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (AdapterTicket) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (AdapterTicket) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (AdapterTicket) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*AdapterTicket) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*AdapterTicket) UnmarshalText([]byte) error    { return opaqueError() }
func (*AdapterTicket) UnmarshalBinary([]byte) error  { return opaqueError() }

func (AdapterPermit) String() string                 { return opaqueFormat }
func (AdapterPermit) GoString() string               { return opaqueFormat }
func (AdapterPermit) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (AdapterPermit) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (AdapterPermit) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (AdapterPermit) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*AdapterPermit) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*AdapterPermit) UnmarshalText([]byte) error    { return opaqueError() }
func (*AdapterPermit) UnmarshalBinary([]byte) error  { return opaqueError() }

func (AdapterBindings) String() string                 { return opaqueFormat }
func (AdapterBindings) GoString() string               { return opaqueFormat }
func (AdapterBindings) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (AdapterBindings) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (AdapterBindings) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (AdapterBindings) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*AdapterBindings) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*AdapterBindings) UnmarshalText([]byte) error    { return opaqueError() }
func (*AdapterBindings) UnmarshalBinary([]byte) error  { return opaqueError() }

func (AdapterBindingView) String() string                 { return opaqueFormat }
func (AdapterBindingView) GoString() string               { return opaqueFormat }
func (AdapterBindingView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (AdapterBindingView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (AdapterBindingView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (AdapterBindingView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*AdapterBindingView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*AdapterBindingView) UnmarshalText([]byte) error    { return opaqueError() }
func (*AdapterBindingView) UnmarshalBinary([]byte) error  { return opaqueError() }

func (BindingQuery) String() string                 { return opaqueFormat }
func (BindingQuery) GoString() string               { return opaqueFormat }
func (BindingQuery) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (BindingQuery) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (BindingQuery) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (BindingQuery) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*BindingQuery) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*BindingQuery) UnmarshalText([]byte) error    { return opaqueError() }
func (*BindingQuery) UnmarshalBinary([]byte) error  { return opaqueError() }

func (BindingObservation) String() string                 { return opaqueFormat }
func (BindingObservation) GoString() string               { return opaqueFormat }
func (BindingObservation) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (BindingObservation) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (BindingObservation) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (BindingObservation) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*BindingObservation) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*BindingObservation) UnmarshalText([]byte) error    { return opaqueError() }
func (*BindingObservation) UnmarshalBinary([]byte) error  { return opaqueError() }

func (StateQuery) String() string                 { return opaqueFormat }
func (StateQuery) GoString() string               { return opaqueFormat }
func (StateQuery) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (StateQuery) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (StateQuery) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (StateQuery) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*StateQuery) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*StateQuery) UnmarshalText([]byte) error    { return opaqueError() }
func (*StateQuery) UnmarshalBinary([]byte) error  { return opaqueError() }

func (StateObservation) String() string                 { return opaqueFormat }
func (StateObservation) GoString() string               { return opaqueFormat }
func (StateObservation) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (StateObservation) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (StateObservation) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (StateObservation) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*StateObservation) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*StateObservation) UnmarshalText([]byte) error    { return opaqueError() }
func (*StateObservation) UnmarshalBinary([]byte) error  { return opaqueError() }

func (FDQuery) String() string                 { return opaqueFormat }
func (FDQuery) GoString() string               { return opaqueFormat }
func (FDQuery) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (FDQuery) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (FDQuery) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (FDQuery) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*FDQuery) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*FDQuery) UnmarshalText([]byte) error    { return opaqueError() }
func (*FDQuery) UnmarshalBinary([]byte) error  { return opaqueError() }

func (FDObservation) String() string                 { return opaqueFormat }
func (FDObservation) GoString() string               { return opaqueFormat }
func (FDObservation) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (FDObservation) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (FDObservation) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (FDObservation) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*FDObservation) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*FDObservation) UnmarshalText([]byte) error    { return opaqueError() }
func (*FDObservation) UnmarshalBinary([]byte) error  { return opaqueError() }

func (PointerQuery) String() string                 { return opaqueFormat }
func (PointerQuery) GoString() string               { return opaqueFormat }
func (PointerQuery) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (PointerQuery) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (PointerQuery) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (PointerQuery) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*PointerQuery) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*PointerQuery) UnmarshalText([]byte) error    { return opaqueError() }
func (*PointerQuery) UnmarshalBinary([]byte) error  { return opaqueError() }

func (PointerObservation) String() string                 { return opaqueFormat }
func (PointerObservation) GoString() string               { return opaqueFormat }
func (PointerObservation) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (PointerObservation) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (PointerObservation) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (PointerObservation) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*PointerObservation) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*PointerObservation) UnmarshalText([]byte) error    { return opaqueError() }
func (*PointerObservation) UnmarshalBinary([]byte) error  { return opaqueError() }

func (ObjectQuery) String() string                 { return opaqueFormat }
func (ObjectQuery) GoString() string               { return opaqueFormat }
func (ObjectQuery) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (ObjectQuery) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (ObjectQuery) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (ObjectQuery) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*ObjectQuery) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*ObjectQuery) UnmarshalText([]byte) error    { return opaqueError() }
func (*ObjectQuery) UnmarshalBinary([]byte) error  { return opaqueError() }

func (ObjectObservation) String() string                 { return opaqueFormat }
func (ObjectObservation) GoString() string               { return opaqueFormat }
func (ObjectObservation) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (ObjectObservation) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (ObjectObservation) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (ObjectObservation) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*ObjectObservation) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*ObjectObservation) UnmarshalText([]byte) error    { return opaqueError() }
func (*ObjectObservation) UnmarshalBinary([]byte) error  { return opaqueError() }
