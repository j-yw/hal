package syscallpolicy

import "fmt"

const opaqueFormat = "syscallpolicy.live[redacted]"

func writeOpaque(state fmt.State) { _, _ = state.Write([]byte(opaqueFormat)) }
func opaqueError() error          { return contractError(ErrorCodeInvalidArgument) }

func (CheckSet) String() string                 { return opaqueFormat }
func (CheckSet) GoString() string               { return opaqueFormat }
func (CheckSet) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (CheckSet) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (CheckSet) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (CheckSet) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*CheckSet) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*CheckSet) UnmarshalText([]byte) error    { return opaqueError() }
func (*CheckSet) UnmarshalBinary([]byte) error  { return opaqueError() }

func (ExpectedPolicyArtifact) String() string                 { return opaqueFormat }
func (ExpectedPolicyArtifact) GoString() string               { return opaqueFormat }
func (ExpectedPolicyArtifact) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (ExpectedPolicyArtifact) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (ExpectedPolicyArtifact) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (ExpectedPolicyArtifact) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*ExpectedPolicyArtifact) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*ExpectedPolicyArtifact) UnmarshalText([]byte) error    { return opaqueError() }
func (*ExpectedPolicyArtifact) UnmarshalBinary([]byte) error  { return opaqueError() }

func (VerifiedPolicyArtifact) String() string                 { return opaqueFormat }
func (VerifiedPolicyArtifact) GoString() string               { return opaqueFormat }
func (VerifiedPolicyArtifact) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (VerifiedPolicyArtifact) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (VerifiedPolicyArtifact) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (VerifiedPolicyArtifact) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*VerifiedPolicyArtifact) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*VerifiedPolicyArtifact) UnmarshalText([]byte) error    { return opaqueError() }
func (*VerifiedPolicyArtifact) UnmarshalBinary([]byte) error  { return opaqueError() }

func (ExpectedPinnedCallsiteEvidence) String() string                 { return opaqueFormat }
func (ExpectedPinnedCallsiteEvidence) GoString() string               { return opaqueFormat }
func (ExpectedPinnedCallsiteEvidence) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (ExpectedPinnedCallsiteEvidence) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (ExpectedPinnedCallsiteEvidence) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (ExpectedPinnedCallsiteEvidence) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*ExpectedPinnedCallsiteEvidence) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*ExpectedPinnedCallsiteEvidence) UnmarshalText([]byte) error    { return opaqueError() }
func (*ExpectedPinnedCallsiteEvidence) UnmarshalBinary([]byte) error  { return opaqueError() }

func (PinnedBinaryBindingSet) String() string                 { return opaqueFormat }
func (PinnedBinaryBindingSet) GoString() string               { return opaqueFormat }
func (PinnedBinaryBindingSet) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (PinnedBinaryBindingSet) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (PinnedBinaryBindingSet) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (PinnedBinaryBindingSet) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*PinnedBinaryBindingSet) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*PinnedBinaryBindingSet) UnmarshalText([]byte) error    { return opaqueError() }
func (*PinnedBinaryBindingSet) UnmarshalBinary([]byte) error  { return opaqueError() }

func (PinnedCallsiteEvidenceSet) String() string                 { return opaqueFormat }
func (PinnedCallsiteEvidenceSet) GoString() string               { return opaqueFormat }
func (PinnedCallsiteEvidenceSet) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (PinnedCallsiteEvidenceSet) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (PinnedCallsiteEvidenceSet) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (PinnedCallsiteEvidenceSet) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*PinnedCallsiteEvidenceSet) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*PinnedCallsiteEvidenceSet) UnmarshalText([]byte) error    { return opaqueError() }
func (*PinnedCallsiteEvidenceSet) UnmarshalBinary([]byte) error  { return opaqueError() }

func (State) String() string                 { return opaqueFormat }
func (State) GoString() string               { return opaqueFormat }
func (State) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (State) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (State) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (State) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*State) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*State) UnmarshalText([]byte) error    { return opaqueError() }
func (*State) UnmarshalBinary([]byte) error  { return opaqueError() }

func (FilterInput) String() string                 { return opaqueFormat }
func (FilterInput) GoString() string               { return opaqueFormat }
func (FilterInput) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (FilterInput) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (FilterInput) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (FilterInput) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*FilterInput) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*FilterInput) UnmarshalText([]byte) error    { return opaqueError() }
func (*FilterInput) UnmarshalBinary([]byte) error  { return opaqueError() }

func (failure ContractError) String() string                 { return opaqueFormat }
func (failure ContractError) GoString() string               { return opaqueFormat }
func (failure ContractError) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (failure ContractError) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (failure ContractError) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (failure ContractError) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*ContractError) UnmarshalJSON([]byte) error            { return opaqueError() }
func (*ContractError) UnmarshalText([]byte) error            { return opaqueError() }
func (*ContractError) UnmarshalBinary([]byte) error          { return opaqueError() }
