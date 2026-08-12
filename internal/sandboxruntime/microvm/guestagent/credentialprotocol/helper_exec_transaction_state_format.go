package credentialprotocol

import "fmt"

func helperExecTransactionFormat(state fmt.State, name string) {
	_, _ = state.Write([]byte("<credentialprotocol." + name + ">"))
}

func (HelperExecTransactionCorrelation) String() string {
	return "<credentialprotocol.HelperExecTransactionCorrelation>"
}
func (HelperExecTransactionCorrelation) GoString() string {
	return "<credentialprotocol.HelperExecTransactionCorrelation>"
}
func (HelperExecTransactionCorrelation) Format(state fmt.State, _ rune) {
	helperExecTransactionFormat(state, "HelperExecTransactionCorrelation")
}

func (HelperExecTransaction) String() string { return "<credentialprotocol.HelperExecTransaction>" }
func (HelperExecTransaction) GoString() string {
	return "<credentialprotocol.HelperExecTransaction>"
}
func (HelperExecTransaction) Format(state fmt.State, _ rune) {
	helperExecTransactionFormat(state, "HelperExecTransaction")
}

func (HelperExecPayloadProposal) String() string {
	return "<credentialprotocol.HelperExecPayloadProposal>"
}
func (HelperExecPayloadProposal) GoString() string {
	return "<credentialprotocol.HelperExecPayloadProposal>"
}
func (HelperExecPayloadProposal) Format(state fmt.State, _ rune) {
	helperExecTransactionFormat(state, "HelperExecPayloadProposal")
}

func (HelperExecTransactionSnapshot) String() string {
	return "<credentialprotocol.HelperExecTransactionSnapshot>"
}
func (HelperExecTransactionSnapshot) GoString() string {
	return "<credentialprotocol.HelperExecTransactionSnapshot>"
}
func (HelperExecTransactionSnapshot) Format(state fmt.State, _ rune) {
	helperExecTransactionFormat(state, "HelperExecTransactionSnapshot")
}

func (HelperExecTransactionResult) String() string {
	return "<credentialprotocol.HelperExecTransactionResult>"
}
func (HelperExecTransactionResult) GoString() string {
	return "<credentialprotocol.HelperExecTransactionResult>"
}
func (HelperExecTransactionResult) Format(state fmt.State, _ rune) {
	helperExecTransactionFormat(state, "HelperExecTransactionResult")
}

func (HelperExecTransactionCorrelation) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (HelperExecTransactionCorrelation) MarshalText() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (HelperExecTransactionCorrelation) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (*HelperExecTransactionCorrelation) UnmarshalJSON([]byte) error {
	return ErrHelperExecTransactionSerialization
}
func (*HelperExecTransactionCorrelation) UnmarshalText([]byte) error {
	return ErrHelperExecTransactionSerialization
}
func (*HelperExecTransactionCorrelation) UnmarshalBinary([]byte) error {
	return ErrHelperExecTransactionSerialization
}

func (HelperExecTransaction) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (HelperExecTransaction) MarshalText() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (HelperExecTransaction) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (*HelperExecTransaction) UnmarshalJSON([]byte) error {
	return ErrHelperExecTransactionSerialization
}
func (*HelperExecTransaction) UnmarshalText([]byte) error {
	return ErrHelperExecTransactionSerialization
}
func (*HelperExecTransaction) UnmarshalBinary([]byte) error {
	return ErrHelperExecTransactionSerialization
}

func (HelperExecPayloadProposal) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (HelperExecPayloadProposal) MarshalText() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (HelperExecPayloadProposal) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (*HelperExecPayloadProposal) UnmarshalJSON([]byte) error {
	return ErrHelperExecTransactionSerialization
}
func (*HelperExecPayloadProposal) UnmarshalText([]byte) error {
	return ErrHelperExecTransactionSerialization
}
func (*HelperExecPayloadProposal) UnmarshalBinary([]byte) error {
	return ErrHelperExecTransactionSerialization
}

func (HelperExecTransactionSnapshot) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (HelperExecTransactionSnapshot) MarshalText() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (HelperExecTransactionSnapshot) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (*HelperExecTransactionSnapshot) UnmarshalJSON([]byte) error {
	return ErrHelperExecTransactionSerialization
}
func (*HelperExecTransactionSnapshot) UnmarshalText([]byte) error {
	return ErrHelperExecTransactionSerialization
}
func (*HelperExecTransactionSnapshot) UnmarshalBinary([]byte) error {
	return ErrHelperExecTransactionSerialization
}

func (HelperExecTransactionResult) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (HelperExecTransactionResult) MarshalText() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (HelperExecTransactionResult) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperExecTransactionSerialization
}
func (*HelperExecTransactionResult) UnmarshalJSON([]byte) error {
	return ErrHelperExecTransactionSerialization
}
func (*HelperExecTransactionResult) UnmarshalText([]byte) error {
	return ErrHelperExecTransactionSerialization
}
func (*HelperExecTransactionResult) UnmarshalBinary([]byte) error {
	return ErrHelperExecTransactionSerialization
}
