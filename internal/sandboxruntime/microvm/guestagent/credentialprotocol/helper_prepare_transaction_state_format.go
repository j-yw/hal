package credentialprotocol

import "fmt"

func helperPrepareTransactionFormat(state fmt.State, name string) {
	_, _ = state.Write([]byte("<credentialprotocol." + name + ">"))
}

func (HelperPrepareTransactionCorrelation) String() string {
	return "<credentialprotocol.HelperPrepareTransactionCorrelation>"
}
func (HelperPrepareTransactionCorrelation) GoString() string {
	return "<credentialprotocol.HelperPrepareTransactionCorrelation>"
}
func (HelperPrepareTransactionCorrelation) Format(state fmt.State, _ rune) {
	helperPrepareTransactionFormat(state, "HelperPrepareTransactionCorrelation")
}

func (HelperPrepareTransaction) String() string {
	return "<credentialprotocol.HelperPrepareTransaction>"
}
func (HelperPrepareTransaction) GoString() string {
	return "<credentialprotocol.HelperPrepareTransaction>"
}
func (HelperPrepareTransaction) Format(state fmt.State, _ rune) {
	helperPrepareTransactionFormat(state, "HelperPrepareTransaction")
}

func (HelperPrepareFileProposal) String() string {
	return "<credentialprotocol.HelperPrepareFileProposal>"
}
func (HelperPrepareFileProposal) GoString() string {
	return "<credentialprotocol.HelperPrepareFileProposal>"
}
func (HelperPrepareFileProposal) Format(state fmt.State, _ rune) {
	helperPrepareTransactionFormat(state, "HelperPrepareFileProposal")
}

func (HelperPrepareTransactionSnapshot) String() string {
	return "<credentialprotocol.HelperPrepareTransactionSnapshot>"
}
func (HelperPrepareTransactionSnapshot) GoString() string {
	return "<credentialprotocol.HelperPrepareTransactionSnapshot>"
}
func (HelperPrepareTransactionSnapshot) Format(state fmt.State, _ rune) {
	helperPrepareTransactionFormat(state, "HelperPrepareTransactionSnapshot")
}

func (HelperPrepareTransactionResult) String() string {
	return "<credentialprotocol.HelperPrepareTransactionResult>"
}
func (HelperPrepareTransactionResult) GoString() string {
	return "<credentialprotocol.HelperPrepareTransactionResult>"
}
func (HelperPrepareTransactionResult) Format(state fmt.State, _ rune) {
	helperPrepareTransactionFormat(state, "HelperPrepareTransactionResult")
}

func (HelperPrepareTransactionCorrelation) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (HelperPrepareTransactionCorrelation) MarshalText() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (HelperPrepareTransactionCorrelation) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransactionCorrelation) UnmarshalJSON([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransactionCorrelation) UnmarshalText([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransactionCorrelation) UnmarshalBinary([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}

func (HelperPrepareTransaction) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (HelperPrepareTransaction) MarshalText() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (HelperPrepareTransaction) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransaction) UnmarshalJSON([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransaction) UnmarshalText([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransaction) UnmarshalBinary([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}

func (HelperPrepareFileProposal) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (HelperPrepareFileProposal) MarshalText() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (HelperPrepareFileProposal) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareFileProposal) UnmarshalJSON([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareFileProposal) UnmarshalText([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareFileProposal) UnmarshalBinary([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}

func (HelperPrepareTransactionSnapshot) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (HelperPrepareTransactionSnapshot) MarshalText() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (HelperPrepareTransactionSnapshot) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransactionSnapshot) UnmarshalJSON([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransactionSnapshot) UnmarshalText([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransactionSnapshot) UnmarshalBinary([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}

func (HelperPrepareTransactionResult) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (HelperPrepareTransactionResult) MarshalText() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (HelperPrepareTransactionResult) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransactionResult) UnmarshalJSON([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransactionResult) UnmarshalText([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}
func (*HelperPrepareTransactionResult) UnmarshalBinary([]byte) error {
	return ErrHelperPrepareTransactionSerialization
}
