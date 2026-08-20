package credentialproxy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	JobTicketRawBytes              = 32
	JobTicketEncodedBytes          = 43
	JobTicketMaxConcurrentRequests = 4
	JobTicketMaxTotalRequests      = 4096
)

var (
	ErrTicketStoreInvalid         = errors.New("credential proxy ticket store invalid")
	ErrTicketInvalid              = errors.New("credential proxy ticket invalid")
	ErrTicketExpired              = errors.New("credential proxy ticket expired")
	ErrTicketRevoked              = errors.New("credential proxy ticket revoked")
	ErrTicketCorrelation          = errors.New("credential proxy ticket correlation mismatch")
	ErrTicketConcurrencyLimit     = errors.New("credential proxy ticket concurrency limit")
	ErrTicketRequestLimit         = errors.New("credential proxy ticket request limit")
	ErrTicketCleanup              = errors.New("credential proxy ticket cleanup failed")
	ErrLiveTicketNotSerializable  = errors.New("credential proxy live ticket is not serializable")
	ErrTicketConnectionTransition = errors.New("credential proxy ticket connection transition invalid")
)

// JobTicket is an opaque one-job capability. CopyTo is the only operation that
// exposes its exact transient wire value; formatting and serialization never
// inspect the capability body.
type JobTicket struct {
	encoded [JobTicketEncodedBytes]byte
}

func newJobTicket(raw [JobTicketRawBytes]byte) *JobTicket {
	var ticket JobTicket
	base64.RawURLEncoding.Encode(ticket.encoded[:], raw[:])
	return &ticket
}

func (ticket *JobTicket) Len() int {
	if ticket == nil || !validEncodedTicket(ticket.encoded[:]) {
		return 0
	}
	return JobTicketEncodedBytes
}

func (ticket *JobTicket) CopyTo(destination []byte) (int, error) {
	if ticket == nil || !validEncodedTicket(ticket.encoded[:]) || len(destination) != JobTicketEncodedBytes {
		wipeBytes(destination)
		return 0, ErrTicketInvalid
	}
	copy(destination, ticket.encoded[:])
	return JobTicketEncodedBytes, nil
}

func (JobTicket) MarshalJSON() ([]byte, error) { return nil, ErrLiveTicketNotSerializable }
func (JobTicket) MarshalText() ([]byte, error) { return nil, ErrLiveTicketNotSerializable }
func (JobTicket) String() string               { return "credentialproxy.JobTicket{live}" }
func (JobTicket) GoString() string             { return "credentialproxy.JobTicket{live}" }
func (JobTicket) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialproxy.JobTicket{live}"))
}

func validEncodedTicket(encoded []byte) bool {
	if len(encoded) != JobTicketEncodedBytes {
		return false
	}
	var decoded [JobTicketRawBytes]byte
	n, err := base64.RawURLEncoding.Decode(decoded[:], encoded)
	wipeBytes(decoded[:])
	return err == nil && n == JobTicketRawBytes
}

func wipeBytes(values []byte) {
	for index := range values {
		values[index] = 0
	}
}

var _ json.Marshaler = (*JobTicket)(nil)
