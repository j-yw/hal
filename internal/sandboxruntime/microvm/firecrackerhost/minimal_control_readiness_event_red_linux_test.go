//go:build linux

package firecrackerhost

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalReadinessEventDatagramObservations(t *testing.T) {
	wire, want := minimalReadinessGolden(t)
	if got, err := decodeMinimalControlReadinessDatagram(wire, nil, 0); err != nil || got != want {
		t.Fatal("clean datagram prerequisite; ancillary/truncation negatives not reached", err)
	}
	for _, tc := range []struct {
		name  string
		oob   []byte
		flags int
	}{
		{"ancillary_byte", []byte{1}, 0},
		{"ancillary_rights_encoding", unix.UnixRights(123), 0}, // Synthetic bytes; never transferred or treated as a live FD.
		{"truncated", nil, unix.MSG_TRUNC},
		{"control_truncated", nil, unix.MSG_CTRUNC},
		{"both_truncated", nil, unix.MSG_TRUNC | unix.MSG_CTRUNC},
		{"ancillary_and_truncated", []byte{1}, unix.MSG_TRUNC | unix.MSG_CTRUNC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, controlBefore := bytes.Clone(wire), bytes.Clone(tc.oob)
			got, err := decodeMinimalControlReadinessDatagram(wire, tc.oob, tc.flags)
			if !errors.Is(err, errL8RuntimeOwnerProtocol) || got != (minimalControlReadinessEventV1{}) ||
				!bytes.Equal(wire, before) || !bytes.Equal(tc.oob, controlBefore) {
				t.Fatal("invalid datagram observation accepted or mutated borrowed bytes")
			}
		})
	}
	for _, flags := range []int{0, unix.MSG_EOR, unix.MSG_CMSG_CLOEXEC, unix.MSG_EOR | unix.MSG_CMSG_CLOEXEC} {
		if got, err := decodeMinimalControlReadinessDatagram(wire, []byte{}, flags); err != nil || got != want {
			t.Fatal("unrelated kernel flags or empty ancillary slice changed pure decode", err)
		}
	}
	if got, err := decodeMinimalControlReadinessDatagram(append(bytes.Clone(wire), 0), nil, 0); !errors.Is(err, errL8RuntimeOwnerProtocol) || got != (minimalControlReadinessEventV1{}) {
		t.Fatal("datagram wrapper bypassed exact payload extent")
	}
}
