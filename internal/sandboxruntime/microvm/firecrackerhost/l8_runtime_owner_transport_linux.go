//go:build linux

package firecrackerhost

import (
	"context"
	"os"
)

type l8RuntimeOwnerNamespaceCorrelationV1 struct {
	UserDevice    uint64
	UserInode     uint64
	NetworkDevice uint64
	NetworkInode  uint64
}

type l8RuntimeOwnerReceivedPacketV1 struct {
	Packet l8RuntimeOwnerPacketV1
	Files  []*os.File
}

func encodeL8RuntimeOwnerNamespaceCorrelation(l8RuntimeOwnerNamespaceCorrelationV1) []byte {
	return nil
}

func decodeL8RuntimeOwnerNamespaceCorrelation([]byte) (l8RuntimeOwnerNamespaceCorrelationV1, error) {
	return l8RuntimeOwnerNamespaceCorrelationV1{}, errL8RuntimeOwnerProtocol
}

func sendL8RuntimeOwnerSeqpacket(int, l8RuntimeOwnerPacketV1, []*os.File) error {
	return errL8RuntimeOwnerProtocol
}

func receiveL8RuntimeOwnerSeqpacket(int) (l8RuntimeOwnerReceivedPacketV1, error) {
	return l8RuntimeOwnerReceivedPacketV1{}, errL8RuntimeOwnerProtocol
}

func validateL8RuntimeOwnerNamespaceFiles([]*os.File, l8RuntimeOwnerNamespaceCorrelationV1) error {
	return errL8RuntimeOwnerInvalid
}

func l8RuntimeOwnerPeerUID(int) (uint32, error) {
	return 0, errL8RuntimeOwnerInvalid
}

func parseL8RuntimeOwnerProcIdentity([]byte, uint32) (uint32, uint64, byte, error) {
	return 0, 0, 0, errL8RuntimeOwnerInvalid
}

func signalL8RuntimeOwnerProcess(l8RuntimeOwnerProcessObservation, os.Signal) error {
	return errL8RuntimeOwnerInvalid
}

func waitL8RuntimeOwnerProcessTerminal(context.Context, l8RuntimeOwnerProcessObservation) error {
	return errL8RuntimeOwnerInvalid
}

func inspectL8RuntimeOwnerProcessAbsent(uint32) (bool, error) {
	return false, errL8RuntimeOwnerInvalid
}
