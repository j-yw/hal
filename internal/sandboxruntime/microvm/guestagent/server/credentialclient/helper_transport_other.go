//go:build !linux

package credentialclient

import "context"

func revalidateVerifiedHelperStream(VerifiedHelperStream) error {
	return ErrClientControlDependencyUnaccepted
}

func recvHelperDatagramPlatform(ctx context.Context, stream VerifiedHelperStream, dontWait bool) ([]byte, []int, bool, error) {
	return recvHelperDatagramRead(ctx, stream, dontWait)
}

func sendHelperDatagramPlatform(ctx context.Context, stream VerifiedHelperStream, datagram []byte) error {
	return sendHelperDatagramWrite(ctx, stream, datagram)
}

func closeReceivedHelperRights([]int) {}

func newSSHAcceptedConnFromRight(int, [32]byte) SSHConnectionCapability {
	return nil
}
