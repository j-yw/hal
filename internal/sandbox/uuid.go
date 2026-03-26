package sandbox

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	uuidV7VersionBits = 0x70
	uuidVariantBits   = 0x80

	uuidV7UnixMilliMask = uint64(1<<48 - 1)
	uuidV7RandAMask     = uint16(1<<12 - 1)
	uuidV7RandBMask     = uint64(1<<62 - 1)
)

// UUIDSource generates UUIDv7 values with injectable time and randomness for tests.
//
// References:
//   - RFC 9562, UUID Version 7
//   - Layout: 48-bit unix milliseconds, 12-bit rand_a, 62-bit rand_b
//   - Variant: RFC4122 (10xx)
type UUIDSource struct {
	clock func() time.Time
	rand  io.Reader

	mu sync.Mutex

	initialized   bool
	lastUnixMilli uint64
	randA         uint16
	randB         uint64
}

var defaultUUIDSource = NewUUIDSource(nil, nil)

// NewUUIDSource returns a UUIDv7 generator.
//
// If clock is nil, time.Now is used.
// If randReader is nil, crypto/rand.Reader is used.
func NewUUIDSource(clock func() time.Time, randReader io.Reader) *UUIDSource {
	if clock == nil {
		clock = time.Now
	}
	if randReader == nil {
		randReader = cryptoRand.Reader
	}

	return &UUIDSource{
		clock: clock,
		rand:  randReader,
	}
}

// NewV7 generates a UUIDv7 using the package default source.
func NewV7() (string, error) {
	return defaultUUIDSource.NewV7()
}

// NewV7 generates a monotonic RFC 9562-compliant UUIDv7 string.
func (s *UUIDSource) NewV7() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	currentMilli := s.nowUnixMilli()

	switch {
	case !s.initialized:
		if err := s.seedRandom(); err != nil {
			return "", err
		}
		s.lastUnixMilli = currentMilli
		s.initialized = true
	case currentMilli > s.lastUnixMilli:
		if err := s.seedRandom(); err != nil {
			return "", err
		}
		s.lastUnixMilli = currentMilli
	default:
		currentMilli = s.lastUnixMilli
		if overflow := s.incrementRandom(); overflow {
			s.lastUnixMilli++
			currentMilli = s.lastUnixMilli
		}
	}

	return formatUUIDv7(currentMilli, s.randA, s.randB), nil
}

func (s *UUIDSource) nowUnixMilli() uint64 {
	now := s.clock().UnixMilli()
	if now < 0 {
		return 0
	}
	return uint64(now)
}

func (s *UUIDSource) seedRandom() error {
	var random [10]byte
	if _, err := io.ReadFull(s.rand, random[:]); err != nil {
		return fmt.Errorf("generate uuid v7 random bytes: %w", err)
	}

	s.randA = binary.BigEndian.Uint16(random[0:2]) & uuidV7RandAMask
	s.randB = binary.BigEndian.Uint64(random[2:10]) & uuidV7RandBMask
	return nil
}

func (s *UUIDSource) incrementRandom() bool {
	if s.randB < uuidV7RandBMask {
		s.randB++
		return false
	}

	s.randB = 0
	if s.randA < uuidV7RandAMask {
		s.randA++
		return false
	}

	s.randA = 0
	return true
}

func formatUUIDv7(unixMilli uint64, randA uint16, randB uint64) string {
	unixMilli &= uuidV7UnixMilliMask
	randA &= uuidV7RandAMask
	randB &= uuidV7RandBMask

	var raw [16]byte

	raw[0] = byte(unixMilli >> 40)
	raw[1] = byte(unixMilli >> 32)
	raw[2] = byte(unixMilli >> 24)
	raw[3] = byte(unixMilli >> 16)
	raw[4] = byte(unixMilli >> 8)
	raw[5] = byte(unixMilli)

	raw[6] = uuidV7VersionBits | byte((randA>>8)&0x0f)
	raw[7] = byte(randA)

	raw[8] = uuidVariantBits | byte((randB>>56)&0x3f)
	raw[9] = byte(randB >> 48)
	raw[10] = byte(randB >> 40)
	raw[11] = byte(randB >> 32)
	raw[12] = byte(randB >> 24)
	raw[13] = byte(randB >> 16)
	raw[14] = byte(randB >> 8)
	raw[15] = byte(randB)

	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

func isUUIDv7(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	if len(value) != 36 {
		return false
	}

	for i, ch := range value {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
			continue
		}
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}

	if value[14] != '7' {
		return false
	}

	switch value[19] {
	case '8', '9', 'a', 'b':
		return true
	default:
		return false
	}
}
