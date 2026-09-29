package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength  = 128
	MemoryKiB  = 19 * 1024
	Iterations = 2
	Lanes      = 1 //parallelism
	KeyLength  = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey([]byte(password), salt, Iterations, MemoryKiB, Lanes, KeyLength)

	return encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		memoryKiB:   MemoryKiB,
		iterations:  Iterations,
		parallelism: Lanes,
		salt:        salt,
		derivedKey:  derivedKey,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	if expectedHash, ok := decodeLegacyHash(encodedHash); ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}
	a2idHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	if a2idHash.version != argon2.Version {
		return false
	}
	derivedKey := argon2.IDKey([]byte(password), a2idHash.salt, a2idHash.iterations, a2idHash.memoryKiB, a2idHash.parallelism, uint32(len(a2idHash.derivedKey)))
	return subtle.ConstantTimeCompare(derivedKey, a2idHash.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	if _, ok := decodeLegacyHash(encodedHash); ok {
		return true
	}
	a2idHash, ok := parseArgon2idHash(encodedHash)
	if ok {
		return !(a2idHash.version == argon2.Version &&
			a2idHash.memoryKiB == MemoryKiB &&
			a2idHash.iterations == Iterations &&
			a2idHash.parallelism == Lanes &&
			len(a2idHash.derivedKey) == KeyLength)
	}
	return false
}
