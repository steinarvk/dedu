package deduhash

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

var (
	Mismatch = errors.New("Hash mismatch")
)

var fixedSalt = []byte("dedu.hash.2")

type Hasher struct {
	key []byte
}

type parsedHash struct {
	hashVersion  string
	contentsHash string
	lengthHash   string
}

const (
	bufferSize = 10 * 1024
)

func (h *Hasher) computeHashV1(r io.Reader) (string, int64, error) {
	mac := hmac.New(sha256.New, h.key)
	mac.Write(fixedSalt)

	buf := make([]byte, bufferSize)
	var sz int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			sz += int64(n)
			mac.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", 0, fmt.Errorf("Read error: %v", err)
		}
	}
	checksum := mac.Sum(nil)
	hexdigest := fmt.Sprintf("%x", checksum)
	return hexdigest, sz, nil
}

func (h *Hasher) computeLengthHashV1(n int64) (string, error) {
	lengthHashLength := 3
	data := fmt.Sprintf("%d", n)
	rv, nn, err := h.computeHashV1(strings.NewReader(data))
	if err != nil {
		return "", err
	}
	if nn != int64(len(data)) {
		return "", fmt.Errorf("Sanity check failed: %d != %d", nn, len(data))
	}
	return rv[:lengthHashLength], nil
}

func parseHash(h string) (*parsedHash, error) {
	components := strings.Split(h, "-")
	if len(components) == 0 {
		return nil, fmt.Errorf("No components")
	}
	switch components[0] {
	case "1":
		if len(components) != 4 {
			return nil, fmt.Errorf("Wrong number of dashed components in hash: %q", h)
		}
		return &parsedHash{
			hashVersion:  "1",
			contentsHash: components[1] + components[3],
			lengthHash:   components[2],
		}, nil
	default:
		return nil, fmt.Errorf("Unknown hash kind %q", components[0])
	}
}

func formatHashV1(mainhash, lhash string) (string, error) {
	// for visual-inspection convenience, we make sure both the beginning
	// and the end of the hash have high entropy.
	prefixLength := 20
	suffixLength := 20
	if len(mainhash) < (prefixLength + suffixLength) {
		return "", fmt.Errorf("Main hash %q too short (wanted %d)", mainhash, prefixLength+suffixLength)
	}
	prefix := mainhash[:prefixLength]
	suffix := mainhash[prefixLength : prefixLength+suffixLength]
	return fmt.Sprintf("1-%s-%s-%s", prefix, lhash, suffix), nil
}

func (h *Hasher) ComputeFileHash(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("failed to open %q for hashing: %v", filename, err)
	}
	defer f.Close()

	rv, err := h.ComputeHash(f)
	if err != nil {
		return "", fmt.Errorf("failed to hash %q: %v", filename, err)
	}

	return rv, nil
}

func (h *Hasher) ComputeHash(r io.Reader) (string, error) {
	digest, length, err := h.computeHashV1(r)
	if err != nil {
		return "", fmt.Errorf("Failed to compute hash: %v", err)
	}

	ldigest, err := h.computeLengthHashV1(length)
	if err != nil {
		return "", fmt.Errorf("Failed to compute length-hash: %v", err)
	}

	rv, err := formatHashV1(digest, ldigest)
	if err != nil {
		return "", fmt.Errorf("Failed to format hash: %v", err)
	}
	return rv, nil
}

func (h *Hasher) VerifyHash(r io.Reader, size int64, hash string) (bool, error) {
	parsed, err := parseHash(hash)
	if err != nil {
		return false, err
	}
	if parsed.hashVersion != "1" {
		return false, fmt.Errorf("Unknown hash version %q", parsed.hashVersion)
	}

	lh, err := h.computeLengthHashV1(size)
	if err != nil {
		return false, err
	}
	if lh != parsed.lengthHash {
		return false, Mismatch
	}

	computedHash, err := h.ComputeHash(r)
	if err != nil {
		return false, fmt.Errorf("Failed to verify hash: %v", err)
	}

	if computedHash != hash {
		return false, Mismatch
	}

	return true, nil
}

func (h *Hasher) sanityCheck() error {
	hash, err := h.ComputeHash(strings.NewReader(""))
	if err != nil {
		return fmt.Errorf("Sanity check failed: Failed to compute hash: %v", err)
	}
	ok, err := h.VerifyHash(strings.NewReader(""), 0, hash)
	if err != nil {
		return fmt.Errorf("Sanity check failed: Failed to verify hash: %v", err)
	}
	if !ok {
		return fmt.Errorf("Sanity check failed: hash verification returned false")
	}
	return nil
}

func New(key []byte) (*Hasher, error) {
	rv := &Hasher{key: key}
	if err := rv.sanityCheck(); err != nil {
		return nil, err
	}
	return rv, nil
}

var deduhashRE = regexp.MustCompile(`^1-[0-9a-f]{20}-[0-9a-f]{3}-[0-9a-f]{20}$`)

func LooksLikeDeduhash(s string) bool {
	return deduhashRE.MatchString(s)
}
