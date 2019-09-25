// Package quasihash computes a checksum of a seekable file in constant time by reading only parts of it.
package quasihash

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
)

var ErrIsDir = errors.New("cannot hash directory")

type Key []byte

var fixedSalt = []byte("dedu.quasihash.1")

const (
	lengthHashLength  = 3
	contentHashLength = 20
	chunkSize         = 20 * 4096
	numChunks         = 8
)

func formatHashV1(fileSizeDigest, contentDigest []byte) string {
	// Mix the length hash (which will have a lot of collisions) into the
	// middle of the hash, to make the has more easily visually
	// distinguishable by either its prefix or its suffix.

	lengthHashHex := fmt.Sprintf("%x", fileSizeDigest)[:lengthHashLength]
	contentHashHex := fmt.Sprintf("%x", contentDigest)[:contentHashLength]

	n := len(contentHashHex) / 2
	leftHex := contentHashHex[:n]
	rightHex := contentHashHex[n:]

	return fmt.Sprintf("q1-%s-%s-%s", leftHex, lengthHashHex, rightHex)
}

func chunkOffsets(totalSize int64, chunkSize int64, numChunks int) ([]int64, error) {
	if chunkSize*int64(numChunks) >= totalSize {
		return nil, fmt.Errorf("file too small for chunking")
	}

	if numChunks < 2 {
		return nil, fmt.Errorf("no strategy for only %d chunks", numChunks)
	}

	lastChunkOffset := totalSize - chunkSize

	rv := []int64{0}

	skip := lastChunkOffset / int64(numChunks-1)

	for i := 1; i < numChunks; i++ {
		rv = append(rv, skip*int64(i))
	}
	rv = append(rv, lastChunkOffset)
	return rv, nil
}

func (k Key) QuasihashFile(path string) (string, error) {
	mac := hmac.New(sha256.New, []byte(k))

	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	if info.IsDir() {
		return "", ErrIsDir
	}

	totalSize := info.Size()
	mac.Write(fixedSalt)

	mac.Write([]byte(fmt.Sprintf("%d", totalSize)))

	fileSizeOnlyHash := mac.Sum(nil)

	if totalSize <= (chunkSize * numChunks) {
		// File is too small for the chunking strategy.
		// Just read all of it.
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return "", err
		}
		if int64(len(data)) != totalSize {
			return "", fmt.Errorf("file size changed while hashing")
		}

		logrus.Debugf("hashing entire file offsets: %v", len(data))

		mac.Write(data)
	} else {
		offsets, err := chunkOffsets(totalSize, chunkSize, numChunks)
		if err != nil {
			return "", err
		}

		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()

		logrus.Debugf("hash offsets: %v", offsets)

		for _, offset := range offsets {
			actualOffset, err := f.Seek(offset, 0)
			if err != nil {
				return "", err
			}
			if offset != actualOffset {
				return "", fmt.Errorf("seeked to %d but arrived at %d", offset, actualOffset)
			}

			buf := make([]byte, chunkSize)

			if _, err := io.ReadFull(f, buf); err != nil {
				return "", err
			}

			logrus.Infof("read from %d/%d to %d/%d; adding to hash", offset, totalSize, offset+chunkSize, totalSize)
			mac.Write(buf)
		}
	}

	logrus.Debugf("finalhash: %x", mac.Sum(nil))
	logrus.Debugf("finalhash: %x", mac.Sum(nil))

	return formatHashV1(fileSizeOnlyHash, mac.Sum(nil)), nil
}

func (k Key) QuasihashVerifyFile(path, quasihash string) (bool, error) {
	// TODO: very inefficient, could check the length first.
	// TODO: could check the length first!

	h, err := k.QuasihashFile(path)
	if err != nil {
		return false, err
	}

	return h == quasihash, nil
}
