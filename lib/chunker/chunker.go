package chunker

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/steinarvk/dedu/lib/deduhash"

	pb "github.com/steinarvk/dedu/gen/dedupb"
)

type Chunk struct {
	Metadata    *pb.LocalResourceChunk
	Plaintext   []byte
	Final       bool
	FinalLength int64
	Empty       bool
	FinalHash   string
	Error       error
}

type Chunker struct {
	Hasher    *deduhash.Hasher
	ChunkSize int64
}

const (
	bufSize          = 10
	DefaultChunkSize = 1024 * 1024
)

func (c *Chunker) ReadFile(name string) <-chan Chunk {
	path, err := filepath.Abs(name)
	if err != nil {
		returnError(err)
	}

	outCh := make(chan Chunk, bufSize)

	go func() {
		defer func() {
			logrus.Infof("All done in ReadFile(%q)", name)
			close(outCh)
		}()

		f, err := os.Open(path)
		if err != nil {
			outCh <- Chunk{Error: err}
			return
		}
		defer f.Close()

		for chunk := range c.Read(path, f) {
			outCh <- chunk
		}
	}()

	return outCh
}

func returnError(err error) <-chan Chunk {
	outCh := make(chan Chunk, 1)
	outCh <- Chunk{Error: err}
	return outCh
}

func (c *Chunker) Read(name string, r io.Reader) <-chan Chunk {
	chunkSize := c.ChunkSize
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}

	var finalHash string
	var finalHashErr error
	wg := sync.WaitGroup{}
	wg.Add(1)
	pipeReader, pipeWriter := io.Pipe()
	r = io.TeeReader(r, pipeWriter)
	go func() {
		logrus.Infof("Beginning hashing of complete file %q", name)
		finalHash, finalHashErr = c.Hasher.ComputeHash(pipeReader)
		logrus.Infof("Finished hashing of complete file %q", name)
		wg.Done()
	}()

	outCh := make(chan Chunk, bufSize)

	var nextChunk *Chunk

	var offset int64

	go func() {
		defer func() {
			if nextChunk != nil {
				nextChunk.Error = fmt.Errorf("Closed prematurely")
				outCh <- *nextChunk
			}
			close(outCh)
		}()

		for {
			if nextChunk != nil {
				outCh <- *nextChunk
				nextChunk = nil
			}

			logrus.Infof("Reading up to %d bytes from offset %d of %q", chunkSize, offset, name)

			buf := make([]byte, chunkSize)

			bytesRead, err := io.ReadFull(r, buf)
			eof := err == io.EOF || err == io.ErrUnexpectedEOF
			if !eof && err != nil {
				logrus.Infof("Error reading %q: %v", err)
				outCh <- Chunk{Error: err}
				return
			}

			plaintextBytes := buf[:bytesRead]

			if len(plaintextBytes) > 0 {
				plaintextHash, err := c.Hasher.ComputeHash(bytes.NewReader(plaintextBytes))
				if err != nil {
					outCh <- Chunk{Error: err}
					return
				}

				md := pb.LocalResourceChunk{
					ResourceName:    name,
					Offset:          offset,
					Length:          int64(len(plaintextBytes)),
					HashOfPlaintext: plaintextHash,
					Chunk: &pb.ChunkReference{
						Hash:   plaintextHash,
						Length: int64(len(plaintextBytes)),
					},
				}

				nextChunk = &Chunk{
					Metadata:  &md,
					Plaintext: plaintextBytes,
				}
			}

			offset += int64(len(plaintextBytes))

			if eof {
				if err := pipeWriter.Close(); err != nil {
					outCh <- Chunk{Error: err}
					return
				}
				logrus.Infof("Reached EOF of %q after %d bytes", name, offset)
				if nextChunk == nil {
					if offset > 0 {
						logrus.Fatalf("Sanity check violated: EOF reached with no nextChunk, but data was read")
					}
					nextChunk = &Chunk{
						Empty: true,
					}
				}
				nextChunk.Final = true
				logrus.Infof("Waiting for complete-file hashing")
				wg.Wait()
				logrus.Infof("Done waiting for complete-file hashing")
				if finalHashErr != nil {
					outCh <- Chunk{Error: finalHashErr}
					return
				}
				nextChunk.FinalHash = finalHash
				nextChunk.FinalLength = offset
				outCh <- *nextChunk
				nextChunk = nil
				logrus.Infof("All done with %q", name)
				return
			}
		}
	}()
	return outCh
}
