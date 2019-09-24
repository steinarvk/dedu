package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/steinarvk/dedu/lib/pcloud"
	"github.com/steinarvk/orc"

	orcdedu "github.com/steinarvk/dedu/module/orc-dedu"
)

var downloadCmd = orc.Command(debugCmd, orc.Modules(orcdedu.M), cobra.Command{
	Use:   "download",
	Short: "Download a chunk and write it to stdout",
}, func(chunkIds []string) error {
	ctx := context.Background()

	dedu := orcdedu.M.Dedu

	storage, err := pcloud.New(ctx, dedu.PcloudCreds, dedu.Config.PcloudTargetFolder)
	if err != nil {
		return err
	}

	conn := storage.Connection(ctx)

	for _, chunkId := range chunkIds {
		packed, err := conn.Get(ctx, chunkId)
		if err != nil {
			return err
		}

		plaintext, headers, err := dedu.Packer.Unpack(packed)
		if err != nil {
			return err
		}

		logrus.Infof("Read chunk %q with headers: %v", chunkId, headers)

		if headers.Private.VirtualChunk == nil {
			os.Stdout.Write(plaintext)
			continue
		}

		var content []byte

		for _, subchunk := range headers.Private.VirtualChunk.Chunk {
			subchunkId := subchunk.Hash

			packed, err := conn.Get(ctx, subchunkId)
			if err != nil {
				return err
			}

			plaintext, headers, err := dedu.Packer.Unpack(packed)
			if err != nil {
				return err
			}

			logrus.Infof("Read subchunk %q with headers: %v", subchunkId, headers)

			if headers.Private.VirtualChunk != nil {
				return fmt.Errorf("Subchunk cannot be virtual")
			}

			content = append(content, plaintext...)
		}

		computedHash, err := dedu.Hasher.ComputeHash(bytes.NewReader(content))
		if err != nil {
			return err
		}

		logrus.Infof("Reconstructed content has hash %q (wanted %q) and length %d (wanted %d)", computedHash, chunkId, len(content), headers.Private.VirtualChunk.TotalLength)

		if computedHash != chunkId {
			return fmt.Errorf("Failed to reach expected chunkId (%q vs %q)", chunkId, computedHash)
		}

		os.Stdout.Write(content)
	}
	return nil
})
