package cmd

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/steinarvk/dedu/lib/deduchunk"
	"github.com/steinarvk/dedu/lib/pcloud"
	"github.com/steinarvk/orc"

	pb "github.com/steinarvk/dedu/gen/dedupb"
	orcdedu "github.com/steinarvk/dedu/module/orc-dedu"
)

var uploadCmd = orc.Command(debugCmd, orc.Modules(orcdedu.M), cobra.Command{
	Use:   "upload",
	Short: "Hash, chunk, pack, and upload a file",
}, func(files []string) error {
	ctx := context.Background()

	dedu := orcdedu.M.Dedu

	storage, err := pcloud.New(ctx, dedu.PcloudCreds, dedu.Config.PcloudTargetFolder)
	if err != nil {
		return err
	}

	conn := storage.Connection(ctx)

	for _, file := range files {
		var remoteChunks []*pb.ChunkReference
		var remoteBlob *pb.VirtualChunk

		for chunk := range dedu.Chunker.ReadFile(file) {
			logrus.Infof("Processing chunk!")
			if chunk.Error != nil {
				return chunk.Error
			}
			if chunk.Metadata != nil {
				if chunk.Metadata.Chunk != nil {
					remoteChunks = append(remoteChunks, chunk.Metadata.Chunk)
				}
			}
			if chunk.Final {
				remoteBlob = &pb.VirtualChunk{
					ChunkId:     chunk.FinalHash,
					TotalLength: chunk.FinalLength,
					Chunk:       remoteChunks,
				}
			}

			chunkName := chunk.Metadata.HashOfPlaintext
			packed, err := dedu.Packer.Pack(chunk.Plaintext, nil)
			if err != nil {
				return err
			}
			if err := conn.Put(ctx, chunkName, packed); err != nil {
				if err != pcloud.AlreadyExists {
					return err
				} else {
					fmt.Printf("Already exists: %s\n", chunkName)
				}
			} else {
				fmt.Printf("Uploaded: %s\n", chunkName)
			}
		}

		if remoteBlob != nil && len(remoteBlob.Chunk) > 1 {
			chunkName := remoteBlob.ChunkId
			packed, err := dedu.Packer.Pack(nil, &deduchunk.ExtraData{
				VirtualChunk: remoteBlob,
			})
			if err != nil {
				return err
			}
			if err := conn.Put(ctx, chunkName, packed); err != nil {
				if err != pcloud.AlreadyExists {
					return err
				} else {
					fmt.Printf("Already exists: %s\n", chunkName)
				}
			} else {
				fmt.Printf("Uploaded: %s [virtual]\n", chunkName)
			}
		}
	}
	return nil
})
