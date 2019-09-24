package cmd

import (
	"bytes"
	"fmt"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/steinarvk/orc"

	cryptorand "crypto/rand"

	pb "github.com/steinarvk/dedu/gen/dedupb"
)

func init() {
	var secretsConfigFile string

	generateSecretsCmd := orc.Command(Root, orc.Modules(), cobra.Command{
		Use:   "generate-secrets",
		Short: "Generate hashing and encryption keys",
	}, func(files []string) error {
		if secretsConfigFile == "" {
			return fmt.Errorf("missing required flag: --secrets_output_file")
		}

		secretsConfig := pb.DeduSecretsConfig{}

		randombytes := make([]byte, 1024)
		_, err := cryptorand.Read(randombytes)
		if err != nil {
			return err
		}

		secretsConfig.HashingKey = randombytes

		kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
		if err != nil {
			return err
		}

		keysetBuf := bytes.NewBuffer(nil)
		keysetWriter := keyset.NewBinaryWriter(keysetBuf)
		if err := insecurecleartextkeyset.Write(kh, keysetWriter); err != nil {
			return err
		}
		secretsConfig.EncryptionKeys = &pb.Keyset{
			Kind: &pb.Keyset_UnencryptedTinkKeyset{
				UnencryptedTinkKeyset: keysetBuf.Bytes(),
			},
		}

		data := []byte(proto.MarshalTextString(&secretsConfig))

		f, err := os.OpenFile(secretsConfigFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(0600))
		if err != nil {
			return fmt.Errorf("Error opening %q: %v", secretsConfigFile, err)
		}

		if _, err := f.Write(data); err != nil {
			return fmt.Errorf("Error writing %q: %v", secretsConfigFile, err)
		}

		if err := f.Close(); err != nil {
			return fmt.Errorf("Error writing %q: %v", err)
		}

		logrus.Infof("Wrote secrets to %q (%d bytes)", secretsConfigFile, len(data))

		return nil
	})

	generateSecretsCmd.Flags().StringVar(&secretsConfigFile, "secrets_output_file", "", "filename of secrets file to create")
}
