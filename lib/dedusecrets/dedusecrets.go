package dedusecrets

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"github.com/steinarvk/dedu/lib/chunker"
	"github.com/steinarvk/dedu/lib/deduchunk"
	"github.com/steinarvk/dedu/lib/deduhash"
	"github.com/steinarvk/dedu/lib/obfuscate"
	"github.com/steinarvk/dedu/lib/quasihash"

	pb "github.com/steinarvk/dedu/gen/dedupb"
)

type Dedu struct {
	Hasher      *deduhash.Hasher
	Encrypter   tink.AEAD
	Chunker     *chunker.Chunker
	Packer      *deduchunk.Packer
	Obfuscator  *obfuscate.Obfuscator
	PcloudCreds *pb.PcloudCredentials
	Config      *pb.DeduConfig
	Quasihasher quasihash.Key
}

func LoadFromFile(secretsFilename, configFilename string) (*Dedu, error) {
	if secretsFilename == "" {
		return nil, fmt.Errorf("No secrets filename provided")
	}

	data, err := ioutil.ReadFile(secretsFilename)
	if err != nil {
		return nil, fmt.Errorf("Error reading %q: %v", secretsFilename, err)
	}

	secretsConfig := pb.DeduSecretsConfig{}
	if err := proto.UnmarshalText(string(data), &secretsConfig); err != nil {
		return nil, fmt.Errorf("Error parsing %q: %v", secretsFilename, err)
	}

	if secretsConfig.Config != nil && configFilename != "" {
		return nil, fmt.Errorf("Secrets config (%q) contains regular config, but config filename provided (%q)", secretsFilename, configFilename)
	}
	if secretsConfig.Config == nil && configFilename == "" {
		return nil, fmt.Errorf("No config filename provided")
	}
	if configFilename != "" {
		configData, err := ioutil.ReadFile(configFilename)
		if err != nil {
			return nil, fmt.Errorf("Error reading %q: %v", configFilename, err)
		}

		myConfig := pb.DeduConfig{}
		if err := proto.UnmarshalText(string(configData), &myConfig); err != nil {
			return nil, fmt.Errorf("Error parsing %q: %v", configFilename, err)
		}
		secretsConfig.Config = &myConfig
	}

	rv := &Dedu{Config: secretsConfig.Config}

	if len(secretsConfig.HashingKey) == 0 {
		return nil, fmt.Errorf("No hashing_key set")
	}

	hasher, err := deduhash.New(secretsConfig.HashingKey)
	if err != nil {
		return nil, err
	}
	rv.Hasher = hasher

	rv.Quasihasher = quasihash.Key(secretsConfig.HashingKey)

	switch v := secretsConfig.EncryptionKeys.Kind.(type) {
	case *pb.Keyset_UnencryptedTinkKeyset:
		keysetReader := keyset.NewBinaryReader(bytes.NewBuffer(v.UnencryptedTinkKeyset))
		kh, err := insecurecleartextkeyset.Read(keysetReader)
		if err != nil {
			return nil, fmt.Errorf("Error loading encryption keys: %v", err)
		}

		crypter, err := aead.New(kh)
		if err != nil {
			return nil, fmt.Errorf("Error loading encryption keys: %v", err)
		}

		rv.Encrypter = crypter

	default:
		return nil, fmt.Errorf("No known kind of encryption_keys set")
	}

	pc := secretsConfig.GetStorageCreds().Pcloud
	if pc.Username == "" || pc.Password == "" {
		return nil, fmt.Errorf("No storage_creds.pcloud provided: no known storage")
	}

	rv.PcloudCreds = pc

	rv.Chunker = &chunker.Chunker{
		Hasher:    rv.Hasher,
		ChunkSize: rv.Config.ChunkSize,
	}

	rv.Obfuscator = obfuscate.New()

	rv.Packer = &deduchunk.Packer{
		Encrypter:  rv.Encrypter,
		Hasher:     rv.Hasher,
		Obfuscator: rv.Obfuscator,
	}

	return rv, nil
}
