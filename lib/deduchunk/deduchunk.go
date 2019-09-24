package deduchunk

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"github.com/steinarvk/dedu/lib/deduhash"
	"github.com/steinarvk/dedu/lib/obfuscate"

	pb "github.com/steinarvk/dedu/gen/dedupb"
)

const (
	magicBlockSize = 16
)

type Packer struct {
	Hasher     *deduhash.Hasher
	Obfuscator *obfuscate.Obfuscator
	Encrypter  tink.AEAD
}

type ExtraData struct {
	VirtualChunk *pb.VirtualChunk
	Metadata     *pb.ChunkMetadata
}

func generateNewEncryptionKey() (tink.AEAD, []byte, error) {
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, nil, err
	}

	keysetBuf := bytes.NewBuffer(nil)
	keysetWriter := keyset.NewBinaryWriter(keysetBuf)
	if err := insecurecleartextkeyset.Write(kh, keysetWriter); err != nil {
		return nil, nil, err
	}

	rv, err := aead.New(kh)
	if err != nil {
		return nil, nil, err
	}
	return rv, keysetBuf.Bytes(), nil
}

func calculateHashes(content []byte) *pb.Hashes {
	rv := &pb.Hashes{}
	sha1Sum := sha1.Sum(content)
	md5Sum := md5.Sum(content)
	rv.Sha1 = sha1Sum[:]
	rv.Md5 = md5Sum[:]
	return rv
}

func (p *Packer) Pack(plaintext []byte, extra *ExtraData) ([]byte, error) {
	var chunkId string
	if extra != nil && extra.VirtualChunk != nil {
		if len(plaintext) > 0 {
			return nil, fmt.Errorf("Virtual chunk cannot have data")
		}
		chunkId = extra.VirtualChunk.ChunkId
		if chunkId == "" {
			return nil, fmt.Errorf("Virtual chunk ID not set")
		}
	} else {
		h, err := p.Hasher.ComputeHash(bytes.NewReader(plaintext))
		if err != nil {
			return nil, err
		}
		chunkId = h
	}

	chunkKey, chunkKeySerialized, err := generateNewEncryptionKey()
	if err != nil {
		return nil, err
	}

	privateHeader := pb.PrivateHeader{
		ChunkSpecificEncryptionKey: chunkKeySerialized,
		PlaintextLength:            int32(len(plaintext)),
	}

	if len(plaintext) > 0 {
		privateHeader.PlaintextHashes = calculateHashes(plaintext)
	}

	if extra != nil {
		privateHeader.VirtualChunk = extra.VirtualChunk
		privateHeader.OptionalMetadata = extra.Metadata
	}

	privateHeaderPlaintextBytes, err := proto.Marshal(&privateHeader)
	if err != nil {
		return nil, err
	}

	privateHeaderCryptotextBytes, err := p.Encrypter.Encrypt(privateHeaderPlaintextBytes, nil)
	if err != nil {
		return nil, err
	}

	publicHeader := pb.PublicHeader{
		ChunkId:             chunkId,
		PrivateHeaderLength: int32(len(privateHeaderCryptotextBytes)),
	}

	publicHeaderPlaintextBytes, err := proto.Marshal(&publicHeader)
	if err != nil {
		return nil, err
	}

	emptyPassword := ""

	publicHeaderObfuscatedBytes, err := p.Obfuscator.Obfuscate(publicHeaderPlaintextBytes, emptyPassword)
	if err != nil {
		return nil, err
	}

	magicHeader := pb.MagicHeader{
		Dedu:               "DEDU",
		ProtocolVersion:    1,
		PublicHeaderLength: int32(len(publicHeaderObfuscatedBytes)),
	}

	magicHeaderPlaintextBytes, err := proto.Marshal(&magicHeader)
	if err != nil {
		return nil, err
	}

	magicHeaderObfuscatedBlock, err := p.Obfuscator.ObfuscateBlock(magicHeaderPlaintextBytes, emptyPassword)
	if err != nil {
		return nil, err
	}

	if len(magicHeaderObfuscatedBlock) != magicBlockSize {
		return nil, fmt.Errorf("Sanity check failed: produced header block of length %d", len(magicHeaderObfuscatedBlock))
	}

	headers := append(magicHeaderObfuscatedBlock, append(publicHeaderObfuscatedBytes, privateHeaderCryptotextBytes...)...)

	cryptotext, err := chunkKey.Encrypt(plaintext, nil)
	if err != nil {
		return nil, err
	}

	return append(headers, cryptotext...), nil
}

func (p *Packer) Unpack(packed []byte) ([]byte, *pb.Header, error) {
	rv, hdr, err := p.unpack(packed)
	if err != nil {
		return nil, nil, fmt.Errorf("Invalid chunk: %v", err)
	}
	return rv, hdr, nil
}

func (p *Packer) unpack(packed []byte) ([]byte, *pb.Header, error) {
	r := bytes.NewReader(packed)

	emptyPassword := ""

	magicBlockObfuscatedBytes := make([]byte, magicBlockSize)
	if _, err := io.ReadFull(r, magicBlockObfuscatedBytes); err != nil {
		return nil, nil, err
	}
	magicBlockBytes, err := p.Obfuscator.UnobfuscateBlock(magicBlockObfuscatedBytes, emptyPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("Bad magic block obfuscation")
	}
	magicBlock := pb.MagicHeader{}
	if err := proto.Unmarshal(magicBlockBytes, &magicBlock); err != nil {
		return nil, nil, fmt.Errorf("Unable to parse magic block: %v", err)
	}
	if magicBlock.ProtocolVersion != 1 {
		return nil, nil, fmt.Errorf("Magic block had unknown ProtocolVersion: %d", magicBlock.ProtocolVersion)
	}
	if magicBlock.PublicHeaderLength <= 0 {
		return nil, nil, fmt.Errorf("Magic block had bad public header length: %d", magicBlock.PublicHeaderLength)
	}

	publicHeaderObfuscatedBytes := make([]byte, magicBlock.PublicHeaderLength)
	if _, err := io.ReadFull(r, publicHeaderObfuscatedBytes); err != nil {
		return nil, nil, err
	}
	publicHeaderBytes, err := p.Obfuscator.Unobfuscate(publicHeaderObfuscatedBytes, emptyPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to unobfuscate public header: %v", err)
	}
	publicHeader := pb.PublicHeader{}
	if err := proto.Unmarshal(publicHeaderBytes, &publicHeader); err != nil {
		return nil, nil, fmt.Errorf("Unable to parse public header: %v", err)
	}
	if publicHeader.PrivateHeaderLength <= 0 {
		return nil, nil, fmt.Errorf("Public header had bad private header length: %d", publicHeader.PrivateHeaderLength)
	}

	privateHeaderEncryptedBytes := make([]byte, publicHeader.PrivateHeaderLength)
	if _, err := io.ReadFull(r, privateHeaderEncryptedBytes); err != nil {
		return nil, nil, err
	}
	privateHeaderPlaintextBytes, err := p.Encrypter.Decrypt(privateHeaderEncryptedBytes, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to decrypt private header: %v", err)
	}
	privateHeader := pb.PrivateHeader{}
	if err := proto.Unmarshal(privateHeaderPlaintextBytes, &privateHeader); err != nil {
		return nil, nil, fmt.Errorf("Error parsing private header: %v", err)
	}

	keysetReader := keyset.NewBinaryReader(bytes.NewBuffer(privateHeader.ChunkSpecificEncryptionKey))
	kh, err := insecurecleartextkeyset.Read(keysetReader)
	if err != nil {
		return nil, nil, fmt.Errorf("Error loading chunk-specific encryption keys: %v", err)
	}

	chunkSpecificCrypter, err := aead.New(kh)
	if err != nil {
		return nil, nil, fmt.Errorf("Error loading chunk-specific encryption keys: %v", err)
	}

	rest, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := chunkSpecificCrypter.Decrypt(rest, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("Error decrypting data: %v", err)
	}

	header := &pb.Header{
		Magic:   &magicBlock,
		Public:  &publicHeader,
		Private: &privateHeader,
	}

	if len(plaintext) > 0 {
		ok, err := p.Hasher.VerifyHash(bytes.NewReader(plaintext), int64(len(plaintext)), header.Public.ChunkId)
		if !ok || err != nil {
			return nil, nil, fmt.Errorf("Content chunk ID (%q) does not match decrypted data of %d bytes (%v)", header.Public.ChunkId, len(plaintext), err)
		}
	}

	return plaintext, header, nil
}
