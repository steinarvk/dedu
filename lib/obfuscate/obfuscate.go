package obfuscate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"sync"

	cryptorand "crypto/rand"

	"golang.org/x/crypto/pbkdf2"
)

var salt = []byte("DEDUDEDU")

const (
	iterationCount = 4096
	keyLength      = 16
	blockSize      = 16
	nonceSize      = 12
)

type Obfuscator struct {
	mu       sync.Mutex
	keyCache map[string][]byte
}

func New() *Obfuscator {
	rv := &Obfuscator{}
	rv.deriveKey("")
	return rv
}

func (o *Obfuscator) deriveKey(password string) []byte {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.keyCache == nil {
		o.keyCache = map[string][]byte{}
	}

	key, ok := o.keyCache[password]
	if !ok {
		key = pbkdf2.Key([]byte(password), salt, iterationCount, keyLength, sha1.New)
		o.keyCache[password] = key
	}
	return key
}

func (o *Obfuscator) deriveBlockCipher(password string) (cipher.Block, error) {
	key := o.deriveKey(password)
	return aes.NewCipher(key)
}

func (o *Obfuscator) ObfuscateBlock(plaintext []byte, password string) ([]byte, error) {
	cipher, err := o.deriveBlockCipher(password)
	if err != nil {
		return nil, err
	}

	n := len(plaintext)
	if (n + 1) > cipher.BlockSize() {
		return nil, fmt.Errorf("Plaintext too long (%d+1 bytes > %d, block size)", len(plaintext), cipher.BlockSize())
	}
	if n > 255 {
		return nil, fmt.Errorf("Plaintext too long (%d bytes > %d, protocol limit)", len(plaintext), 255)
	}

	taggedPlaintext := append([]byte{byte(n)}, plaintext...)

	for len(taggedPlaintext) < cipher.BlockSize() {
		taggedPlaintext = append(taggedPlaintext, 0)
	}

	buf := make([]byte, blockSize)
	cipher.Encrypt(buf, taggedPlaintext)

	return buf, nil
}

func (o *Obfuscator) UnobfuscateBlock(cryptotext []byte, password string) ([]byte, error) {
	cipher, err := o.deriveBlockCipher(password)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, blockSize)
	cipher.Decrypt(buf, cryptotext)
	length := int(buf[0])

	if length+1 >= len(buf) {
		return nil, fmt.Errorf("Plaintext does not contain %d bytes", length)
	}

	return buf[1 : length+1], nil
}

func (o *Obfuscator) Obfuscate(plaintext []byte, password string) ([]byte, error) {
	bc, err := o.deriveBlockCipher(password)
	if err != nil {
		return nil, err
	}

	crypter, err := cipher.NewGCMWithNonceSize(bc, nonceSize)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, err
	}

	return crypter.Seal(nonce, nonce, plaintext, nil), nil
}

func (o *Obfuscator) Unobfuscate(cryptotext []byte, password string) ([]byte, error) {
	bc, err := o.deriveBlockCipher(password)
	if err != nil {
		return nil, err
	}

	crypter, err := cipher.NewGCMWithNonceSize(bc, nonceSize)
	if err != nil {
		return nil, err
	}

	if len(cryptotext) < nonceSize {
		return nil, fmt.Errorf("Cryptotext too short (nonce is %d bytes)", nonceSize)
	}

	nonce := cryptotext[:nonceSize]
	actualCryptotext := cryptotext[nonceSize:]

	plaintext, err := crypter.Open(nil, nonce, actualCryptotext, nil)
	if err != nil {
		return nil, fmt.Errorf("Decryption failed: %v", err)
	}

	return plaintext, nil
}
