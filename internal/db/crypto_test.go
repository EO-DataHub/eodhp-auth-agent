package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupCrypto() *crypto {
	crypto, err := newCrypto("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		panic(err)
	}
	return crypto
}

func TestCrypto_EncryptThenDecode_OriginalValue(t *testing.T) {
	crypto := setupCrypto()

	originalValue := "test"
	encryptedValue, err := crypto.encrypt(originalValue)
	assert.NoError(t, err)

	decryptedValue, err := crypto.decrypt(encryptedValue)
	assert.NoError(t, err)
	assert.Equal(t, originalValue, decryptedValue)
}

func TestCrypto_HashTwice_SameValue(t *testing.T) {
	crypto := setupCrypto()

	value := "test"
	hashValue1 := crypto.hash(value)
	hashValue2 := crypto.hash(value)

	assert.Equal(t, hashValue1, hashValue2)
}
