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

func TestCrypto_EncryptTwice_SameValue(t *testing.T) {
	crypto := setupCrypto()

	value := "test"
	encryptedValue1, err := crypto.encrypt(value)
	assert.NoError(t, err)

	encryptedValue2, err := crypto.encrypt(value)
	assert.NoError(t, err)

	assert.Equal(t, encryptedValue1, encryptedValue2)
}
