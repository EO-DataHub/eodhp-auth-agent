package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

type crypto struct {
	Key string
	gcm cipher.AEAD
}

func newCrypto(key string) (*crypto, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	c := &crypto{
		Key: key,
		gcm: gcm,
	}
	return c, nil
}

func (c crypto) encrypt(plainText string) (string, error) {
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := c.gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func (c crypto) decrypt(cipherText string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	nonceSize := c.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", err
	}

	nonce, cipherText := data[:nonceSize], string(data[nonceSize:])
	plainText, err := c.gcm.Open(nil, nonce, []byte(cipherText), nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
