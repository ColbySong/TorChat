package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
)

var label = []byte("")
var hash = sha256.New()

func RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptOAEP(hash, rand.Reader, pub, plainText, label)
	if err != nil {
		HandleNonFatalError("Could not encrypt message", err)
		return nil, err
	}

	return cipherText, nil
}

func RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	plainText, err := rsa.DecryptOAEP(hash, rand.Reader, priv, cipherText, label)
	if err != nil {
		HandleNonFatalError("Could not decrypt message", err)
		return nil, err
	}

	return plainText, nil
}

func GenerateAESKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	HandleFatalError("Could not generate random AES key", err)

	return key
}

func PubKeyToString(key ecdsa.PublicKey) string {
	return hex.EncodeToString(elliptic.Marshal(key.Curve, key.X, key.Y))
}
