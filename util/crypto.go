package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

var label = []byte("")
var hash = sha256.New()

func RSAEncrypt(pub *rsa.PublicKey, plainText []byte) []byte {
	cipherText, err := rsa.EncryptOAEP(hash, rand.Reader, pub, plainText, label)
	HandleFatalError("Could not encrypt message", err)
	OutLog.Printf("OAEP encrypted [%s] to \n[%x]\n", string(plainText), cipherText)

	return cipherText
}

func RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) []byte {
	plainText, err := rsa.DecryptOAEP(hash, rand.Reader, priv, cipherText, label)
	HandleFatalError("Could not decrypt message", err)
	OutLog.Printf("OAEP decrypted [%x] to \n[%s]\n", cipherText, plainText)

	return plainText
}

func GenerateAESKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	HandleFatalError("Could not generate random AES key", err)

	return key
}
