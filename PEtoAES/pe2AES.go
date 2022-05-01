package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/Enelg52/Backpack/runpe"
	"io"
	"io/ioutil"
	"os"
)

func main() {
	path := flag.String("p", "C:\\Users\\enelg\\Documents\\mimikatz.exe", "path")
	key := flag.String("k", "12345678901234567890123456789012", "key for encryption")
	flag.Parse()
	peToAES(*path, *key)
}

func peToAES(destPath string, key string) {
	if len(key) != 32 {
		fmt.Println("[-] The key needs to be 12 chars long")
		return
	}
	byteKey := []byte(key)
	destPE, err := ioutil.ReadFile(destPath)
	runpe.CheckErr(err)
	file1, err := os.Create("../pe.txt")
	runpe.CheckErr(err)
	defer file1.Close()

	hexPayload := hex.EncodeToString(destPE)
	aesPayload, _ := encrypt([]byte(hexPayload), byteKey)
	_, err = fmt.Fprintf(file1, "%s", aesPayload)
	runpe.CheckErr(err)

	file2, err := os.Create("../key.txt")
	runpe.CheckErr(err)
	defer file1.Close()

	_, err = fmt.Fprintf(file2, "%s", key)
	runpe.CheckErr(err)

	fmt.Println("[+] Done !")
}

func encrypt(plainText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	runpe.CheckErr(err)
	gcm, err := cipher.NewGCM(block)
	runpe.CheckErr(err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	runpe.CheckErr(err)
	cypherText := gcm.Seal(nonce, nonce, plainText, nil)
	return cypherText, nil
}
