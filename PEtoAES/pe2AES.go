package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/Enelg52/GoHollowPacker/runpe"
	"io"
	"io/ioutil"
	"os"
)

func main() {
	path := flag.String("p", "C:\\Users\\yanng\\Documents\\Root\\mimikatz\\mimikatz_trunk\\x64\\mimikatz.exe", "path")
	key := flag.String("k", "12345678901234567890123456789044", "key for encryption")
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
	f, err := os.Create("pe.txt")
	runpe.CheckErr(err)
	defer f.Close()

	hexPayload := hex.EncodeToString(destPE)
	aesPayload, _ := encrypt([]byte(hexPayload), byteKey)
	_, err = fmt.Fprintf(f, "%s", aesPayload)
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
