// Command adbtest exercises the adb client with an existing adbkey (dev only).
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"tvbridge/adb"
)

func main() {
	b, _ := os.ReadFile(os.Args[1])
	blk, _ := pem.Decode(b)
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		panic(err)
	}
	out, err := adb.Shell(os.Args[2], k.(*rsa.PrivateKey), os.Args[3], 5*time.Second)
	fmt.Printf("out=%q err=%v\n", out, err)
}
