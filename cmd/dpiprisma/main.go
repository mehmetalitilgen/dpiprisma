package main

import (
	"fmt"

	tlsx "github.com/mehmetalitilgen/dpiprisma/internal"
)

func main() {

	_ , pub := tlsx.X25519Keypair()
	fmt.Println(pub)

	

}