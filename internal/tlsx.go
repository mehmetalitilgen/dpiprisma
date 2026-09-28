package tlsx

import (
	"crypto/ecdh"
	"crypto/rand"
)


func X25519Keypair() (priv []byte, pub []byte) {
	priv = make([]byte, 32)
	rand.Read(priv) 
	
	key, err := ecdh.X25519().NewPrivateKey(priv)

	if err != nil {
		panic(err) 
	}
	return priv, key.PublicKey().Bytes()
}


func buildClientHello() []byte {
	
}