package main

import "crypto/tls"

func verifiedConfiguration() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func main() {
	_ = verifiedConfiguration()
}
