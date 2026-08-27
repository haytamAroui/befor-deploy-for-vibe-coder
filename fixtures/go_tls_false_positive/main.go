package main

import "crypto/tls"

// Example only: &tls.Config{InsecureSkipVerify: true}
const documentation = "tls.Config{InsecureSkipVerify: true}"
const rawDocumentation = `tls.Config{InsecureSkipVerify: true}`

func verifiedConfiguration() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func main() {
	_ = documentation
	_ = rawDocumentation
	_ = verifiedConfiguration()
}
