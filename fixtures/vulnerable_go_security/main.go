package main

import "crypto/tls"

func unsafeConfiguration() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

func main() {
	_ = unsafeConfiguration()
}
