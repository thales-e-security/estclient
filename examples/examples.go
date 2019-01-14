// Copyright 2019 Thales eSecurity
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"github.com/thales-e-security/estclient"
)

var (
	id     = "estuser"
	secret = "estpwd"
)

// main contains examples used in documentation
func main() {

	client := estclient.NewEstClient("testrfc7030.com:8443")

	cacerts, err := client.CaCerts()
	panicOnError(err)

	fmt.Printf("EST Root Cert: %+v\n", cacerts.EstTA.Subject)
	fmt.Printf("Old EST Root Cert: %+v\n", cacerts.OldWithOld)
	fmt.Printf("Old Cert Signed By New Key: %+v\n", cacerts.OldWithNew)
	fmt.Printf("New Cert Signed By Old Key: %+v\n", cacerts.NewWithOld)
	fmt.Printf("Other chain certs: %+v\n", cacerts.EstChainCerts)

	// Create key and certificate request
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	panicOnError(err)

	template := x509.CertificateRequest{Subject: pkix.Name{CommonName: "Test"}}

	reqBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	panicOnError(err)

	req, err := x509.ParseCertificateRequest(reqBytes)
	panicOnError(err)

	// Enroll with EST CA
	authData := estclient.AuthData{ID: &id, Secret: &secret}

	cert, err := client.SimpleEnroll(authData, req)
	panicOnError(err)
	fmt.Printf("Initial cert (DER): %x\n", cert.Raw)

	// Re-enroll with EST CA
	authData = estclient.AuthData{ID: &id, Secret: &secret, Key: key, ClientCert: cert}
	cert2, err := client.SimpleReenroll(authData, req)
	panicOnError(err)
	fmt.Printf("Renewed cert (DER): %x\n", cert2.Raw)
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}
