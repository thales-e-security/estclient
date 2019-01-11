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

package estclient

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"testing"
	"time"

	"github.com/fullsailor/pkcs7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSelfSigned(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/example-root.pem")
	testError(t, err)

	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	testError(t, err)

	result, err := isSelfSigned(cert)
	testError(t, err)

	assert.True(t, result)
}

func TestParseCaCertsWithNoChainRSA(t *testing.T) {
	runCertBagTest(t, x509.SHA256WithRSA, func() (crypto.PrivateKey, crypto.PublicKey, error) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}

		return privKey, &privKey.PublicKey, nil
	})
}

func TestParseCaCertsWithNoChainECDSA(t *testing.T) {
	runCertBagTest(t, x509.ECDSAWithSHA256, func() (crypto.PrivateKey, crypto.PublicKey, error) {

		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		return privKey, &privKey.PublicKey, nil
	})
}

type keyGenerator func() (crypto.PrivateKey, crypto.PublicKey, error)

func runCertBagTest(t *testing.T, sigAlg x509.SignatureAlgorithm, generate keyGenerator) {
	subject := pkix.Name{
		CommonName: "EST TA",
	}

	// Make an old root cert
	template := x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		NotAfter:              time.Now().AddDate(1, 0, 0),
		NotBefore:             time.Now(),
		SerialNumber:          new(big.Int),
		SignatureAlgorithm:    sigAlg,
		Subject:               subject,
	}

	oldKey, oldKeyPub, err := generate()
	testError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, oldKeyPub, oldKey)
	testError(t, err)
	oldWithOld, err := x509.ParseCertificate(der)
	testError(t, err)

	template.NotAfter = template.NotAfter.AddDate(0, 0, 1)
	newKey, newKeyPub, err := generate()
	testError(t, err)
	der, err = x509.CreateCertificate(rand.Reader, &template, &template, newKeyPub, newKey)
	testError(t, err)
	estTA, err := x509.ParseCertificate(der)
	testError(t, err)

	der, err = x509.CreateCertificate(rand.Reader, &template, estTA, oldKeyPub, newKey)
	oldWithNew, err := x509.ParseCertificate(der)
	testError(t, err)

	der, err = x509.CreateCertificate(rand.Reader, &template, oldWithOld, newKeyPub, oldKey)
	testError(t, err)
	newWithOld, err := x509.ParseCertificate(der)
	testError(t, err)

	runParseTest(t, oldWithOld, oldWithNew, newWithOld, estTA)
}

// TestParseCaCertsWithNoChainDSA uses certs from disk, since Golang can't create DSA certs
func TestParseCaCertsWithNoChainDSA(t *testing.T) {
	nwn := readCertFromPemFileOrFail(t, "testdata/dsa-new-with-new.pem")
	nwo := readCertFromPemFileOrFail(t, "testdata/dsa-new-with-old.pem")
	own := readCertFromPemFileOrFail(t, "testdata/dsa-old-with-new.pem")
	owo := readCertFromPemFileOrFail(t, "testdata/dsa-old-with-old.pem")

	runParseTest(t, owo, own, nwo, nwn)
}

func readCertFromPemFileOrFail(t *testing.T, file string) *x509.Certificate {
	pemData, err := ioutil.ReadFile(file)
	require.NoError(t, err)

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("No data in pem file")
	}

	res, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	return res
}

func runParseTest(t *testing.T, owo, own, nwo, nwn *x509.Certificate) {
	// Chuck in a random order
	certReponse := own.Raw
	certReponse = append(certReponse, nwn.Raw...)
	certReponse = append(certReponse, nwo.Raw...)
	certReponse = append(certReponse, owo.Raw...)

	p7Data, err := pkcs7.DegenerateCertificate(certReponse)
	testError(t, err)

	result, err := parseCaCerts(base64.StdEncoding.EncodeToString(p7Data))
	testError(t, err)

	if assert.NotNil(t, result.EstTA) {
		assert.Equal(t, result.EstTA.Raw, nwn.Raw)
	}

	if assert.NotNil(t, result.NewWithOld) {
		assert.Equal(t, result.NewWithOld.Raw, nwo.Raw)
	}

	if assert.NotNil(t, result.OldWithOld) {
		assert.Equal(t, result.OldWithOld.Raw, owo.Raw)
	}

	if assert.NotNil(t, result.OldWithNew) {
		assert.Equal(t, result.OldWithNew.Raw, own.Raw)
	}
	assert.True(t, len(result.EstChainCerts) == 0)
}

func TestExampleCACertsData(t *testing.T) {
	// Test data taken from RFC 7030 Appendix
	b64, err := ioutil.ReadFile("testdata/example-cacerts.b64")
	testError(t, err)

	result, err := parseCaCerts(string(b64))
	testError(t, err)

	if assert.NotNil(t, result.EstTA) {
		assert.Equal(t, "estExampleCA NwN", result.EstTA.Subject.CommonName)
	}

	if assert.NotNil(t, result.NewWithOld) {
		assert.Equal(t, "estExampleCA NwO", result.NewWithOld.Subject.CommonName)
	}

	if assert.NotNil(t, result.OldWithOld) {
		assert.Equal(t, "estExampleCA OwO", result.OldWithOld.Subject.CommonName)
	}

	if assert.NotNil(t, result.OldWithNew) {
		assert.Equal(t, "estExampleCA OwN", result.OldWithNew.Subject.CommonName)
	}
}

func TestReadCertificate(t *testing.T) {
	_, err := readCertificate("not base64")
	assert.Error(t, err)

	_, err = readCertificate(base64.StdEncoding.EncodeToString([]byte("not valid pkcs7")))
	assert.Error(t, err)

	// Create two certs in one package, which should be rejected
	cert := readCertFromPemFileOrFail(t, "testdata/example-root.pem")

	data := cert.Raw
	data = append(data, cert.Raw...)

	doubleCertData, err := pkcs7.DegenerateCertificate(data)
	require.NoError(t, err)
	_, err = readCertificate(base64.StdEncoding.EncodeToString(doubleCertData))
	assert.Error(t, err)

	// Finally, check we can read a normal cert
	certData, err := pkcs7.DegenerateCertificate(cert.Raw)
	require.NoError(t, err)

	result, err := readCertificate(base64.StdEncoding.EncodeToString(certData))
	assert.Equal(t, cert, result)
}

func TestParseCACertsWithBadData(t *testing.T) {
	_, err := parseCaCerts("not base64")
	assert.Error(t, err)

	_, err = parseCaCerts(base64.StdEncoding.EncodeToString([]byte("not valid pkcs7")))
	assert.Error(t, err)
}
