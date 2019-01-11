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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testError(t *testing.T, err error) {
	require.NoError(t, err, "%+v", err)
}

func TestCaCerts(t *testing.T) {
	builder := &stubBuilder{api: stubAPI{t: t}}
	client := newEstClient(builder)

	_, err := client.CaCerts()
	testError(t, err)

	assert.Nil(t, builder.lastKey)
	assert.Nil(t, builder.lastCert)
}

func TestSimpleEnroll(t *testing.T) {
	builder := &stubBuilder{api: stubAPI{t: t}}
	client := newEstClient(builder)

	_, req, err := makeCertReq(nil)
	testError(t, err)

	_, err = client.SimpleEnroll(estID, estSecret, req)
	testError(t, err)

	assert.Nil(t, builder.lastKey)
	assert.Nil(t, builder.lastCert)
}

func TestSimpleReenroll(t *testing.T) {
	builder := &stubBuilder{api: stubAPI{t: t}}
	client := newEstClient(builder)

	key, req, err := makeCertReq(nil)
	testError(t, err)

	cert, err := client.SimpleEnroll(estID, estSecret, req)
	testError(t, err)

	assert.Nil(t, builder.lastKey)
	assert.Nil(t, builder.lastCert)

	_, req2, err := makeCertReq(key)

	// First check that we can't re-enroll without passing old key material
	_, err = client.SimpleReenroll(&estID, &estSecret, key, nil, req2)
	assert.Error(t, err)

	_, err = client.SimpleReenroll(&estID, &estSecret, nil, cert, req2)
	assert.Error(t, err)

	// Now perform the actual test
	_, err = client.SimpleReenroll(&estID, &estSecret, key, cert, req2)
	testError(t, err)

	assert.Equal(t, key, builder.lastKey)
	assert.Equal(t, cert, builder.lastCert)
}

// brokenBuilder fails to build server APIs
type brokenBuilder struct{}

func (brokenBuilder) Build(currentKey *rsa.PrivateKey, currentCert *x509.Certificate) (serverAPI, error) {
	return nil, errors.New("boom")
}

func TestBrokenBuilder(t *testing.T) {
	builder := brokenBuilder{}
	client := newEstClient(builder)
	runErrorTestsOnClient(t, client)
}

func runErrorTestsOnClient(t *testing.T, client EstClient) {
	_, err := client.CaCerts()
	assert.Error(t, err)

	key, req, err := makeCertReq(nil)
	testError(t, err)

	_, err = client.SimpleEnroll(estID, estSecret, req)
	assert.Error(t, err)

	_, req2, err := makeCertReq(nil)
	testError(t, err)

	// Borrow an unrelated certificate
	cert := readCertFromPemFileOrFail(t, "testdata/example-root.pem")

	_, err = client.SimpleReenroll(nil, nil, key, cert, req2)
	assert.Error(t, err)
}

type brokenAPI struct{}

func (brokenAPI) CACerts() (string, error) {
	return "", errors.New("boom")
}

func (brokenAPI) SimpleEnroll(certRequest, id, secret string) (string, error) {
	return "", errors.New("boom")
}

func (brokenAPI) SimpleReEnroll(certRequest string, id, secret *string) (string, error) {
	return "", errors.New("boom")
}

func TestBrokenServerAPI(t *testing.T) {
	builder := &stubBuilder{api: brokenAPI{}}
	client := newEstClient(builder)
	runErrorTestsOnClient(t, client)
}

func TestNewWithHost(t *testing.T) {
	const host = "foo"
	client := NewEstClient(host)

	c := client.(estHTTPClient)

	b := c.builder.(swaggerAPIBuilder)

	assert.Equal(t, host, b.host)
	assert.Nil(t, b.options.TLSTrustAnchor)
	assert.False(t, b.options.InsecureSkipVerify)
}

func TestNewWithOptions(t *testing.T) {
	const host = "foo"

	cert := readCertFromPemFileOrFail(t, "testdata/example-root.pem")

	options := ClientOptions{
		InsecureSkipVerify: true,
		TLSTrustAnchor:     cert,
	}
	client := NewEstClientWithOptions(host, options)

	c := client.(estHTTPClient)

	b := c.builder.(swaggerAPIBuilder)

	assert.Equal(t, host, b.host)
	assert.Equal(t, options, b.options)
}

// makeCertReq generates a certificate request using existingKey, if non-nil. Otherwise a fresh
// key is generated. The function returns the private key that was used and the certificate request.
func makeCertReq(existingKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.CertificateRequest, error) {

	var err error
	key := existingKey
	if key == nil {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Testy McTesterson",
		},
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, nil, err
	}

	req, err := x509.ParseCertificateRequest(der)
	return key, req, err
}

type stubBuilder struct {
	lastKey  *rsa.PrivateKey
	lastCert *x509.Certificate
	api      serverAPI
}

func (s *stubBuilder) Build(currentKey *rsa.PrivateKey, currentCert *x509.Certificate) (serverAPI, error) {
	s.lastCert = currentCert
	s.lastKey = currentKey
	return s.api, nil
}

// stubAPI returns some pre-recorded responses from http://testrfc7030.com/
type stubAPI struct {
	t *testing.T
}

func (stubAPI) CACerts() (string, error) {
	return "MIIBgQYJKoZIhvcNAQcCoIIBcjCCAW4CAQExADALBgkqhkiG9w0BBwGgggFWMIIB\n" +
		"UjCB+qADAgECAgkAndg29DdzGY4wCgYIKoZIzj0EAwIwFzEVMBMGA1UEAxMMZXN0\n" +
		"RXhhbXBsZUNBMB4XDTE4MDEwMjIwMzAzMFoXDTI3MTIzMTIwMzAzMFowFzEVMBMG\n" +
		"A1UEAxMMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8mr4\n" +
		"FwMwr92wPV18DeEW6T5TaGzjpk5Ww2bm+987lPHYNn3hqpMmhTDMgPf2cJZULhud\n" +
		"ipElVnw3p3o7+494M6MvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU19Ls64zS\n" +
		"gHGcy/RG01LRJqtjXiowCgYIKoZIzj0EAwIDRwAwRAIgC8OjaNayxGryB8SXNnDk\n" +
		"0/Zm8ifTIWWZO2/5+E7MGCcCIBiYGqNZjT6a61ybebJxB7qgUoFe61Ny4o0QkEFn\n" +
		"TGZFMQA=\n", nil
}

func (s stubAPI) SimpleEnroll(certRequest, id, secret string) (string, error) {
	assert.Equal(s.t, estID, id)
	assert.Equal(s.t, estSecret, secret)

	return "MIICdgYJKoZIhvcNAQcCoIICZzCCAmMCAQExADALBgkqhkiG9w0BBwGgggJLMIIC\n" +
		"RzCCAe2gAwIBAgICFy0wCQYHKoZIzj0EATAXMRUwEwYDVQQDEwxlc3RFeGFtcGxl\n" +
		"Q0EwHhcNMTkwMTExMTExNDA0WhcNMjAwMTExMTExNDA0WjAcMRowGAYDVQQDExFU\n" +
		"ZXN0eSBNY1Rlc3RlcnNvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
		"AM0cg142qnLPzaght1uRKkEP3Q2BW2wN9Lx2ycf2zU/6g475RPBnKvTRrg4cJ2UJ\n" +
		"lBIt/Dk45IUybvISmC+R+qTBb2FZ/xuSE5DHC6wLi2M4MEam9D6TPKAZpSIuxmRx\n" +
		"ofTAKeBf96s/u/8QvODMk4XkQ6UPaLC5XgKcM5bc0fOifQHNtxzySdW148w8+n85\n" +
		"E6eN6aHo2voLhr9Owa4zrjGET1WjHr0s5BayCUGis1nVE3vdnM3h4VqRZMlOL211\n" +
		"fsYfIqL1StrHXoRTPgjIxXle58fOuPXprNr7+lg/kYXwT5++j2HmHor59iWqCf4C\n" +
		"eDn8nwbP2WTGtnW9y+gq2OsCAwEAAaNaMFgwCQYDVR0TBAIwADALBgNVHQ8EBAMC\n" +
		"B4AwHQYDVR0OBBYEFOIMC6Qc0Kujm6bvQrLxhzNvNy1bMB8GA1UdIwQYMBaAFNfS\n" +
		"7OuM0oBxnMv0RtNS0SarY14qMAkGByqGSM49BAEDSQAwRgIhAIjgU8GNgv3jXG6D\n" +
		"Lb3Y1BjYA38xypC5DJ1onPhcp9I+AiEAl/Rs8F/MTNeMOREC4/5ADqZbAPeCZpkD\n" +
		"UokX7j9+enIxAA==\n", nil
}

func (stubAPI) SimpleReEnroll(certRequest string, id, secret *string) (string, error) {
	return "MIICdQYJKoZIhvcNAQcCoIICZjCCAmICAQExADALBgkqhkiG9w0BBwGgggJKMIIC\n" +
		"RjCCAe2gAwIBAgICFy4wCQYHKoZIzj0EATAXMRUwEwYDVQQDEwxlc3RFeGFtcGxl\n" +
		"Q0EwHhcNMTkwMTExMTExNDA1WhcNMjAwMTExMTExNDA1WjAcMRowGAYDVQQDExFU\n" +
		"ZXN0eSBNY1Rlc3RlcnNvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
		"AJ9G2Gyb1zerdMFLK7X5bNeoRyMbmddPtiGFul6PTsdSzYTqxZSbR/5cqKNZ8R/o\n" +
		"fH65VmjsZQ5NCvMdrqa6AgfCoZpIqQRIVgrvL0JvlYhPw04jGu3EBIdWGuYntyRd\n" +
		"+ESUaX/DfAVxB1mgdRFK12iTrU+NW6SZCZ9ohdDMfyohYjQfmqtVg08ryV2g7sTJ\n" +
		"FkWl+9u9LWnOss+b4fohVQabUST4Zhy/icZDtZL9UuvnOqmgrwENPhwxb2VoMe0t\n" +
		"VOEdlvQ2n+AjerpBVV6R2Y8cWgJlQm9vtehUr//avA2AvB8eHAUGMvEpDjqAKy1M\n" +
		"pmT04yECTSZ9vtoMzCi3KX0CAwEAAaNaMFgwCQYDVR0TBAIwADALBgNVHQ8EBAMC\n" +
		"B4AwHQYDVR0OBBYEFAU8Ran+0pFogxbz8W/Dh4o1aA/bMB8GA1UdIwQYMBaAFNfS\n" +
		"7OuM0oBxnMv0RtNS0SarY14qMAkGByqGSM49BAEDSAAwRQIgA7ujYP1hsa+ubrQx\n" +
		"9ZVyiUdz9TUMNpwjqwR8ONoO7FwCIQCEVnaVqtPhZN72VUh8eAiwseA9Mwz4e/3I\n" +
		"ZD4679zQ0DEA\n", nil
}
