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
	"testing"

	"github.com/stretchr/testify/assert"
)

// Note: all these tests rely on the example RFC server hosted at http://testrfc7030.com.
// Avoid running these tests by specifying "go test -short".

const estServer = "testrfc7030.com:8443"

var (
	estID     = "estuser"
	estSecret = "estpwd"
)

func TestCaCertsWithServer(t *testing.T) {
	skipIfNeeded(t)

	client := NewEstClient(estServer)

	_, err := client.CaCerts()
	assert.NoError(t, err)
}

func TestSimpleEnrollWithServer(t *testing.T) {
	skipIfNeeded(t)

	client := NewEstClient(estServer)

	_, req, err := makeCertReq(nil)
	assert.NoError(t, err)

	authData := AuthData{
		ID:     &estID,
		Secret: &estSecret,
	}
	_, err = client.SimpleEnroll(authData, req)
	assert.NoError(t, err)
}

func TestSimpleReenrollWithServer(t *testing.T) {
	skipIfNeeded(t)

	client := NewEstClient(estServer)

	key, req, err := makeCertReq(nil)
	assert.NoError(t, err)

	authData := AuthData{
		ID:     &estID,
		Secret: &estSecret,
	}

	cert, err := client.SimpleEnroll(authData, req)
	assert.NoError(t, err)

	_, req2, err := makeCertReq(key)
	authData.Key = key
	authData.ClientCert = cert

	_, err = client.SimpleReenroll(authData, req2)
	assert.NoError(t, err)
}

func TestExplicitTAWithServer(t *testing.T) {
	skipIfNeeded(t)

	wrongCACert := readCertFromPemFileOrFail(t, "testdata/example-root.pem")
	client := NewEstClientWithOptions(estServer, ClientOptions{TLSTrustAnchor: wrongCACert})

	_, req, err := makeCertReq(nil)
	assert.NoError(t, err)

	authData := AuthData{
		ID:     &estID,
		Secret: &estSecret,
	}

	_, err = client.SimpleEnroll(authData, req)

	// Would be nice to assert what the error message is, but that
	// seems a brittle approach
	assert.Error(t, err)
}

func skipIfNeeded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
}
