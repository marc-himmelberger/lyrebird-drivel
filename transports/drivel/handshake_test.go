/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package drivel

import (
	"bytes"
	"testing"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/drivel/drivelcrypto"
)

func TestHandshakeDrivelcryptoClient(t *testing.T) {
	okem := okemScheme
	kem := kemScheme
	lengthDetails := getLengthDetails(okem, kem)

	// Generate the server node id and id keypair, and ephemeral session keys.
	nodeID, _ := drivelcrypto.NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	idKeypair := okem.KeyGen()
	serverFilter, _ := replayfilter.New(replayTTL)
	clientKeypair := kem.KeyGen()

	// Test client handshake padding.
	for l := lengthDetails.clientMinPadLength; l <= lengthDetails.clientMaxPadLength; l++ {
		// Generate the client state and override the pad length.
		clientHs := newClientHandshake(okem, kem, nodeID, idKeypair.Public(), clientKeypair)
		clientHs.padLen = l

		// Generate what the client will send to the server.
		clientBlob, err := clientHs.generateHandshake()
		if err != nil {
			t.Fatalf("[%d:0] clientHandshake.generateHandshake() failed: %s", l, err)
		}
		if len(clientBlob) > maxHandshakeLength {
			t.Fatalf("[%d:0] Generated client body is oversized: %d", l, len(clientBlob))
		}
		if len(clientBlob) < lengthDetails.clientMinHandshakeLength {
			t.Fatalf("[%d:0] Generated client body is undersized: %d", l, len(clientBlob))
		}
		if len(clientBlob) != lengthDetails.clientMinHandshakeLength+l {
			t.Fatalf("[%d:0] Generated client body incorrect size: %d", l, len(clientBlob))
		}

		// Generate the server state and override the pad length.
		serverHs := newServerHandshake(okem, kem, nodeID, idKeypair)
		serverHs.padLen = lengthDetails.serverMinPadLength

		// Parse the client handshake message.
		serverSeed, err := serverHs.parseClientHandshake(serverFilter, clientBlob)
		if err != nil {
			t.Fatalf("[%d:0] serverHandshake.parseClientHandshake() failed: %s", l, err)
		}

		// Genrate what the server will send to the client.
		serverBlob, err := serverHs.generateHandshake()
		if err != nil {
			t.Fatalf("[%d:0]: serverHandshake.generateHandshake() failed: %s", l, err)
		}

		// Parse the server handshake message.
		n, clientSeed, err := clientHs.parseServerHandshake(serverBlob)
		if err != nil {
			t.Fatalf("[%d:0] clientHandshake.parseServerHandshake() failed: %s", l, err)
		}
		if n != len(serverBlob) {
			t.Fatalf("[%d:0] clientHandshake.parseServerHandshake() has bytes remaining: %d", l, n)
		}

		// Ensure the derived shared secret is the same.
		if 0 != bytes.Compare(clientSeed, serverSeed) {
			t.Fatalf("[%d:0] client/server seed mismatch", l)
		}
	}

	// Test oversized client padding.
	clientHs := newClientHandshake(okem, kem, nodeID, idKeypair.Public(), clientKeypair)
	clientHs.padLen = lengthDetails.clientMaxPadLength + 1
	clientBlob, err := clientHs.generateHandshake()
	if err != nil {
		t.Fatalf("clientHandshake.generateHandshake() (forced oversize) failed: %s", err)
	}
	serverHs := newServerHandshake(okem, kem, nodeID, idKeypair)
	_, err = serverHs.parseClientHandshake(serverFilter, clientBlob)
	if err == nil {
		t.Fatalf("serverHandshake.parseClientHandshake() succeded (oversized)")
	}

	// Test undersized client padding.
	clientHs.padLen = lengthDetails.clientMinPadLength - 1
	clientBlob, err = clientHs.generateHandshake()
	if err != nil {
		t.Fatalf("clientHandshake.generateHandshake() (forced undersize) failed: %s", err)
	}
	serverHs = newServerHandshake(okem, kem, nodeID, idKeypair)
	_, err = serverHs.parseClientHandshake(serverFilter, clientBlob)
	if err == nil {
		t.Fatalf("serverHandshake.parseClientHandshake() succeded (undersized)")
	}
}

func TestHandshakeDrivelcryptoServer(t *testing.T) {
	okem := okemScheme
	kem := kemScheme
	lengthDetails := getLengthDetails(okem, kem)

	// Generate the server node id and id keypair, and ephemeral session keys.
	nodeID, _ := drivelcrypto.NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	idKeypair := okem.KeyGen()
	serverFilter, _ := replayfilter.New(replayTTL)
	clientKeypair := kem.KeyGen()

	// Test server handshake padding.
	for l := lengthDetails.serverMinPadLength; l <= lengthDetails.serverMaxPadLength+inlineSeedFrameLength; l++ {
		// Generate the client state and override the pad length.
		clientHs := newClientHandshake(okem, kem, nodeID, idKeypair.Public(), clientKeypair)
		clientHs.padLen = lengthDetails.clientMinPadLength

		// Generate what the client will send to the server.
		clientBlob, err := clientHs.generateHandshake()
		if err != nil {
			t.Fatalf("[%d:1] clientHandshake.generateHandshake() failed: %s", l, err)
		}
		if len(clientBlob) > maxHandshakeLength {
			t.Fatalf("[%d:1] Generated client body is oversized: %d", l, len(clientBlob))
		}

		// Generate the server state and override the pad length.
		serverHs := newServerHandshake(okem, kem, nodeID, idKeypair)
		serverHs.padLen = l

		// Parse the client handshake message.
		serverSeed, err := serverHs.parseClientHandshake(serverFilter, clientBlob)
		if err != nil {
			t.Fatalf("[%d:1] serverHandshake.parseClientHandshake() failed: %s", l, err)
		}

		// Genrate what the server will send to the client.
		serverBlob, err := serverHs.generateHandshake()
		if err != nil {
			t.Fatalf("[%d:1]: serverHandshake.generateHandshake() failed: %s", l, err)
		}

		// Parse the server handshake message.
		n, clientSeed, err := clientHs.parseServerHandshake(serverBlob)
		if err != nil {
			t.Fatalf("[%d:1] clientHandshake.parseServerHandshake() failed: %s", l, err)
		}
		if n != len(serverBlob) {
			t.Fatalf("[%d:1] clientHandshake.parseServerHandshake() has bytes remaining: %d", l, n)
		}

		// Ensure the derived shared secret is the same.
		if 0 != bytes.Compare(clientSeed, serverSeed) {
			t.Fatalf("[%d:1] client/server seed mismatch", l)
		}
	}

	// Test oversized client padding.
	clientHs := newClientHandshake(okem, kem, nodeID, idKeypair.Public(), clientKeypair)
	clientHs.padLen = lengthDetails.clientMaxPadLength + 1
	clientBlob, err := clientHs.generateHandshake()
	if err != nil {
		t.Fatalf("clientHandshake.generateHandshake() (forced oversize) failed: %s", err)
	}
	serverHs := newServerHandshake(okem, kem, nodeID, idKeypair)
	_, err = serverHs.parseClientHandshake(serverFilter, clientBlob)
	if err == nil {
		t.Fatalf("serverHandshake.parseClientHandshake() succeded (oversized)")
	}

	// Test undersized client padding.
	clientHs.padLen = lengthDetails.clientMinPadLength - 1
	clientBlob, err = clientHs.generateHandshake()
	if err != nil {
		t.Fatalf("clientHandshake.generateHandshake() (forced undersize) failed: %s", err)
	}
	serverHs = newServerHandshake(okem, kem, nodeID, idKeypair)
	_, err = serverHs.parseClientHandshake(serverFilter, clientBlob)
	if err == nil {
		t.Fatalf("serverHandshake.parseClientHandshake() succeded (undersized)")
	}

	// Test oversized server padding.
	//
	// NB: serverMaxPadLength isn't the real maxPadLength that triggers client
	// rejection, because the implementation is written with the asusmption
	// that the PRNG_SEED is also inlined with the response.  Thus the client
	// actually accepts longer padding.  The server handshake test and this
	// test adjust around that.
	clientHs.padLen = lengthDetails.clientMinPadLength
	clientBlob, err = clientHs.generateHandshake()
	if err != nil {
		t.Fatalf("clientHandshake.generateHandshake() failed: %s", err)
	}
	serverHs = newServerHandshake(okem, kem, nodeID, idKeypair)
	serverHs.padLen = lengthDetails.serverMaxPadLength + inlineSeedFrameLength + 1
	_, err = serverHs.parseClientHandshake(serverFilter, clientBlob)
	if err != nil {
		t.Fatalf("serverHandshake.parseClientHandshake() failed: %s", err)
	}
	serverBlob, err := serverHs.generateHandshake()
	if err != nil {
		t.Fatalf("serverHandshake.generateHandshake() (forced oversize) failed: %s", err)
	}
	_, _, err = clientHs.parseServerHandshake(serverBlob)
	if err == nil {
		t.Fatalf("clientHandshake.parseServerHandshake() succeded (oversized)")
	}
}

// Benchmark Client/Server handshake.  The actual time taken that will be
// observed on either the Client or Server is half the reported time per
// operation since the benchmark does both sides.
func BenchmarkHandshake(b *testing.B) {
	// Generate the "long lasting" identity key and NodeId.
	idKeypair, err := NewKeypair(false)
	if err != nil || idKeypair == nil {
		b.Fatal("Failed to generate identity keypair")
	}
	nodeID, err := NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	if err != nil {
		b.Fatal("Failed to load NodeId:", err)
	}
	b.ResetTimer()

	// Start the actual benchmark.
	for i := 0; i < b.N; i++ {
		// Generate the keypairs.
		serverKeypair, err := NewKeypair(true)
		if err != nil || serverKeypair == nil {
			b.Fatal("Failed to generate server keypair")
		}

		clientKeypair, err := NewKeypair(true)
		if err != nil || clientKeypair == nil {
			b.Fatal("Failed to generate client keypair")
		}

		// Server handshake.
		clientPublic := clientKeypair.Representative().ToPublic()
		ok, serverSeed, serverAuth := ServerHandshake(clientPublic,
			serverKeypair, idKeypair, nodeID)
		if !ok || serverSeed == nil || serverAuth == nil {
			b.Fatal("ServerHandshake failed")
		}

		// Client handshake.
		serverPublic := serverKeypair.Representative().ToPublic()
		ok, clientSeed, clientAuth := ClientHandshake(clientKeypair,
			serverPublic, idKeypair.Public(), nodeID)
		if !ok || clientSeed == nil || clientAuth == nil {
			b.Fatal("ClientHandshake failed")
		}

		// Validate the authenticator.  Real code would pass the AUTH read off
		// the network as a slice to CompareAuth here.
		if !CompareAuth(clientAuth, serverAuth.Bytes()[:]) ||
			!CompareAuth(serverAuth, clientAuth.Bytes()[:]) {
			b.Fatal("AUTH mismatched between client/server")
		}
	}
}
