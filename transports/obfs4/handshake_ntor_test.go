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

package obfs4

import (
	"bytes"
	"testing"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
)

func TestHandshakeNtorClient(t *testing.T) {
	// Generate the server node id and id keypair, and ephemeral session keys.
	nodeID, _ := ntor.NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	idKeypair, _ := ntor.NewKeypair(false)
	serverFilter, _ := replayfilter.New(replayTTL)
	clientKeypair, err := ntor.NewKeypair(true)
	if err != nil {
		t.Fatalf("client: ntor.NewKeypair failed: %s", err)
	}
	serverKeypair, err := ntor.NewKeypair(true)
	if err != nil {
		t.Fatalf("server: ntor.NewKeypair failed: %s", err)
	}

	// Test client handshake padding.
	for l := clientMinPadLength; l <= clientMaxPadLength; l++ {
		// Generate the client state and override the pad length.
		clientHs := newClientHandshake(nodeID, idKeypair.Public(), clientKeypair)
		clientHs.padLen = l

		// Generate what the client will send to the server.
		clientBlob, err := clientHs.generateHandshake()
		if err != nil {
			t.Fatalf("[%d:0] clientHandshake.generateHandshake() failed: %s", l, err)
		}
		if len(clientBlob) > maxHandshakeLength {
			t.Fatalf("[%d:0] Generated client body is oversized: %d", l, len(clientBlob))
		}
		if len(clientBlob) < clientMinHandshakeLength {
			t.Fatalf("[%d:0] Generated client body is undersized: %d", l, len(clientBlob))
		}
		if len(clientBlob) != clientMinHandshakeLength+l {
			t.Fatalf("[%d:0] Generated client body incorrect size: %d", l, len(clientBlob))
		}

		// Generate the server state and override the pad length.
		serverHs := newServerHandshake(nodeID, idKeypair, serverKeypair)
		serverHs.padLen = serverMinPadLength

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
		clientHs.serverRepresentative = nil
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
	clientHs := newClientHandshake(nodeID, idKeypair.Public(), clientKeypair)
	if err != nil {
		t.Fatalf("newClientHandshake failed: %s", err)
	}
	clientHs.padLen = clientMaxPadLength + 1
	clientBlob, err := clientHs.generateHandshake()
	if err != nil {
		t.Fatalf("clientHandshake.generateHandshake() (forced oversize) failed: %s", err)
	}
	serverHs := newServerHandshake(nodeID, idKeypair, serverKeypair)
	_, err = serverHs.parseClientHandshake(serverFilter, clientBlob)
	if err == nil {
		t.Fatalf("serverHandshake.parseClientHandshake() succeded (oversized)")
	}

	// Test undersized client padding.
	clientHs.padLen = clientMinPadLength - 1
	clientBlob, err = clientHs.generateHandshake()
	if err != nil {
		t.Fatalf("clientHandshake.generateHandshake() (forced undersize) failed: %s", err)
	}
	serverHs = newServerHandshake(nodeID, idKeypair, serverKeypair)
	_, err = serverHs.parseClientHandshake(serverFilter, clientBlob)
	if err == nil {
		t.Fatalf("serverHandshake.parseClientHandshake() succeded (undersized)")
	}
}

func TestHandshakeNtorServer(t *testing.T) {
	// Generate the server node id and id keypair, and ephemeral session keys.
	nodeID, _ := ntor.NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	idKeypair, _ := ntor.NewKeypair(false)
	serverFilter, _ := replayfilter.New(replayTTL)
	clientKeypair, err := ntor.NewKeypair(true)
	if err != nil {
		t.Fatalf("client: ntor.NewKeypair failed: %s", err)
	}
	serverKeypair, err := ntor.NewKeypair(true)
	if err != nil {
		t.Fatalf("server: ntor.NewKeypair failed: %s", err)
	}

	// Test server handshake padding.
	for l := serverMinPadLength; l <= serverMaxPadLength+inlineSeedFrameLength; l++ {
		// Generate the client state and override the pad length.
		clientHs := newClientHandshake(nodeID, idKeypair.Public(), clientKeypair)
		clientHs.padLen = clientMinPadLength

		// Generate what the client will send to the server.
		clientBlob, err := clientHs.generateHandshake()
		if err != nil {
			t.Fatalf("[%d:1] clientHandshake.generateHandshake() failed: %s", l, err)
		}
		if len(clientBlob) > maxHandshakeLength {
			t.Fatalf("[%d:1] Generated client body is oversized: %d", l, len(clientBlob))
		}

		// Generate the server state and override the pad length.
		serverHs := newServerHandshake(nodeID, idKeypair, serverKeypair)
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
	clientHs := newClientHandshake(nodeID, idKeypair.Public(), clientKeypair)
	if err != nil {
		t.Fatalf("newClientHandshake failed: %s", err)
	}
	clientHs.padLen = clientMaxPadLength + 1
	clientBlob, err := clientHs.generateHandshake()
	if err != nil {
		t.Fatalf("clientHandshake.generateHandshake() (forced oversize) failed: %s", err)
	}
	serverHs := newServerHandshake(nodeID, idKeypair, serverKeypair)
	_, err = serverHs.parseClientHandshake(serverFilter, clientBlob)
	if err == nil {
		t.Fatalf("serverHandshake.parseClientHandshake() succeded (oversized)")
	}

	// Test undersized client padding.
	clientHs.padLen = clientMinPadLength - 1
	clientBlob, err = clientHs.generateHandshake()
	if err != nil {
		t.Fatalf("clientHandshake.generateHandshake() (forced undersize) failed: %s", err)
	}
	serverHs = newServerHandshake(nodeID, idKeypair, serverKeypair)
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
	clientHs.padLen = clientMinPadLength
	clientBlob, err = clientHs.generateHandshake()
	if err != nil {
		t.Fatalf("clientHandshake.generateHandshake() failed: %s", err)
	}
	serverHs = newServerHandshake(nodeID, idKeypair, serverKeypair)
	serverHs.padLen = serverMaxPadLength + inlineSeedFrameLength + 1
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
func BenchmarkObfs4Handshake(b *testing.B) {
	// Generate the "long lasting" identity key and NodeId.
	idKeypair, err := ntor.NewKeypair(false)
	if err != nil || idKeypair == nil {
		b.Fatal("Failed to generate identity keypair")
	}
	nodeID, err := ntor.NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	if err != nil {
		b.Fatal("Failed to load NodeId:", err)
	}

	// Start the actual benchmark.
	for b.Loop() {
		// Generate the keypairs.
		serverKeypair, err := ntor.NewKeypair(true)
		if err != nil || serverKeypair == nil {
			b.Fatal("Failed to generate server keypair")
		}

		clientKeypair, err := ntor.NewKeypair(true)
		if err != nil || clientKeypair == nil {
			b.Fatal("Failed to generate client keypair")
		}

		// Client sends first message
		clientHs := newClientHandshake(nodeID, idKeypair.Public(), clientKeypair)
		msg1, err := clientHs.generateHandshake()
		if err != nil {
			b.Fatal("ClientHandshake failed", err)
		}
		if msg1 == nil {
			b.Fatal("ClientHandshake is nil")
		}
		if len(msg1) < clientMinHandshakeLength {
			b.Fatalf("ClientHandshake is too short: %d bytes, expected at least %d",
				len(msg1), clientMinHandshakeLength)
		}

		// Server receives message
		filter, err := replayfilter.New(replayTTL)
		if err != nil {
			b.Fatal("ServerHandshake failed to create replay filter", err)
		}
		serverHs := newServerHandshake(nodeID, idKeypair, serverKeypair)
		keySeedServer, err := serverHs.parseClientHandshake(filter, msg1)
		if err != nil {
			b.Fatal("ServerHandshake failed to parse", err)
		}
		if keySeedServer == nil {
			b.Fatal("ServerHandshake derived nil KEY_SEED")
		}
		if len(keySeedServer) != ntor.KeySeedLength {
			b.Fatalf("ServerHandshake KEY_SEED is wrong length: %d bytes, expected %d",
				len(keySeedServer), ntor.KeySeedLength)
		}

		// Server responds
		msg2, err := serverHs.generateHandshake()
		if err != nil {
			b.Fatal("ServerHandshake failed", err)
		}
		if msg2 == nil {
			b.Fatal("ServerHandshake is nil")
		}
		if len(msg2) < serverMinHandshakeLength {
			b.Fatalf("ServerHandshake is too short: %d bytes, expected at least %d",
				len(msg2), serverMinHandshakeLength)
		}

		// Client receives
		_, keySeedClient, err := clientHs.parseServerHandshake(msg2)
		if err != nil {
			b.Fatal("ClientHandshake failed to parse", err)
		}
		if keySeedClient == nil {
			b.Fatal("ClientHandshake derived nil KEY_SEED")
		}
		if len(keySeedClient) != ntor.KeySeedLength {
			b.Fatalf("ClientHandshake KEY_SEED is wrong length: %d bytes, expected %d",
				len(keySeedClient), ntor.KeySeedLength)
		}

		// Validate the authenticator.  Real code would pass the AUTH read off
		// the network as a slice to CompareAuth here.
		if !bytes.Equal(keySeedServer, keySeedClient) {
			b.Fatal("KEY_SEED mismatched between client/server")
		}
	}
}
