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
	"slices"
	"testing"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/drivel/drivelcrypto"
)

// Test that all lengths are positive and have the correct relationship between them
func TestGetLengthDetails(t *testing.T) {
	for _, okemName := range cryptofactory.OkemNames() {
		for _, kemName := range cryptofactory.KemNames() {
			t.Run(kemName+"|"+okemName, func(t *testing.T) {
				testSingleGetLengthDetails(t, okemName, kemName)
			})
		}
	}
}

func testSingleGetLengthDetails(t *testing.T, okemName string, kemName string) {
	okem := cryptofactory.NewOkem(okemName)
	kem := cryptofactory.NewKem(kemName)

	details := getLengthDetails(okem, kem)

	// Check that all fields are strictly positive
	if details.epkLength <= 0 {
		t.Fatalf("epkLength = %v <= 0", details.epkLength)
	}
	if details.ectLength <= 0 {
		t.Fatalf("ectLength = %v <= 0", details.ectLength)
	}
	if details.csLength <= 0 {
		t.Fatalf("csLength = %v <= 0", details.csLength)
	}
	if details.authLength <= 0 {
		t.Fatalf("authLength = %v <= 0", details.authLength)
	}
	if details.clientMinHandshakeLength <= 0 {
		t.Fatalf("clientMinHandshakeLength = %v <= 0", details.clientMinHandshakeLength)
	}
	if details.serverMinHandshakeLength <= 0 {
		t.Fatalf("serverMinHandshakeLength = %v <= 0", details.serverMinHandshakeLength)
	}
	if details.clientMinPadLength < 0 {
		t.Fatalf("clientMinPadLength = %v <= 0", details.clientMinPadLength)
	}
	if details.clientMaxPadLength < 0 {
		t.Fatalf("clientMaxPadLength = %v <= 0", details.clientMaxPadLength)
	}
	if details.serverMinPadLength < 0 {
		t.Fatalf("serverMinPadLength = %v <= 0", details.serverMinPadLength)
	}
	if details.serverMaxPadLength < 0 {
		t.Fatalf("serverMaxPadLength = %v <= 0", details.serverMaxPadLength)
	}

	// Check that min, max of padding makes sense
	if details.clientMinPadLength > details.clientMaxPadLength {
		t.Fatalf("client___PadLength Min/Max not valid: %v > %v", details.clientMinPadLength, details.clientMaxPadLength)
	}
	if details.serverMinPadLength > details.serverMaxPadLength {
		t.Fatalf("server___PadLength Min/Max not valid: %v > %v", details.serverMinPadLength, details.serverMaxPadLength)
	}
}

// Tests utility function that other tests will rely on
func TestGeneratePaddingTests(t *testing.T) {
	for _, okemName := range cryptofactory.OkemNames() {
		for _, kemName := range cryptofactory.KemNames() {
			t.Run(kemName+"|"+okemName, func(t *testing.T) {
				okem := cryptofactory.NewOkem(okemName)
				kem := cryptofactory.NewKem(kemName)
				lengthDetails := getLengthDetails(okem, kem)

				values1 := generatePaddingTests(lengthDetails.clientMinPadLength, lengthDetails.clientMaxPadLength)
				// must contain first 100 values
				for l := lengthDetails.clientMinPadLength; l < min(lengthDetails.clientMinPadLength+100, lengthDetails.clientMaxPadLength); l++ {
					if !slices.Contains(values1, l) {
						t.Fatalf("padding value of %d not found", l)
					}
				}
				// must contain last 100 values
				for l := max(lengthDetails.clientMinPadLength, lengthDetails.clientMaxPadLength-100); l < lengthDetails.clientMinPadLength; l++ {
					if !slices.Contains(values1, l) {
						t.Fatalf("padding value of %d not found", l)
					}
				}
				// all values must be in range
				for _, l := range values1 {
					if l < lengthDetails.clientMinPadLength || l > lengthDetails.clientMaxPadLength {
						t.Fatalf("padding value of %d invalid", l)
					}
				}

				values2 := generatePaddingTests(lengthDetails.serverMinPadLength, lengthDetails.serverMaxPadLength)
				// must contain first 100 values
				for l := lengthDetails.serverMinPadLength; l < min(lengthDetails.serverMinPadLength+100, lengthDetails.serverMaxPadLength); l++ {
					if !slices.Contains(values2, l) {
						t.Fatalf("padding value of %d not found", l)
					}
				}
				// must contain last 100 values
				for l := max(lengthDetails.serverMinPadLength, lengthDetails.serverMaxPadLength-100); l < lengthDetails.serverMinPadLength; l++ {
					if !slices.Contains(values2, l) {
						t.Fatalf("padding value of %d not found", l)
					}
				}
				// all values must be in range
				for _, l := range values2 {
					if l < lengthDetails.serverMinPadLength || l > lengthDetails.serverMaxPadLength {
						t.Fatalf("padding value of %d invalid", l)
					}
				}
			})
		}
	}
}

// Creates a list of ints that should be tested as padding values.
// There will be a region around padMin, padMax that is exhaustively tested.
// Outside of the exhaustive region, the entire range is covered with <100 evenly spaced values.
func generatePaddingTests(padMin, padMax int) []int {
	values := make([]int, 0, 100+2*300)

	bigSteps := (padMax - padMin) / 100
	exhaustiveRegion := 100
	padIncrement := 1

	for l := padMin; l <= padMax; l += padIncrement {
		if l-padMin > exhaustiveRegion {
			if l+bigSteps < padMax-exhaustiveRegion {
				padIncrement = bigSteps
			} else if l < padMax-exhaustiveRegion {
				padIncrement = padMax - exhaustiveRegion - l
			} else {
				padIncrement = 1
			}
		}
		values = append(values, l)
	}

	return values
}

// Test that runs through all KEMs and OKEMs
// and checks if client and server arrive at the same KEY_SEED
// with all expected lengths of padding
func TestHandshakeDrivelcrypto(t *testing.T) {
	for _, okemName := range cryptofactory.OkemNames() {
		for _, kemName := range cryptofactory.KemNames() {
			t.Run(kemName+"|"+okemName, func(t *testing.T) {
				testHandshakeDrivelcryptoClient(t, okemName, kemName)
				testHandshakeDrivelcryptoServer(t, okemName, kemName)
			})
		}
	}
}

func testHandshakeDrivelcryptoClient(t *testing.T, okemName string, kemName string) {
	okem := cryptofactory.NewOkem(okemName)
	kem := cryptofactory.NewKem(kemName)

	lengthDetails := getLengthDetails(okem, kem)

	// Generate the server node id and id keypair, and ephemeral session keys.
	nodeID, _ := drivelcrypto.NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	idKeypair := okem.KeyGen()
	serverFilter, _ := replayfilter.New(replayTTL)
	clientKeypair := kem.KeyGen()

	// Test client handshake padding.
	// Exhaustive padding check are too expensive
	// TODO: remove this with fragmentation?
	padMin := lengthDetails.clientMinPadLength
	padMax := lengthDetails.clientMaxPadLength
	for _, l := range generatePaddingTests(padMin, padMax) {
		t.Logf("%d / %d up to %d", l, padMin, padMax)

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
		if !bytes.Equal(clientSeed, serverSeed) {
			t.Fatalf("[%d:0] client/server seed mismatch", l)
		}
	}

	// Test oversized client padding.
	clientHs := newClientHandshake(okem, kem, nodeID, idKeypair.Public(), clientKeypair)
	clientHs.padLen = padMax + 1
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
	clientHs.padLen = padMin - 1
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

func testHandshakeDrivelcryptoServer(t *testing.T, okemName string, kemName string) {
	okem := cryptofactory.NewOkem(okemName)
	kem := cryptofactory.NewKem(kemName)
	lengthDetails := getLengthDetails(okem, kem)

	// Generate the server node id and id keypair, and ephemeral session keys.
	nodeID, _ := drivelcrypto.NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	idKeypair := okem.KeyGen()
	serverFilter, _ := replayfilter.New(replayTTL)
	clientKeypair := kem.KeyGen()

	// Test server handshake padding.
	// Exhaustive padding check are too expensive
	// TODO: remove this with fragmentation?
	padMin := lengthDetails.serverMinPadLength
	padMax := lengthDetails.serverMaxPadLength + inlineSeedFrameLength
	for _, l := range generatePaddingTests(padMin, padMax) {
		t.Logf("%d / %d up to %d", l, padMin, padMax)

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
		if !bytes.Equal(clientSeed, serverSeed) {
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
	serverHs.padLen = padMax + 1
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

// Benchmark Client/Server handshake for all KEMs/OKEMs.
// The actual time taken that will be observed on either the Client or
// Server is half the reported time per operation since the benchmark does both sides.
func BenchmarkDrivelHandshake(b *testing.B) {
	for _, okemName := range cryptofactory.OkemNames() {
		for _, kemName := range cryptofactory.KemNames() {
			b.Run(kemName+"|"+okemName, func(b *testing.B) {
				benchmarkDrivelHandshake(b, okemName, kemName)
			})
		}
	}
}

func benchmarkDrivelHandshake(b *testing.B, okemName string, kemName string) {
	okem := cryptofactory.NewOkem(okemName)
	kem := cryptofactory.NewKem(kemName)

	// Generate the "long lasting" identity key and NodeId.
	idKeypair := okem.KeyGen()
	if idKeypair == nil {
		b.Fatal("Failed to generate identity keypair")
	}
	nodeID, err := drivelcrypto.NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	if err != nil {
		b.Fatal("Failed to load NodeId:", err)
	}

	// Start the actual benchmark.
	for b.Loop() {
		// Generate the client keypair.
		clientKeypair := kem.KeyGen()
		if clientKeypair == nil {
			b.Fatal("Failed to generate client keypair")
		}

		// Client sends first message
		clientHs := newClientHandshake(okem, kem, nodeID, idKeypair.Public(), clientKeypair)
		msg1, err := clientHs.generateHandshake()
		if err != nil {
			b.Fatal("ClientHandshake failed", err)
		}
		if msg1 == nil {
			b.Fatal("ClientHandshake is nil")
		}
		if len(msg1) < clientHs.lengthDetails.clientMinHandshakeLength {
			b.Fatalf("ClientHandshake is too short: %d bytes, expected at least %d",
				len(msg1), clientHs.lengthDetails.clientMinHandshakeLength)
		}

		// Server receives message
		filter, err := replayfilter.New(replayTTL)
		if err != nil {
			b.Fatal("ServerHandshake failed to create replay filter", err)
		}
		serverHs := newServerHandshake(okem, kem, nodeID, idKeypair)
		keySeedServer, err := serverHs.parseClientHandshake(filter, msg1)
		if err != nil {
			b.Fatal("ServerHandshake failed to parse", err)
		}
		if keySeedServer == nil {
			b.Fatal("ServerHandshake derived nil KEY_SEED")
		}
		if len(keySeedServer) != drivelcrypto.KeySeedLength {
			b.Fatalf("ServerHandshake KEY_SEED is wrong length: %d bytes, expected %d",
				len(keySeedServer), drivelcrypto.KeySeedLength)
		}

		// Server responds
		msg2, err := serverHs.generateHandshake()
		if err != nil {
			b.Fatal("ServerHandshake failed", err)
		}
		if msg2 == nil {
			b.Fatal("ServerHandshake is nil")
		}
		if len(msg2) < clientHs.lengthDetails.serverMinHandshakeLength {
			b.Fatalf("ServerHandshake is too short: %d bytes, expected at least %d",
				len(msg2), clientHs.lengthDetails.serverMinHandshakeLength)
		}

		// Client receives
		_, keySeedClient, err := clientHs.parseServerHandshake(msg2)
		if err != nil {
			b.Fatal("ClientHandshake failed to parse", err)
		}
		if keySeedClient == nil {
			b.Fatal("ClientHandshake derived nil KEY_SEED")
		}
		if len(keySeedClient) != drivelcrypto.KeySeedLength {
			b.Fatalf("ClientHandshake KEY_SEED is wrong length: %d bytes, expected %d",
				len(keySeedClient), drivelcrypto.KeySeedLength)
		}

		// Validate the authenticator.  Real code would pass the AUTH read off
		// the network as a slice to CompareAuth here.
		if !bytes.Equal(keySeedServer, keySeedClient) {
			b.Fatal("KEY_SEED mismatched between client/server")
		}
	}
}
