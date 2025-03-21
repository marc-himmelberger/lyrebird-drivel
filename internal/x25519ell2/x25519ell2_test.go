// Copyright (c) 2021 Yawning Angel <yawning at schwanenlied dot me>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package x25519ell2

import (
	"bytes"
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519/field"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptodata"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
	"golang.org/x/crypto/curve25519"
)

// Number of times to repeat exchanges or encoding tests.
const numRepeats = 100

func TestX25519Ell2(t *testing.T) {
	t.Run("Constants", testConstants)
	t.Run("KeyExchage", testKeyExchange)
	t.Run("Encode", testEncode)
	t.Run("KemExchange", testKemExchange)
	t.Run("OkemExchange", testOkemExchange)
}

func testConstants(t *testing.T) {
	// While the constants were calculated and serialized with a known
	// correct implementation of the field arithmetic, re-derive them
	// to be sure.

	t.Run("NegTwo", func(t *testing.T) {
		expected := new(field.Element).Add(feOne, feOne)
		expected.Negate(expected)

		if expected.Equal(feNegTwo) != 1 {
			t.Fatalf("invalid value for -2: %x", feNegTwo.Bytes())
		}
	})

	t.Run("LopX", func(t *testing.T) {
		// d = -121665/121666
		d := mustFeFromUint64(121666)
		d.Invert(d)
		d.Multiply(d, mustFeFromUint64(121665))
		d.Negate(d)

		// lop_x = sqrt((sqrt(d + 1) + 1) / d)
		expected := new(field.Element).Add(d, feOne)
		expected.Invert(expected)
		expected.SqrtRatio(feOne, expected)
		expected.Add(expected, feOne)
		expected.SqrtRatio(expected, d)

		if expected.Equal(feLopX) != 1 {
			t.Fatalf("invalid value for low order point X: %x", feLopX.Bytes())
		}
	})

	t.Run("LopY", func(t *testing.T) {
		// lop_y = -lop_x * sqrtm1
		expected := new(field.Element).Negate(feLopX)
		expected.Multiply(expected, feSqrtM1)

		if expected.Equal(feLopY) != 1 {
			t.Fatalf("invalid value for low order point Y: %x", feLopY.Bytes())
		}
	})
}

func testKeyExchange(t *testing.T) {
	var randSk [32]byte
	_, _ = rand.Read(randSk[:])

	var good, bad int
	for i := 0; i < numRepeats; i++ {
		var (
			publicKey, privateKey, representative [32]byte
			publicKeyClean                        [32]byte
			tweak                                 [1]byte
		)
		_, _ = rand.Read(privateKey[:])
		_, _ = rand.Read(tweak[:])

		// This won't match the public key from the Elligator2-ed scalar
		// basepoint multiply, but we want to ensure that the public keys
		// we do happen to generate are interoperable (otherwise something
		// is badly broken).
		curve25519.ScalarBaseMult(&publicKeyClean, &privateKey)

		if !ScalarBaseMult(&publicKey, &representative, &privateKey, tweak[0]) {
			t.Logf("bad: %x", privateKey)
			bad++
			continue
		}
		t.Logf("good: %x", privateKey)

		t.Logf("publicKey: %x, repr: %x", publicKey, representative)

		var shared, sharedRep, sharedClean, pkFromRep [32]byte
		RepresentativeToPublicKey(&pkFromRep, &representative)
		if !bytes.Equal(pkFromRep[:], publicKey[:]) {
			t.Fatalf("public key mismatch(repr): expected %x, actual: %x", publicKey, pkFromRep)
		}

		curve25519.ScalarMult(&sharedClean, &randSk, &publicKeyClean) //nolint: staticcheck
		curve25519.ScalarMult(&shared, &randSk, &publicKey)           //nolint: staticcheck
		curve25519.ScalarMult(&sharedRep, &randSk, &pkFromRep)        //nolint: staticcheck

		if !bytes.Equal(shared[:], sharedRep[:]) {
			t.Fatalf("shared secret mismatch: expected %x, actual: %x", shared, sharedRep)
		}
		if !bytes.Equal(shared[:], sharedClean[:]) {
			t.Fatalf("shared secret mismatch(clean): expected %x, actual: %x", shared, sharedClean)
		}

		good++
	}

	t.Logf("good: %d, bad: %d", good, bad)
}

func testEncode(t *testing.T) {
	var bufPublicKey [32]byte
	var bufRepresentative [32]byte

	kem := X25519KEM{}
	encoder := Elligator2Encoder{}

	obfCtxt := make([]byte, encoder.LengthObfuscatedCiphertext())

	// Test all 8 possible tweak values (only lowest and highest two bits are used)
	for tweak_lo := 0; tweak_lo < 2; tweak_lo++ {
		for tweak_hi_1 := 0; tweak_hi_1 < 2; tweak_hi_1++ {
			for tweak_hi_2 := 0; tweak_hi_2 < 2; tweak_hi_2++ {
				tweak := byte((tweak_hi_2 << 7) | (tweak_hi_1 << 6) | tweak_lo)

				// Generate numRepeats keypairs and check consistency
				for i := 0; i < numRepeats; i++ {
					keypair := kem.KeyGen()

					// a) generate public key and representative via ScalarBaseMult function
					isEncodeable1 := ScalarBaseMult(&bufPublicKey, &bufRepresentative, (*[32]byte)(keypair.Private().Bytes()), tweak)

					// b) generate representative via Encode code with the same, fixed, tweak
					isEncodeable2 := encoder.encodeCiphertextWithTweak(obfCtxt, keypair.Public().Bytes(), tweak)

					if isEncodeable1 != isEncodeable2 {
						t.Fatalf("encodeability mismatch: expected %v, actual: %v", isEncodeable1, isEncodeable2)
					}
					if !isEncodeable1 {
						continue
					}
					if !bytes.Equal(bufPublicKey[:], keypair.Public().Bytes()) {
						t.Fatalf("public key mismatch: expected %x, actual: %x", bufPublicKey, keypair.Public().Bytes())
					}
					if !bytes.Equal(bufRepresentative[:], obfCtxt) {
						t.Fatalf("representative mismatch: expected %x, actual: %x", bufRepresentative, obfCtxt)
					}
				}
			}
		}
	}
}

func testKemExchange(t *testing.T) {
	kem := X25519KEM{}

	for i := 0; i < numRepeats; i++ {
		// Fix a server keypair from KeyGen
		keypairServer := kem.KeyGen()

		var privateKeyServer [32]byte
		copy(privateKeyServer[:], keypairServer.Private().Bytes())

		// a) Simulate OKEM operation
		kemCtxt, kemSharedClient, err := kem.Encaps(keypairServer.Public())
		if err != nil {
			t.Fatal("Encaps(pk) failed:", err)
		}
		kemSharedServer, err := kem.Decaps(keypairServer.Private(), kemCtxt)
		if err != nil {
			t.Fatal("Decaps(sk, c) failed:", err)
		}
		if !bytes.Equal(kemSharedClient.Bytes(), kemSharedServer.Bytes()) {
			t.Fatalf("correctness violation: expected %x, actual: %x", kemSharedClient.Bytes(), kemSharedServer.Bytes())
		}

		// b) Simulate old x25519ell2 operation
		var sharedServer [32]byte

		curve25519.ScalarMult(&sharedServer, &privateKeyServer, (*[32]byte)(kemCtxt.Bytes())) //nolint: staticcheck

		if !bytes.Equal(sharedServer[:], kemSharedServer.Bytes()) {
			t.Fatalf("interop failure: expected %x, actual: %x", sharedServer, kemSharedServer.Bytes())
		}
	}
}

func testOkemExchange(t *testing.T) {
	kem := X25519KEM{}
	encoder := Elligator2Encoder{}

	for i := 0; i < numRepeats; i++ {
		// Fix a server keypair from KeyGen
		keypairServer := kem.KeyGen()

		var privateKeyServer [32]byte
		copy(privateKeyServer[:], keypairServer.Private().Bytes())

		// a) Simulate OKEM operation
		kemCtxt, kemSharedClient, err := kem.Encaps(keypairServer.Public())
		if err != nil {
			t.Fatal("Encaps(pk) failed:", err)
		}
		// encode
		okemCtxt := make([]byte, encoder.LengthObfuscatedCiphertext())
		if !encoder.EncodeCiphertext(okemCtxt, kemCtxt.Bytes()) {
			t.Logf("bad: %x", kemCtxt)
			continue
		}
		t.Logf("good: %x", kemCtxt)
		// decode
		ctxt := make([]byte, kem.LengthCiphertext())
		encoder.DecodeCiphertext(ctxt, okemCtxt)
		kemCtxt2, err := cryptodata.New(ctxt, kem.LengthCiphertext())
		if err != nil {
			t.Fatal("cryptodata.New(ctxt) failed:", err)
		}
		okemSharedServer, err := kem.Decaps(keypairServer.Private(), kems.Ciphertext(kemCtxt2))
		if err != nil {
			t.Fatal("Decaps(sk, c) failed:", err)
		}
		if !bytes.Equal(kemSharedClient.Bytes(), okemSharedServer.Bytes()) {
			t.Fatalf("correctness violation: expected %x, actual: %x", kemSharedClient.Bytes(), okemSharedServer.Bytes())
		}

		// b) Simulate old x25519ell2 operation
		var sharedServer, pkFromRep [32]byte
		RepresentativeToPublicKey(&pkFromRep, (*[32]byte)(okemCtxt))

		curve25519.ScalarMult(&sharedServer, &privateKeyServer, &pkFromRep) //nolint: staticcheck

		if !bytes.Equal(sharedServer[:], okemSharedServer.Bytes()) {
			t.Fatalf("interop failure: expected %x, actual: %x", sharedServer, okemSharedServer.Bytes())
		}
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	var publicKey, representative, privateKey [32]byte

	// Find the private key that results in a point that's in the image of the map.
	for {
		_, _ = rand.Reader.Read(privateKey[:])
		if ScalarBaseMult(&publicKey, &representative, &privateKey, 0) {
			break
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScalarBaseMult(&publicKey, &representative, &privateKey, 0)
	}
}

func BenchmarkMap(b *testing.B) {
	var publicKey, representative [32]byte
	_, _ = rand.Reader.Read(representative[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RepresentativeToPublicKey(&publicKey, &representative)
	}
}
