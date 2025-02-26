/*
 * Copyright (c) 2025, Marc Himmelberger <marc dot himmelberger at inf dot ethz dot ch>
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

// Package drivelcrypto implements the cryptographic functionality of the Drivel
// protocol as defined in
// TODO: <link hybrid paper>.
// It also supports using OKEMs to transform the public keys and ciphertexts sent
// over the wire to a form that is indistinguishable from random strings.
package drivelcrypto // import "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/pq_obfs/drivelcrypto"

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/okems"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// NodeIDLength is the length of a Drivel node identifier.
	NodeIDLength = 20

	// KeySeedLength is the length of the derived KEY_SEED.
	KeySeedLength = sha256.Size

	// AuthLength is the lenght of the derived AUTH.
	AuthLength = sha256.Size
)

var protoID = []byte("Drivel")
var tMarkClient = append(protoID, []byte(":mc")...)
var tMarkServer = append(protoID, []byte(":ms")...)
var tMacClient = append(protoID, []byte(":mac_c")...)
var tMacServer = append(protoID, []byte(":mac_s")...)
var tDerive = append(protoID, []byte(":derive_key")...)
var tSKey = append(protoID, []byte(":key_extract")...)
var tKeyVerify = append(protoID, []byte(":server_mac")...)
var mExpand = append(protoID, []byte(":key_expand")...)

// NodeIDLengthError is the error returned when the node ID being imported is
// an invalid length.
type NodeIDLengthError int

func (e NodeIDLengthError) Error() string {
	return fmt.Sprintf("drivel: Invalid NodeID length: %d", int(e))
}

// KeySeed is the key material that results from a handshake (KEY_SEED).
type KeySeed [KeySeedLength]byte

// Bytes returns a pointer to the raw key material.
func (key_seed *KeySeed) Bytes() *[KeySeedLength]byte {
	return (*[KeySeedLength]byte)(key_seed)
}

// Auth is the verifier that results from a handshake (AUTH).
type Auth [AuthLength]byte

// Bytes returns a pointer to the raw auth.
func (auth *Auth) Bytes() *[AuthLength]byte {
	return (*[AuthLength]byte)(auth)
}

// NodeID is a Drivel node identifier.
type NodeID [NodeIDLength]byte

// NewNodeID creates a NodeID from the raw bytes.
func NewNodeID(raw []byte) (*NodeID, error) {
	if len(raw) != NodeIDLength {
		return nil, NodeIDLengthError(len(raw))
	}

	nodeID := new(NodeID)
	copy(nodeID[:], raw)

	return nodeID, nil
}

// NodeIDFromHex creates a new NodeID from the hexdecimal representation.
func NodeIDFromHex(encoded string) (*NodeID, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return NewNodeID(raw)
}

// Bytes returns a pointer to the raw NodeID.
func (id *NodeID) Bytes() *[NodeIDLength]byte {
	return (*[NodeIDLength]byte)(id)
}

// Hex returns the hexdecimal representation of the NodeID.
func (id *NodeID) Hex() string {
	return hex.EncodeToString(id[:])
}

// ServerHandshake does the server side of a Drivel handshake and returns status,
// KEY_SEED, and AUTH.  If status is not true, the handshake MUST be aborted.
func ServerHandshake(clientPublic *PublicKey, serverKeypair *Keypair, idKeypair *Keypair, id *NodeID) (ok bool, keySeed *KeySeed, auth *Auth) {
	var notOk int
	var secretInput bytes.Buffer

	// Server side uses EXP(X,y) | EXP(X,b)
	var exp [SharedSecretLength]byte
	curve25519.ScalarMult(&exp, serverKeypair.private.Bytes(),
		clientPublic.Bytes())
	notOk |= constantTimeIsZero(exp[:])
	secretInput.Write(exp[:])

	curve25519.ScalarMult(&exp, idKeypair.private.Bytes(),
		clientPublic.Bytes())
	notOk |= constantTimeIsZero(exp[:])
	secretInput.Write(exp[:])

	keySeed, auth = drivelCommon(secretInput, id, idKeypair.public,
		clientPublic, serverKeypair.public)
	return notOk == 0, keySeed, auth
}

// ClientHandshake does the client side of a Drivel handshake and returnes
// status, KEY_SEED, and AUTH.  If status is not true or AUTH does not match
// the value recieved from the server, the handshake MUST be aborted.
func ClientHandshake(clientKeypair *Keypair, serverPublic *PublicKey, idPublic *PublicKey, id *NodeID) (ok bool, keySeed *KeySeed, auth *Auth) {
	var notOk int
	var secretInput bytes.Buffer

	// Client side uses EXP(Y,x) | EXP(B,x)
	var exp [SharedSecretLength]byte
	curve25519.ScalarMult(&exp, clientKeypair.private.Bytes(),
		serverPublic.Bytes())
	notOk |= constantTimeIsZero(exp[:])
	secretInput.Write(exp[:])

	curve25519.ScalarMult(&exp, clientKeypair.private.Bytes(),
		idPublic.Bytes())
	notOk |= constantTimeIsZero(exp[:])
	secretInput.Write(exp[:])

	keySeed, auth = drivelCommon(secretInput, id, idPublic,
		clientKeypair.public, serverPublic)
	return notOk == 0, keySeed, auth
}

// CompareAuth does a constant time compare of a Auth and a byte slice
// (presumably received over a network).
func CompareAuth(auth1 *Auth, auth2 []byte) bool {
	auth1Bytes := auth1.Bytes()
	return hmac.Equal(auth1Bytes[:], auth2)
}

func drivelCommon(prfEphermalSecret hash.Hash, sharedKemSecret []byte,
	serverOkemPublicKey *okems.PublicKey, okemCiphertext []byte,
	clientKemPublicKey *okems.PublicKey, kemCiphertext []byte) (keySeed *KeySeed, auth *Auth) {

	var derivedSecret []byte       // ES'
	var finalSecret []byte         // ES'
	var prfFinalCombiner hash.Hash // F_2(ES', ...)
	var prfFinalSecret hash.Hash   // F_1(FS, ...)

	// ES' = F1(ES, ":derive_key")
	prfEphermalSecret.Reset()
	_, _ = prfEphermalSecret.Write(tDerive)
	derivedSecret = prfEphermalSecret.Sum(nil)

	// F2(ES', ...)
	prfFinalCombiner = hmac.New(sha256.New, derivedSecret)

	// FS = F2(ES', K_e)
	prfFinalCombiner.Reset()
	_, _ = prfFinalCombiner.Write(sharedKemSecret)
	finalSecret = prfFinalCombiner.Sum(nil)

	// F1(FS, ...)
	prfFinalSecret = hmac.New(sha256.New, finalSecret)

	// context = pk_S | c_S | pk_e | c_e | protoID
	var context bytes.Buffer
	context.Write(serverOkemPublicKey.Bytes())
	context.Write(okemCiphertext)
	context.Write(clientKemPublicKey.Bytes())
	context.Write(kemCiphertext)
	context.Write(protoID)

	// skey = F1(FS, context | ":key_extract")
	prfFinalSecret.Reset()
	_, _ = prfFinalSecret.Write(context.Bytes())
	_, _ = prfFinalSecret.Write(tSKey)
	keySeed = (*KeySeed)(prfFinalSecret.Sum(nil))

	// auth = F1(FS, context | ":server_mac")
	prfFinalSecret.Reset()
	_, _ = prfFinalSecret.Write(context.Bytes())
	_, _ = prfFinalSecret.Write(tKeyVerify)
	auth = (*Auth)(prfFinalSecret.Sum(nil))

	return keySeed, auth
}

// MessageMark computes a mark as prf(msgMark | tMarkClient)
// or prf(msgMark | tMarkServer) depending on `isClient`.a
func MessageMark(prfEphermalSecret hash.Hash, isClient bool, msgMark []byte) (mark []byte) {
	tag := tMarkServer
	if isClient {
		tag = tMarkClient
	}

	prfEphermalSecret.Reset()
	_, _ = prfEphermalSecret.Write(msgMark)
	_, _ = prfEphermalSecret.Write(tag)
	mark = prfEphermalSecret.Sum(nil)

	return mark
}

// MessageMAC computes a MAC with HMAC-SHA-256 over the entire `msg` (must include the mark)
// followed by tMacClient or tMacServer respectively (depending on the value of `isClient`).
func MessageMAC(prfEphermalSecret hash.Hash, isClient bool, msg []byte, epochHour []byte) (mac []byte) {
	tag := tMacServer
	if isClient {
		tag = tMacClient
	}

	prfEphermalSecret.Reset()
	_, _ = prfEphermalSecret.Write(msg)
	_, _ = prfEphermalSecret.Write(epochHour) // TODO I think this avoids format confusion attacks, but double-check
	_, _ = prfEphermalSecret.Write(tag)
	mac = prfEphermalSecret.Sum(nil)

	return mac
}

// KdfExpand expands pseudorandomKey via HKDF-SHA256 and returns `okm_len` bytes
// of key material. pseudorandomKey must be a strong pseudorandom cryptographic key.
// Info is an arbitrary identifier for the output, repeated keys will yield the same output.
func KdfExpand(pseudorandomKey []byte, okmLen int) []byte {
	kdf := hkdf.Expand(sha256.New, pseudorandomKey, mExpand) // TODO mExpand might need to be an argument if we derive EK1 and EK2 from ES.
	okm := make([]byte, okmLen)
	n, err := io.ReadFull(kdf, okm)
	if err != nil {
		panic(fmt.Sprintf("BUG: Failed HKDF: %s", err.Error()))
	} else if n != len(okm) {
		panic(fmt.Sprintf("BUG: Got truncated HKDF output: %d", n))
	}

	return okm
}

// Expands the key to appropriate length using KdfExpand, then XORs with the message.
// This performs symmetric encryption/decryption and may hide structure within a message.
// However, this function MUST NOT be called twice with the same key.
func XorEncryptDecrypt(key []byte, message []byte) []byte {
	expanded := KdfExpand(key, len(message))
	n := subtle.XORBytes(expanded, expanded, message)
	if n != len(message) {
		panic(fmt.Sprintf("BUG: XOR encrypt/decrypt got truncated output: %d", n))
	}
	return expanded
}
