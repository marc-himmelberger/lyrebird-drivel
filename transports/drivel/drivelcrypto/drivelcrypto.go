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
// protocol as defined in https://eprint.iacr.org/2025/408.
// It also supports using OKEMs to transform the public keys and ciphertexts sent
// over the wire to a form that is indistinguishable from random strings.
package drivelcrypto // import "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/drivel/drivelcrypto"

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/okems"
	"golang.org/x/crypto/hkdf"
)

const (
	// NodeIDLength is the length of a Drivel node identifier.
	NodeIDLength = 20

	// KeySeedLength is the length of the derived KEY_SEED.
	KeySeedLength = KdfOutLength

	// AuthLength is the lenghth of the derived AUTH.
	AuthLength = KdfOutLength

	// MarkLength is the lenghth of [MessageMark] outputs.
	MarkLength = KdfOutLength / 2

	// MacLength is the lenghth of [MessageMAC] outputs.
	MacLength = KdfOutLength / 2

	// KdfOutLength is the length of one round of KDF application.
	// It should be used when a constant-size KDF output is desired.
	KdfOutLength = sha256.Size
)

// Define string constants for info/context inputs to HKDF
var protoID = []byte("Drivel")

var tMarkClient = append(protoID, []byte(":mc")...)
var tMarkServer = append(protoID, []byte(":ms")...)
var tMacClient = append(protoID, []byte(":mac_c")...)
var tMacServer = append(protoID, []byte(":mac_s")...)
var tDerive = append(protoID, []byte(":derive_key")...)
var tSKey = append(protoID, []byte(":key_extract")...)
var tKeyVerify = append(protoID, []byte(":server_mac")...)
var tXorExpand = append(protoID, []byte(":enc_expand")...)

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

// CompareAuth does a constant time compare of a Auth and a byte slice
// (presumably received over a network).
func CompareAuth(auth1 *Auth, auth2 []byte) bool {
	auth1Bytes := auth1.Bytes()
	return hmac.Equal(auth1Bytes[:], auth2)
}

// DrivelCommon is one of the final steps of the client and server sides of the handshake.
// It returns status, KEY_SEED, and AUTH.  If status is not true or (in case of the client)
// AUTH does not match the value recieved from the server, the handshake MUST be aborted.
// As this function is common for client and server, it does not accept handshake structs.
func DrivelCommon(ephemeralSecret []byte, sharedKemSecret kems.SharedSecret,
	serverOkemPublicKey okems.PublicKey, okemCiphertext okems.ObfuscatedCiphertext,
	clientKemPublicKey kems.PublicKey, kemCiphertext kems.Ciphertext) (keySeed *KeySeed, auth *Auth) {

	var derivedSecret []byte // ES'
	var finalSecret []byte   // FS

	// ES' = F1(ES, ":derive_key")
	derivedSecret = KdfExpand(ephemeralSecret, tDerive, KdfOutLength)

	// FS = F2(ES', K_e)
	finalSecret = PrfCombine(derivedSecret, sharedKemSecret.Bytes())

	// context = pk_S | c_S | pk_e | c_e | protoID
	var context bytes.Buffer
	context.Write(serverOkemPublicKey.Bytes())
	context.Write(okemCiphertext.Bytes())
	context.Write(clientKemPublicKey.Bytes())
	context.Write(kemCiphertext.Bytes())
	context.Write(protoID)

	// skey = F1(FS, context | ":key_extract")
	keySeed = (*KeySeed)(KdfExpand(finalSecret, append(context.Bytes(), tSKey...), KeySeedLength))

	// auth = F1(FS, context | ":server_mac")
	auth = (*Auth)(KdfExpand(finalSecret, append(context.Bytes(), tKeyVerify...), AuthLength))

	return keySeed, auth
}

// MessageMark computes a mark as HKDF-SHA256(ephermalSecret, msgMark | tMarkClient, KdfOutLength)
// or HKDF-SHA256(ephermalSecret, msgMark | tMarkServer, KdfOutLength) depending on `isClient`.
func MessageMark(ephermalSecret []byte, isClient bool, msgMark []byte) (mark []byte) {
	tag := tMarkServer
	if isClient {
		tag = tMarkClient
	}

	var infoBuf bytes.Buffer
	_, _ = infoBuf.Write(msgMark)
	_, _ = infoBuf.Write(tag)

	return KdfExpand(ephermalSecret, infoBuf.Bytes(), MarkLength)
}

// MessageMAC computes a MAC with HKDF-SHA256 over the entire `msg` (should include the mark)
// followed by tMacClient or tMacServer respectively (depending on the value of `isClient`).
// The argument `epochHour` is also integrated into the MAC and should not be sent alongside the message.
func MessageMAC(ephermalSecret []byte, isClient bool, msg []byte, epochHour int64) (mac []byte) {
	tag := tMacServer
	if isClient {
		tag = tMacClient
	}

	// Use fixed-length encoding of epoch hour to avoid confusion attacks
	// An 8-digit representation lasts until at least the year 12 000
	epochHourStr := fmt.Sprintf("%08d", epochHour)

	var infoBuf bytes.Buffer
	_, _ = infoBuf.Write(msg)
	_, _ = infoBuf.Write([]byte(epochHourStr))
	_, _ = infoBuf.Write(tag)

	return KdfExpand(ephermalSecret, infoBuf.Bytes(), MacLength)
}

// KdfExpand expands pseudorandomKey via HKDF-SHA256 and returns `okm_len` bytes
// of key material. pseudorandomKey must be a strong pseudorandom cryptographic key.
// Info is an arbitrary identifier for the output, repeated key-info pairs will yield the same output.
// Corresponds to F_1 from https://eprint.iacr.org/2025/408.pdf
func KdfExpand(pseudorandomKey []byte, info []byte, okmLen int) []byte {
	kdf := hkdf.Expand(sha256.New, pseudorandomKey, info)
	okm := make([]byte, okmLen)
	n, err := io.ReadFull(kdf, okm)
	if err != nil {
		panic(fmt.Sprintf("BUG: Failed HKDF: %s", err.Error()))
	} else if n != len(okm) {
		panic(fmt.Sprintf("BUG: Got truncated HKDF output: %d", n))
	}

	return okm
}

// PrfCombine combines input1 and input2 via HMAC-SHA256 and returns key material.
// Repeated input pairs will yield the same output.
// Corresponds to F_2 from https://eprint.iacr.org/2025/408.pdf
func PrfCombine(input1 []byte, input2 []byte) []byte {
	prf := hmac.New(sha256.New, input1)
	prf.Reset()
	_, _ = prf.Write(input2)
	return prf.Sum(nil)
}

// Expands the key to appropriate length using KdfExpand, then XORs with the message.
// This performs symmetric encryption/decryption and may hide structure within a message.
// However, this function MUST NOT be called twice with the same key.
func XorEncryptDecrypt(key []byte, message []byte) []byte {
	expanded := KdfExpand(key, tXorExpand, len(message))
	n := subtle.XORBytes(expanded, expanded, message)
	if n != len(message) {
		panic(fmt.Sprintf("BUG: XOR encrypt/decrypt got truncated output: %d", n))
	}
	return expanded
}
