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

package pq_obfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/okems"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/pq_obfs/drivelcrypto"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/pq_obfs/framing"
)

const (
	maxHandshakeLength = 8192

	clientMinPadLength       = (serverMinHandshakeLength + inlineSeedFrameLength) - clientMinHandshakeLength
	clientMaxPadLength       = maxHandshakeLength - clientMinHandshakeLength
	clientMinHandshakeLength = drivelcrypto.RepresentativeLength + markLength + macLength

	serverMinPadLength       = 0
	serverMaxPadLength       = maxHandshakeLength - (serverMinHandshakeLength + inlineSeedFrameLength)
	serverMinHandshakeLength = drivelcrypto.RepresentativeLength + drivelcrypto.AuthLength + markLength + macLength

	markLength = sha256.Size / 2
	macLength  = sha256.Size / 2

	inlineSeedFrameLength = framing.FrameOverhead + packetOverhead + seedPacketPayloadLength
)

// ErrMarkNotFoundYet is the error returned when the pq_obfs handshake is
// incomplete and requires more data to continue.  This error is non-fatal and
// is the equivalent to EAGAIN/EWOULDBLOCK.
var ErrMarkNotFoundYet = errors.New("handshake: M_[C,S] not found yet")

// ErrInvalidHandshake is the error returned when the pq_obfs handshake fails due
// to the peer not sending the correct mark.  This error is fatal and the
// connection MUST be dropped.
var ErrInvalidHandshake = errors.New("handshake: Failed to find M_[C,S]")

// ErrReplayedHandshake is the error returned when the pq_obfs handshake fails
// due it being replayed.  This error is fatal and the connection MUST be
// dropped.
var ErrReplayedHandshake = errors.New("handshake: Replay detected")

// ErrDrivelcryptoFailed is the error returned when the drivelcrypto handshake fails.  This
// error is fatal and the connection MUST be dropped.
var ErrDrivelcryptoFailed = errors.New("handshake: drivelcrypto handshake failure")

// InvalidMacError is the error returned when the handshake MACs do not match.
// This error is fatal and the connection MUST be dropped.
type InvalidMacError struct {
	Derived  []byte
	Received []byte
}

func (e *InvalidMacError) Error() string {
	return fmt.Sprintf("handshake: MAC mismatch: Dervied: %s Received: %s.",
		hex.EncodeToString(e.Derived), hex.EncodeToString(e.Received))
}

// InvalidAuthError is the error returned when the drivelcrypto AUTH tags do not match.
// This error is fatal and the connection MUST be dropped.
type InvalidAuthError struct {
	Derived  *drivelcrypto.Auth
	Received *drivelcrypto.Auth
}

func (e *InvalidAuthError) Error() string {
	return fmt.Sprintf("handshake: drivelcrypto AUTH mismatch: Derived: %s Received:%s.",
		hex.EncodeToString(e.Derived.Bytes()[:]),
		hex.EncodeToString(e.Received.Bytes()[:]))
}

// The clientHandshake struct saves all state needed for the
// client between sending and receiving its messages.
type clientHandshake struct {
	// already present in obfs4, set during newClientHandshake
	keypair        *okems.Keypair // TODO should be KEM
	nodeID         *drivelcrypto.NodeID
	serverIdentity *okems.PublicKey
	padLen         int

	// new additions in Drivel, only set in generateHandshake
	ephemeralSharedSecret []byte // K_S
	ephemeralSecret       []byte // ES
	encryptionKey1        []byte // EK_1
	encryptionKey2        []byte // EK_2

	prfEphermalSecret hash.Hash // F_1(ES, ...)

	// already present in obfs4, but only set in generateHandshake
	epochHour []byte
}

// Constructor which sets up struct for handshake. Never fails.
func newClientHandshake(nodeID *drivelcrypto.NodeID, serverIdentity *okems.PublicKey, sessionKey *okems.Keypair) *clientHandshake {
	hs := new(clientHandshake)
	hs.keypair = sessionKey
	hs.nodeID = nodeID
	hs.serverIdentity = serverIdentity
	hs.padLen = csrand.IntRange(clientMinPadLength, clientMaxPadLength) // TODO change distribution?

	return hs
}

func (hs *clientHandshake) generateHandshake() ([]byte, error) {
	var err error
	var sessionSecrets []byte
	var okemCiphertext []byte        // c_S
	var encClientKemPublicKey []byte // epk_e
	var mark []byte                  // M_C
	var mac []byte                   // MAC_C

	// The client handshake is epk_e | c_S | P_C | M_C | MAC_C(epk_e | c_S | P_C | M_C | E) where:
	//  * epk_e is the encrypted client KEM public key.
	//  * c_S is the (obfuscated) OKEM ciphertext.
	//  * P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
	// TODO change?
	//  * M_C is a "mark" computed as HMAC-SHA256(ES, epk_e | c_S| ":mc")
	// TODO do not truncate, RFC4868 does not specify those as PRFs anymore
	// TODO but I suppose we could truncate just for Marks and MACs as per the RFC
	//  * MAC_C is HMAC-SHA256(ES, epk_e | ... | E | ":mac_c")
	//  * E is the string representation of the number of hours since the UNIX epoch.

	// Generate the padding
	pad, err := makePad(hs.padLen)
	if err != nil {
		return nil, err
	}

	// Encapsulate with OKEM against server
	okemCiphertext, hs.ephemeralSharedSecret, err = okems.Encaps(hs.serverIdentity)
	if err != nil {
		return nil, err
	}

	// Derive session secrets from NodeID and OKEM shared secret
	prfSessionCombiner := hmac.New(sha256.New, hs.nodeID.Bytes()[:])
	prfSessionCombiner.Reset()
	_, _ = prfSessionCombiner.Write(hs.ephemeralSharedSecret)
	sessionSecrets = prfSessionCombiner.Sum(nil)

	// TODO Output length is too small for XOR-Encryption of an entire public key?
	// TODO What should these lengths be? How would we expand?
	ephemeralSecretLength := 10 // TODO move up to constants
	hs.ephemeralSecret = sessionSecrets[:ephemeralSecretLength]
	// XXX add KDF expand step with different :derive_key values?
	hs.encryptionKey1 = sessionSecrets[:ephemeralSecretLength]
	hs.encryptionKey2 = sessionSecrets[:ephemeralSecretLength]

	// Prepare other PRF given our derived secrets
	hs.prfEphermalSecret = hmac.New(sha256.New, hs.ephemeralSecret)

	// Encrypt own KEM public key
	clientKemPublicKey := hs.keypair.Public()
	encClientKemPublicKey = drivelcrypto.XorEncryptDecrypt(hs.encryptionKey1, clientKemPublicKey.Bytes())
	// TODO figure out how this should work?

	// buf will be used to construct the final message
	var buf bytes.Buffer

	// Start building message as epk_e | c_S
	buf.Write(encClientKemPublicKey)
	buf.Write(okemCiphertext)

	// Derive mark before padding
	mark = drivelcrypto.MessageMark(hs.prfEphermalSecret, true, buf.Bytes())

	// Continue building message with P_C | M_C
	buf.Write(pad)
	buf.Write(mark)

	// Generate MAC over entire message
	hs.epochHour = []byte(strconv.FormatInt(getEpochHour(), 10))
	mac = drivelcrypto.MessageMAC(hs.prfEphermalSecret, true, buf.Bytes(), hs.epochHour)

	// Complete message with mac
	buf.Write(mac)

	return buf.Bytes(), nil
}

func (hs *clientHandshake) parseServerHandshake(resp []byte) (int, []byte, error) {
	// TODO this verifies the final server message!

	// No point in examining the data unless the miminum plausible response has
	// been received.
	if serverMinHandshakeLength > len(resp) {
		return 0, nil, ErrMarkNotFoundYet
	}

	if hs.serverRepresentative == nil || hs.serverAuth == nil {
		// Pull out the representative/AUTH. (XXX: Add ctors to drivelcrypto)
		hs.serverRepresentative = new(drivelcrypto.Representative)
		copy(hs.serverRepresentative.Bytes()[:], resp[0:drivelcrypto.RepresentativeLength])
		hs.serverAuth = new(drivelcrypto.Auth)
		copy(hs.serverAuth.Bytes()[:], resp[drivelcrypto.RepresentativeLength:])

		// Derive the mark.
		hs.mac.Reset()
		_, _ = hs.mac.Write(hs.serverRepresentative.Bytes()[:])
		hs.serverMark = hs.mac.Sum(nil)[:markLength]
	}

	// Attempt to find the mark + MAC.
	pos := findMarkMac(hs.serverMark, resp, drivelcrypto.RepresentativeLength+drivelcrypto.AuthLength+serverMinPadLength,
		maxHandshakeLength, false)
	if pos == -1 {
		if len(resp) >= maxHandshakeLength {
			return 0, nil, ErrInvalidHandshake
		}
		return 0, nil, ErrMarkNotFoundYet
	}

	// Validate the MAC.
	hs.mac.Reset()
	_, _ = hs.mac.Write(resp[:pos+markLength])
	_, _ = hs.mac.Write(hs.epochHour)
	macCmp := hs.mac.Sum(nil)[:macLength]
	macRx := resp[pos+markLength : pos+markLength+macLength]
	if !hmac.Equal(macCmp, macRx) {
		return 0, nil, &InvalidMacError{macCmp, macRx}
	}

	// Complete the handshake.
	serverPublic := hs.serverRepresentative.ToPublic()
	ok, seed, auth := drivelcrypto.ClientHandshake(hs.keypair, serverPublic,
		hs.serverIdentity, hs.nodeID)
	if !ok {
		return 0, nil, ErrDrivelcryptoFailed
	}
	if !drivelcrypto.CompareAuth(auth, hs.serverAuth.Bytes()[:]) {
		return 0, nil, &InvalidAuthError{auth, hs.serverAuth}
	}

	return pos + markLength + macLength, seed.Bytes()[:], nil
}

type serverHandshake struct {
	keypair        *okems.Keypair
	nodeID         *drivelcrypto.NodeID
	serverIdentity *okems.Keypair
	epochHour      []byte
	serverAuth     *drivelcrypto.Auth

	padLen int
	mac    hash.Hash

	clientRepresentative *drivelcrypto.Representative
	clientMark           []byte
}

func newServerHandshake(nodeID *drivelcrypto.NodeID, serverIdentity *okems.Keypair, sessionKey *okems.Keypair) *serverHandshake {
	hs := new(serverHandshake)
	hs.keypair = sessionKey
	hs.nodeID = nodeID
	hs.serverIdentity = serverIdentity
	hs.padLen = csrand.IntRange(serverMinPadLength, serverMaxPadLength)
	hs.mac = hmac.New(sha256.New, append(hs.serverIdentity.Public().Bytes(), hs.nodeID.Bytes()[:]...))

	return hs
}

func (hs *serverHandshake) parseClientHandshake(filter *replayfilter.ReplayFilter, resp []byte) ([]byte, error) {
	// TODO this receives a client message and parses it!

	// No point in examining the data unless the miminum plausible response has
	// been received.
	if clientMinHandshakeLength > len(resp) {
		return nil, ErrMarkNotFoundYet
	}

	if hs.clientRepresentative == nil {
		// Pull out the representative/AUTH. (XXX: Add ctors to drivelcrypto)
		hs.clientRepresentative = new(drivelcrypto.Representative)
		copy(hs.clientRepresentative.Bytes()[:], resp[0:drivelcrypto.RepresentativeLength])

		// Derive the mark.
		hs.mac.Reset()
		_, _ = hs.mac.Write(hs.clientRepresentative.Bytes()[:])
		hs.clientMark = hs.mac.Sum(nil)[:markLength]
	}

	// Attempt to find the mark + MAC.
	pos := findMarkMac(hs.clientMark, resp, drivelcrypto.RepresentativeLength+clientMinPadLength,
		maxHandshakeLength, true)
	if pos == -1 {
		if len(resp) >= maxHandshakeLength {
			return nil, ErrInvalidHandshake
		}
		return nil, ErrMarkNotFoundYet
	}

	// Validate the MAC.
	macFound := false
	for _, off := range []int64{0, -1, 1} {
		// Allow epoch to be off by up to a hour in either direction.
		epochHour := []byte(strconv.FormatInt(getEpochHour()+int64(off), 10))
		hs.mac.Reset()
		_, _ = hs.mac.Write(resp[:pos+markLength])
		_, _ = hs.mac.Write(epochHour)
		macCmp := hs.mac.Sum(nil)[:macLength]
		macRx := resp[pos+markLength : pos+markLength+macLength]
		if hmac.Equal(macCmp, macRx) {
			// Ensure that this handshake has not been seen previously.
			if filter.TestAndSet(time.Now(), macRx) {
				// The client either happened to generate exactly the same
				// session key and padding, or someone is replaying a previous
				// handshake.  In either case, fuck them.
				return nil, ErrReplayedHandshake
			}

			macFound = true
			hs.epochHour = epochHour

			// We could break out here, but in the name of reducing timing
			// variation, evaluate all 3 MACs.
		}
	}
	if !macFound {
		// This probably should be an InvalidMacError, but conveying the 3 MACS
		// that would be accepted is annoying so just return a generic fatal
		// failure.
		return nil, ErrInvalidHandshake
	}

	// Client should never sent trailing garbage.
	if len(resp) != pos+markLength+macLength {
		return nil, ErrInvalidHandshake
	}

	clientPublic := hs.clientRepresentative.ToPublic()
	ok, seed, auth := drivelcrypto.ServerHandshake(clientPublic, hs.keypair,
		hs.serverIdentity, hs.nodeID)
	if !ok {
		return nil, ErrDrivelcryptoFailed
	}
	hs.serverAuth = auth

	return seed.Bytes()[:], nil
}

func (hs *serverHandshake) generateHandshake() ([]byte, error) {
	// TODO this uses a parsed client message to send a response!

	var buf bytes.Buffer

	hs.mac.Reset()
	_, _ = hs.mac.Write(hs.keypair.Public().Bytes())
	mark := hs.mac.Sum(nil)[:markLength]

	// The server handshake is Y | AUTH | P_S | M_S | MAC(Y | AUTH | P_S | M_S | E) where:
	//  * Y is the server's ephemeral Curve25519 public key representative.
	//  * AUTH is the drivelcrypto handshake AUTH value.
	//  * P_S is [serverMinPadLength,serverMaxPadLength] bytes of random padding.
	//  * M_S is HMAC-SHA256-128(serverIdentity | NodeID, Y)
	//  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, Y .... E)
	//  * E is the string representation of the number of hours since the UNIX
	//    epoch.

	// Generate the padding
	pad, err := makePad(hs.padLen)
	if err != nil {
		return nil, err
	}

	// Write Y, AUTH, P_S, M_S.
	buf.Write(hs.keypair.Public().Bytes())
	buf.Write(hs.serverAuth.Bytes()[:])
	buf.Write(pad)
	buf.Write(mark)

	// Calculate and write the MAC.
	hs.mac.Reset()
	_, _ = hs.mac.Write(buf.Bytes())
	_, _ = hs.mac.Write(hs.epochHour) // Set in hs.parseClientHandshake()
	buf.Write(hs.mac.Sum(nil)[:macLength])

	return buf.Bytes(), nil
}

// getEpochHour returns the number of hours since the UNIX epoch.
func getEpochHour() int64 {
	return time.Now().Unix() / 3600
}

func findMarkMac(mark, buf []byte, startPos, maxPos int, fromTail bool) (pos int) {
	if len(mark) != markLength {
		panic(fmt.Sprintf("BUG: Invalid mark length: %d", len(mark)))
	}

	endPos := len(buf)
	if startPos > len(buf) {
		return -1
	}
	if endPos > maxPos {
		endPos = maxPos
	}
	if endPos-startPos < markLength+macLength {
		return -1
	}

	if fromTail {
		// The server can optimize the search process by only examining the
		// tail of the buffer.  The client can't send valid data past M_C |
		// MAC_C as it does not have the server's public key yet.
		pos = endPos - (markLength + macLength)
		if !hmac.Equal(buf[pos:pos+markLength], mark) {
			return -1
		}

		return
	}

	// The client has to actually do a substring search since the server can
	// and will send payload trailing the response.
	//
	// XXX: bytes.Index() uses a naive search, which kind of sucks.
	pos = bytes.Index(buf[startPos:endPos], mark)
	if pos == -1 {
		return -1
	}

	// Ensure that there is enough trailing data for the MAC.
	if startPos+pos+markLength+macLength > endPos {
		return -1
	}

	// Return the index relative to the start of the slice.
	pos += startPos
	return
}

func makePad(padLen int) ([]byte, error) {
	pad := make([]byte, padLen)
	if err := csrand.Bytes(pad); err != nil {
		return nil, err
	}

	return pad, nil
}
