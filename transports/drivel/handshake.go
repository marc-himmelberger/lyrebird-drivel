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
	"crypto/hmac"
	"errors"
	"fmt"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/log"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptodata"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/okems"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/drivel/drivelcrypto"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/drivel/framing"
)

const (
	// Currently set to 11 pages of 4KiB each (for good alignment).
	// with 35973 B, TestGetLengthDetails first verifies that all data can fit
	// this corresponds to 8.7825 pages - we then also add the original 8192 B for padding
	// => buffer is 35.130 KiB
	// TODO Using better fragmentation, a reduction by another 21520 B is plausible (size of FrodoKEM-1344 public keys)
	// A static choice of KEM/OKEM combination (at compile-time) could also reduce this significantly (~ 10 KiB)
	maxHandshakeLength = 45056

	inlineSeedFrameLength = framing.FrameOverhead + packetOverhead + seedPacketPayloadLength
)

type lengthDetails struct {
	epkLength  int
	ectLength  int
	csLength   int
	authLength int

	clientMinHandshakeLength int // epk_e | c_S | M_C | MAC_C
	serverMinHandshakeLength int // ect_e | auth | M_S | MAC_S

	clientMinPadLength int
	clientMaxPadLength int

	serverMinPadLength int
	serverMaxPadLength int
}

func getLengthDetails(okem okems.ObfuscatedKem, kem kems.KeyEncapsulationMechanism) *lengthDetails {
	details := new(lengthDetails)

	details.epkLength = kem.LengthPublicKey()
	details.ectLength = kem.LengthCiphertext()
	details.csLength = okem.LengthCiphertext()
	details.authLength = drivelcrypto.AuthLength

	details.clientMinHandshakeLength = details.epkLength + details.csLength + drivelcrypto.MarkLength + drivelcrypto.MacLength
	details.serverMinHandshakeLength = details.ectLength + details.authLength + drivelcrypto.MarkLength + drivelcrypto.MacLength

	// Pad to send at least as much data as smallest server response with inlineSeedFrameLength added
	details.clientMinPadLength = max(0, (details.serverMinHandshakeLength+inlineSeedFrameLength)-details.clientMinHandshakeLength)
	// No minimum amound of padding in server response
	details.serverMinPadLength = 0

	// Pad to at most maxHandshakeLength and allow for inlineSeedFrameLength in server response
	details.clientMaxPadLength = maxHandshakeLength - details.clientMinHandshakeLength
	details.serverMaxPadLength = maxHandshakeLength - (details.serverMinHandshakeLength + inlineSeedFrameLength)

	// log dynamically calculated size details for later analysis
	log.Infof("client padding range [%d, %d]", details.clientMinPadLength, details.clientMaxPadLength)
	log.Infof("bridge padding range [%d, %d]", details.serverMinPadLength, details.serverMaxPadLength)
	log.Infof("size_kem_pk %d", details.epkLength)
	log.Infof("size_kem_ctxt %d", details.ectLength)
	log.Infof("size_okem_ctxt %d", details.csLength)
	log.Infof("size_mark %d", drivelcrypto.MarkLength)
	log.Infof("size_mac %d", drivelcrypto.MacLength)
	log.Infof("size_auth %d", details.authLength)

	return details
}

// Define string constants for info/context inputs to HKDF
var protoID = []byte("Drivel")
var mExpandEnc1 = append(protoID, []byte(":enckey1")...)
var mExpandEnc2 = append(protoID, []byte(":enckey2")...)
var mExpand = append(protoID, []byte(":key_expand")...)

// ErrMarkNotFoundYet is the error returned when the drivel handshake is
// incomplete and requires more data to continue. This error is non-fatal and
// is the equivalent to EAGAIN/EWOULDBLOCK.
var ErrMarkNotFoundYet = errors.New("handshake: M_[C,S] not found yet")

// ErrInvalidHandshake is the error returned when the drivel handshake fails due
// to the peer not sending the correct mark or sending excessive data.
// This error is fatal and the connection MUST be dropped.
var ErrInvalidHandshake = errors.New("handshake: Failed to find M_[C,S]")

// ErrReplayedHandshake is the error returned when the drivel handshake fails
// due it being replayed. This error is fatal and the connection MUST be
// dropped.
var ErrReplayedHandshake = errors.New("handshake: Replay detected")

// ErrDrivelcryptoFailed is the error returned when the drivelcrypto handshake fails.
// This error is fatal and the connection MUST be dropped.
var ErrDrivelcryptoFailed = errors.New("handshake: drivelcrypto handshake failure")

// InvalidMacError is the error returned when the handshake MACs do not match.
// This error is fatal and the connection MUST be dropped.
var ErrInvalidMac = errors.New("handshake: MAC mismatch")

// InvalidAuthError is the error returned when the drivelcrypto AUTH tags do not match.
// This error is fatal and the connection MUST be dropped.
var ErrInvalidAuth = errors.New("handshake: AUTH mismatch")

// The clientHandshake struct saves all state needed for the
// client between sending and receiving its messages.
type clientHandshake struct {
	// Interface references for employed schemes
	okem          okems.ObfuscatedKem
	kem           kems.KeyEncapsulationMechanism
	lengthDetails *lengthDetails

	// already present in obfs4, set during newClientHandshake

	keypair        *kems.Keypair        // pk_e, sk_e
	nodeID         *drivelcrypto.NodeID // NodeID
	serverIdentity okems.PublicKey      // pk_S
	padLen         int                  // P_C

	// new additions in Drivel, only set in generateHandshake

	okemCiphertext okems.ObfuscatedCiphertext // c_S

	ephemeralSecret []byte // ES
	encryptionKey1  []byte // EK_1
	encryptionKey2  []byte // EK_2

	// new additions in Drivel, only set in parseServerHandshake

	encClientKemCiphertext []byte
	serverAuth             *drivelcrypto.Auth
	serverMark             []byte

	// already present in obfs4, but only set in generateHandshake
	epochHour int64
}

// Constructor which sets up struct for handshake. Never fails.
func newClientHandshake(
	okem okems.ObfuscatedKem, kem kems.KeyEncapsulationMechanism,
	nodeID *drivelcrypto.NodeID, serverIdentity okems.PublicKey,
	sessionKey *kems.Keypair,
) *clientHandshake {
	log.Infof("creating clientHandshake")
	hs := new(clientHandshake)
	hs.okem = okem
	hs.kem = kem
	hs.keypair = sessionKey
	hs.nodeID = nodeID
	hs.serverIdentity = serverIdentity
	hs.lengthDetails = getLengthDetails(okem, kem)
	hs.padLen = csrand.IntRange(hs.lengthDetails.clientMinPadLength, hs.lengthDetails.clientMaxPadLength)

	return hs
}

// Uses the state saved in hs to generate a raw message,
// suitable for sending over the network to initiate a handshake.
func (hs *clientHandshake) generateHandshake() ([]byte, error) {
	log.Infof("clientHandshake.generateHandshake()")
	var err error
	var encClientKemPublicKey []byte // epk_e
	var clientMark []byte            // M_C
	var clientMac []byte             // MAC_C

	// The client handshake is epk_e | c_S | P_C | M_C | MAC_C(epk_e | c_S | P_C | M_C | E) where:
	//  * epk_e is the encrypted client KEM public key.
	//  * c_S is the (obfuscated) OKEM ciphertext.
	//  * P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
	//  * M_C is a "mark" computed as HKDF-SHA256(ES, epk_e | c_S| ":mc")
	//  * MAC_C is HKDF-SHA256(ES, epk_e | ... | E | ":mac_c")
	//  * E is the string representation of the number of hours since the UNIX epoch.

	// Generate the padding
	pad, err := makePad(hs.padLen)
	if err != nil {
		return nil, err
	}

	// Encapsulate with OKEM against server

	var okemSharedSecret okems.SharedSecret // K_S

	hs.okemCiphertext, okemSharedSecret, err = hs.okem.Encaps(hs.serverIdentity)
	if err != nil {
		return nil, err
	}

	// Derive ephemeral secret from NodeID and OKEM shared secret
	hs.ephemeralSecret = drivelcrypto.PrfCombine(hs.nodeID.Bytes()[:], okemSharedSecret.Bytes())

	// Derive encryption keys from ephemeral secret using KDF and different info values
	hs.encryptionKey1 = drivelcrypto.KdfExpand(hs.ephemeralSecret, mExpandEnc1, drivelcrypto.XorKeySize)
	hs.encryptionKey2 = drivelcrypto.KdfExpand(hs.ephemeralSecret, mExpandEnc2, drivelcrypto.XorKeySize)

	// Encrypt own KEM public key
	clientKemPublicKey := hs.keypair.Public()
	encClientKemPublicKey = drivelcrypto.XorEncryptDecrypt(hs.encryptionKey1, clientKemPublicKey.Bytes())

	// buf will be used to construct the final message
	buf := bytes.NewBuffer(make([]byte, 0, maxHandshakeLength))

	// Start building message as epk_e | c_S
	buf.Write(encClientKemPublicKey)
	buf.Write(hs.okemCiphertext.Bytes())

	// Derive mark before padding
	clientMark = drivelcrypto.MessageMark(hs.ephemeralSecret, true, buf.Bytes())

	// Continue building message with P_C | M_C
	buf.Write(pad)
	buf.Write(clientMark)

	// Generate MAC over entire message
	hs.epochHour = getEpochHour()
	clientMac = drivelcrypto.MessageMAC(hs.ephemeralSecret, true, buf.Bytes(), hs.epochHour)

	// Complete message with mac
	buf.Write(clientMac)

	return buf.Bytes(), nil
}

// Takes a raw message, received over the network and attempts to parse it as a server handshake message.
// This function will return detailed errors if parsing fails.
// Upon success, it returns the number of bytes read and the KEY_SEED.
// Trailing bytes may contain another message, such as an inlineSeedFrame.
func (hs *clientHandshake) parseServerHandshake(resp []byte) (int, []byte, error) {
	log.Infof("clientHandshake.parseServerHandshake(%d B)", len(resp))
	// Copy for brevity
	ectLength := hs.lengthDetails.ectLength
	authLength := hs.lengthDetails.authLength

	// No point in examining the data unless the miminum plausible response has
	// been received.
	if hs.lengthDetails.serverMinHandshakeLength > len(resp) {
		return 0, nil, ErrMarkNotFoundYet
	}

	// First, read encClientKemCiphertext and serverAuth.
	// Then calculate serverMark.
	if hs.serverMark == nil {
		// Pull out message before padding: ect_e | auth
		hs.encClientKemCiphertext = make([]byte, ectLength)
		authBytes := make([]byte, authLength)

		copy(hs.encClientKemCiphertext, resp[0:ectLength])
		copy(authBytes, resp[ectLength:ectLength+authLength])

		hs.serverAuth = (*drivelcrypto.Auth)(authBytes)

		// Derive the mark.
		hs.serverMark = drivelcrypto.MessageMark(hs.ephemeralSecret, false, resp[0:ectLength])
	}

	// Attempt to find the mark + MAC.
	pos := findMarkMac(hs.serverMark, resp, (ectLength+authLength)+hs.lengthDetails.serverMinPadLength,
		maxHandshakeLength, false)
	if pos == -1 {
		if len(resp) >= maxHandshakeLength {
			return 0, nil, ErrInvalidHandshake
		}
		return 0, nil, ErrMarkNotFoundYet
	}

	// Validate the MAC.
	macCmp := drivelcrypto.MessageMAC(hs.ephemeralSecret, false, resp[:pos+drivelcrypto.MarkLength], hs.epochHour)
	macRx := resp[pos+drivelcrypto.MarkLength : pos+drivelcrypto.MarkLength+drivelcrypto.MacLength]
	if !hmac.Equal(macCmp, macRx) {
		return 0, nil, ErrInvalidMac
	}

	// Decrypt KEM ciphertext
	ctxtBytes := drivelcrypto.XorEncryptDecrypt(hs.encryptionKey2, hs.encClientKemCiphertext)
	cd, err := cryptodata.New(ctxtBytes, ectLength)
	if err != nil {
		return 0, nil, err
	}
	kemCiphertext := kems.Ciphertext(cd)

	// Decapsulate with KEM
	kemSharedSecret, err := hs.kem.Decaps(hs.keypair.Private(), kemCiphertext)
	if err != nil {
		return 0, nil, err
	}

	seed, auth := drivelcrypto.DrivelCommon(hs.ephemeralSecret, kemSharedSecret, hs.serverIdentity,
		hs.okemCiphertext, hs.keypair.Public(), kemCiphertext)

	if !drivelcrypto.CompareAuth(auth, hs.serverAuth.Bytes()[:]) {
		return 0, nil, ErrInvalidAuth
	}

	return pos + drivelcrypto.MarkLength + drivelcrypto.MacLength, seed.Bytes()[:], nil
}

// The serverHandshake struct saves all state needed for the
// server and is analogous to clientHandshake.
type serverHandshake struct {
	// Interface references for employed schemes
	okem          okems.ObfuscatedKem
	kem           kems.KeyEncapsulationMechanism
	lengthDetails *lengthDetails

	// already present in obfs4, set during newServerHandshake

	serverIdentity *okems.Keypair       // pk_S, sk_S
	nodeID         *drivelcrypto.NodeID // NodeID
	padLen         int                  // P_S

	// new additions in Drivel, only set in parseClientHandshake

	encClientKemPublicKey []byte                     // epk_e
	okemCiphertext        okems.ObfuscatedCiphertext // c_S
	clientMark            []byte                     // M_C

	ephemeralSecret []byte // ES
	encryptionKey1  []byte // EK_1
	encryptionKey2  []byte // EK_2

	encClientKemCiphertext []byte            // ect_e
	kemSharedSecret        kems.SharedSecret // ES'

	// already present in obfs4, but only set in parseClientHandshake

	epochHour  int64 // Client's chosen epoch hour, not more than 1 hour off
	serverAuth *drivelcrypto.Auth
}

func newServerHandshake(
	okem okems.ObfuscatedKem, kem kems.KeyEncapsulationMechanism,
	nodeID *drivelcrypto.NodeID, serverIdentity *okems.Keypair,
) *serverHandshake {
	log.Infof("creating serverHandshake")
	hs := new(serverHandshake)
	hs.okem = okem
	hs.kem = kem
	hs.nodeID = nodeID
	hs.serverIdentity = serverIdentity
	hs.lengthDetails = getLengthDetails(okem, kem)
	hs.padLen = csrand.IntRange(hs.lengthDetails.serverMinPadLength, hs.lengthDetails.serverMaxPadLength)

	return hs
}

// Takes a raw message, received over the network and attempts to parse it as a client handshake message.
// This function will return detailed errors if parsing fails.
// Upon success, it returns the KEY_SEED and updates the state in hs.
// The message is fully consumed.
func (hs *serverHandshake) parseClientHandshake(filter *replayfilter.ReplayFilter, resp []byte) ([]byte, error) {
	log.Infof("serverHandshake.parseClientHandshake(%d B)", len(resp))
	// Copy for brevity
	epkLength := hs.lengthDetails.epkLength
	csLength := hs.lengthDetails.csLength

	// No point in examining the data unless the miminum plausible response has
	// been received.
	if hs.lengthDetails.clientMinHandshakeLength > len(resp) {
		return nil, ErrMarkNotFoundYet
	}

	// First, read encClientKemPublicKey and okemCiphertext.
	// Then derive ephemeralSecret, set encryptionKey1, encryptionKey2 and calculate clientMark.
	if hs.clientMark == nil {
		// Pull out message before padding: epk_e | c_S
		hs.encClientKemPublicKey = make([]byte, epkLength)
		okemCtxt := make([]byte, csLength)

		copy(hs.encClientKemPublicKey, resp[0:epkLength])
		copy(okemCtxt, resp[epkLength:epkLength+csLength])

		cd, err := cryptodata.New(okemCtxt, csLength)
		if err != nil {
			return nil, err
		}
		hs.okemCiphertext = okems.ObfuscatedCiphertext(cd)

		// Decapsulate with OKEM
		shared, err := hs.okem.Decaps(hs.serverIdentity.Private(), hs.okemCiphertext)
		if err != nil {
			return nil, err
		}

		// Derive ephemeral secret from NodeID and OKEM shared secret
		hs.ephemeralSecret = drivelcrypto.PrfCombine(hs.nodeID.Bytes()[:], shared.Bytes())

		// Derive encryption keys from ephemeral secret using KDF and different info values
		hs.encryptionKey1 = drivelcrypto.KdfExpand(hs.ephemeralSecret, mExpandEnc1, drivelcrypto.XorKeySize)
		hs.encryptionKey2 = drivelcrypto.KdfExpand(hs.ephemeralSecret, mExpandEnc2, drivelcrypto.XorKeySize)

		// Derive the mark.
		hs.clientMark = drivelcrypto.MessageMark(hs.ephemeralSecret, true, resp[0:epkLength+csLength])
	}

	// Attempt to find the mark + MAC.
	pos := findMarkMac(hs.clientMark, resp, (epkLength+csLength)+hs.lengthDetails.clientMinPadLength,
		maxHandshakeLength, true)
	if pos == -1 {
		if len(resp) >= maxHandshakeLength {
			return nil, ErrInvalidHandshake
		}
		return nil, ErrMarkNotFoundYet
	}

	// Validate the MAC. Allow epoch to be off by up to a hour in either direction.
	macFound := false
	epochHour := getEpochHour()
	for _, off := range []int64{0, -1, 1} {
		macCmp := drivelcrypto.MessageMAC(hs.ephemeralSecret, true, resp[:pos+drivelcrypto.MarkLength], epochHour+off)
		macRx := resp[pos+drivelcrypto.MarkLength : pos+drivelcrypto.MarkLength+drivelcrypto.MacLength]
		if hmac.Equal(macCmp, macRx) {
			// Ensure that this handshake has not been seen previously.
			if filter.TestAndSet(time.Now(), macRx) {
				// The client either happened to generate exactly the same
				// session key and padding, or someone is replaying a previous
				// handshake. In either case, fuck them.
				return nil, ErrReplayedHandshake
			}

			macFound = true
			hs.epochHour = epochHour + off

			// We could break out here, but in the name of reducing timing
			// variation, evaluate all 3 MACs.
		}
	}
	if !macFound {
		return nil, ErrInvalidMac
	}

	// Client should never sent trailing garbage.
	if len(resp) != pos+drivelcrypto.MarkLength+drivelcrypto.MacLength {
		return nil, ErrInvalidHandshake
	}

	// Decrypt client KEM public key
	publicBytes := drivelcrypto.XorEncryptDecrypt(hs.encryptionKey1, hs.encClientKemPublicKey)
	cd, err := cryptodata.New(publicBytes, epkLength)
	if err != nil {
		return nil, err
	}
	clientKemPublicKey := kems.PublicKey(cd)

	// Encapsulate with KEM against client

	var kemCiphertext kems.Ciphertext // c_E

	kemCiphertext, hs.kemSharedSecret, err = hs.kem.Encaps(clientKemPublicKey)
	if err != nil {
		return nil, err
	}

	// Encrypt KEM ciphertext
	hs.encClientKemCiphertext = drivelcrypto.XorEncryptDecrypt(hs.encryptionKey2, kemCiphertext.Bytes())

	var seed *drivelcrypto.KeySeed
	seed, hs.serverAuth = drivelcrypto.DrivelCommon(hs.ephemeralSecret, hs.kemSharedSecret, hs.serverIdentity.Public(),
		hs.okemCiphertext, clientKemPublicKey, kemCiphertext)

	return seed.Bytes()[:], nil
}

// Uses the state saved in hs to generate a raw message, suitable for sending over the network in response.
func (hs *serverHandshake) generateHandshake() ([]byte, error) {
	log.Infof("serverHandshake.generateHandshake()")
	var err error
	var serverMark []byte // M_S
	var serverMac []byte  // MAC_S

	// The server handshake is ect_e | AUTH | P_S | M_S | MAC(ect_e | AUTH | P_S | M_S | E) where:
	//  * ect_e is the encrypted KEM ciphertext.
	//  * AUTH is the drivelcrypto handshake AUTH value.
	//  * P_S is [serverMinPadLength,serverMaxPadLength] bytes of random padding.
	//  * M_S is a "mark" computed as HKDF-SHA256(ES, ect_e | ":ms")
	//  * MAC_S is HKDF-SHA256(ES, ect_e | ... | E | ":mac_s")
	//  * E is the string representation of the number of hours since the UNIX epoch.

	// Generate the padding
	pad, err := makePad(hs.padLen)
	if err != nil {
		return nil, err
	}

	// buf will be used to construct the final message
	buf := bytes.NewBuffer(make([]byte, 0, maxHandshakeLength))

	// Start building message as ect_e
	buf.Write(hs.encClientKemCiphertext)

	// Derive mark before adding AUTH and padding
	serverMark = drivelcrypto.MessageMark(hs.ephemeralSecret, false, buf.Bytes())

	// Continue building message with auth | P_S | M_S
	buf.Write(hs.serverAuth[:])
	buf.Write(pad)
	buf.Write(serverMark)

	// Generate MAC over entire message
	// epochHour was set in hs.parseClientHandshake()
	serverMac = drivelcrypto.MessageMAC(hs.ephemeralSecret, false, buf.Bytes(), hs.epochHour)

	// Complete message with mac
	buf.Write(serverMac)

	return buf.Bytes(), nil
}

// getEpochHour returns the number of hours since the UNIX epoch.
func getEpochHour() int64 {
	return time.Now().Unix() / 3600
}

func findMarkMac(mark, buf []byte, startPos, maxPos int, fromTail bool) (pos int) {
	if len(mark) != drivelcrypto.MarkLength {
		panic(fmt.Sprintf("BUG: Invalid mark length: %d", len(mark)))
	}

	endPos := len(buf)
	if startPos > len(buf) {
		return -1
	}
	if endPos > maxPos {
		endPos = maxPos
	}
	if endPos-startPos < drivelcrypto.MarkLength+drivelcrypto.MacLength {
		return -1
	}

	if fromTail {
		// The server can optimize the search process by only examining the
		// tail of the buffer. The client can't send valid data past M_C |
		// MAC_C as it does not have the server's ephemeral shared secret yet.
		pos = endPos - (drivelcrypto.MarkLength + drivelcrypto.MacLength)
		if !hmac.Equal(buf[pos:pos+drivelcrypto.MarkLength], mark) {
			return -1
		}

		return
	}

	// The client has to actually do a substring search since the server can
	// and will send payload trailing the response.
	pos = bytes.Index(buf[startPos:endPos], mark)
	if pos == -1 {
		return -1
	}

	// Ensure that there is enough trailing data for the MAC.
	if startPos+pos+drivelcrypto.MarkLength+drivelcrypto.MacLength > endPos {
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
