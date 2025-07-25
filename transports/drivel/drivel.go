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

// package drivel provides an implementation of the drivel
// obfuscation protocol constructed in https://eprint.iacr.org/2024/1086.
package drivel

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"strconv"
	"syscall"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/drbg"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/log"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/probdist"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/okems"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/drivel/drivelcrypto"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/drivel/framing"
)

const (
	transportName = "drivel"

	kemNameArg    = "kem-name"
	okemNameArg   = "okem-name"
	nodeIDArg     = "node-id"
	publicKeyArg  = "public-key"
	privateKeyArg = "private-key"
	seedArg       = "drbg-seed"
	iatArg        = "iat-mode"

	biasCmdArg = "drivel-distBias"

	seedLength             = drbg.SeedLength
	headerLength           = framing.FrameOverhead + packetOverhead
	clientHandshakeTimeout = time.Duration(60) * time.Second
	serverHandshakeTimeout = time.Duration(30) * time.Second
	replayTTL              = time.Duration(3) * time.Hour

	maxIATDelay   = 100
	maxCloseDelay = 60
)

const (
	iatNone = iota
	iatEnabled
	iatParanoid
)

// biasedDist controls if the probability table will be ScrambleSuit style or
// uniformly distributed.
var biasedDist bool

type drivelClientArgs struct {
	okem okems.ObfuscatedKem
	kem  kems.KeyEncapsulationMechanism

	nodeID    *drivelcrypto.NodeID
	publicKey okems.PublicKey
	iatMode   int
}

// Transport is the drivel implementation of the base.Transport interface.
type Transport struct{}

// Name returns the name of the drivel transport protocol.
func (t *Transport) Name() string {
	return transportName
}

// ClientFactory returns a new drivelClientFactory instance.
func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	cf := &drivelClientFactory{transport: t, stateDir: stateDir}
	return cf, nil
}

// ServerFactory returns a new drivelServerFactory instance.
func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (base.ServerFactory, error) {
	st, err := serverStateFromArgs(stateDir, args)
	if err != nil {
		return nil, err
	}

	var iatSeed *drbg.Seed
	if st.iatMode != iatNone {
		iatSeedSrc := sha256.Sum256(st.drbgSeed.Bytes()[:])
		var err error
		iatSeed, err = drbg.SeedFromBytes(iatSeedSrc[:])
		if err != nil {
			return nil, err
		}
	}

	// Store the arguments that should appear in our descriptor for the clients.
	ptArgs := pt.Args{}
	ptArgs.Add(kemNameArg, st.kem.Name())
	ptArgs.Add(okemNameArg, st.okem.Name())
	ptArgs.Add(nodeIDArg, st.nodeID.Hex())
	ptArgs.Add(iatArg, strconv.Itoa(st.iatMode))

	// Initialize the replay filter.
	filter, err := replayfilter.New(replayTTL)
	if err != nil {
		return nil, err
	}

	// Initialize the close thresholds for failed connections.
	drbg, err := drbg.NewHashDrbg(st.drbgSeed)
	if err != nil {
		return nil, err
	}
	rng := rand.New(drbg)

	sf := &drivelServerFactory{st.okem, st.kem, t, &ptArgs, st.nodeID, st.identityKey, st.drbgSeed, iatSeed, st.iatMode, filter, rng.Intn(maxCloseDelay)}
	return sf, nil
}

type drivelClientFactory struct {
	transport base.Transport
	stateDir  string
}

func (cf *drivelClientFactory) Transport() base.Transport {
	return cf.transport
}

// Uses generic Pluggable Transport arguments and constructs a [drivelClientArgs] for use in [Dial].
// Requires the keys "node-id" and "iat-mode". Errors will be returned for invalid values.
func (cf *drivelClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	var nodeID *drivelcrypto.NodeID
	var publicKey okems.PublicKey

	// Unlike obfs4, Drivel uses only a single "node-id" argument in the SOCKS proxy.
	// This is due to the exceedingly large public keys that do not fit within a 510B limit.
	// See also: https://gitlab.torproject.org/tpo/anti-censorship/team/-/issues/130
	nodeIDStr, ok := args.Get(nodeIDArg)
	if !ok {
		return nil, fmt.Errorf("missing argument '%s'", nodeIDArg)
	}
	nodeID, err := drivelcrypto.NodeIDFromHex(nodeIDStr)
	if err != nil {
		return nil, err
	}

	// The public keys must be deposited in the clients stateDir.
	// The file is identified by the first bytes of nodeID in hex.
	// The file contains the public key in JSON format, see [statefile.go]
	kem, okem, publicKeyStr, err := bridgeInfoFromFile(cf.stateDir, nodeID)
	if err != nil {
		return nil, err
	}
	publicKey, err = okems.PublicKeyFromHex(okem, publicKeyStr)
	if err != nil {
		return nil, err
	}

	// IAT config is common across the two bridge line formats.
	iatStr, ok := args.Get(iatArg)
	if !ok {
		return nil, fmt.Errorf("missing argument '%s'", iatArg)
	}
	iatMode, err := strconv.Atoi(iatStr)
	if err != nil || iatMode < iatNone || iatMode > iatParanoid {
		return nil, fmt.Errorf("invalid iat-mode '%d'", iatMode)
	}

	return &drivelClientArgs{okem, kem, nodeID, publicKey, iatMode}, nil
}

// Should be used as a Dial function to initiate a Pluggable Transport session.
// Receives arguments for Drivel and requires args to be an output of [ParseArgs].
func (cf *drivelClientFactory) Dial(network, addr string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	// Validate args before bothering to open connection.
	ca, ok := args.(*drivelClientArgs)
	if !ok {
		return nil, fmt.Errorf("invalid argument type for args")
	}
	conn, err := dialFn(network, addr)
	if err != nil {
		return nil, err
	}
	dialConn := conn
	if conn, err = newDrivelClientConn(conn, ca); err != nil {
		dialConn.Close()
		return nil, err
	}
	return conn, nil
}

// Not yet implemented
func (cf *drivelClientFactory) OnEvent(f func(base.TransportEvent)) {}

type drivelServerFactory struct {
	okem okems.ObfuscatedKem
	kem  kems.KeyEncapsulationMechanism

	transport base.Transport
	args      *pt.Args

	nodeID       *drivelcrypto.NodeID
	identityKey  *okems.Keypair
	lenSeed      *drbg.Seed
	iatSeed      *drbg.Seed
	iatMode      int
	replayFilter *replayfilter.ReplayFilter

	closeDelay int
}

func (sf *drivelServerFactory) Transport() base.Transport {
	return sf.transport
}

func (sf *drivelServerFactory) Args() *pt.Args {
	return sf.args
}

func (sf *drivelServerFactory) WrapConn(conn net.Conn) (net.Conn, error) {
	// Not much point in having a separate newDrivelServerConn routine when
	// wrapping requires using values from the factory instance.

	lenDist := probdist.New(sf.lenSeed, 0, framing.MaximumSegmentLength, biasedDist)
	var iatDist *probdist.WeightedDist
	if sf.iatSeed != nil {
		iatDist = probdist.New(sf.iatSeed, 0, maxIATDelay, biasedDist)
	}

	c := &drivelConn{conn, true, lenDist, iatDist, sf.iatMode, bytes.NewBuffer(nil), bytes.NewBuffer(nil), make([]byte, consumeReadSize), nil, nil}

	startTime := time.Now()

	if err := c.serverHandshake(sf); err != nil {
		c.closeAfterDelay(sf, startTime)
		return nil, err
	}

	return c, nil
}

type drivelConn struct {
	net.Conn

	isServer bool

	lenDist *probdist.WeightedDist
	iatDist *probdist.WeightedDist
	iatMode int

	receiveBuffer        *bytes.Buffer
	receiveDecodedBuffer *bytes.Buffer
	readBuffer           []byte

	encoder *framing.Encoder
	decoder *framing.Decoder
}

// This sets up a message length distribution, executes [clientHandshake] and implements a timeout.
// Errors are forwarded from [clientHandshake].
func newDrivelClientConn(conn net.Conn, args *drivelClientArgs) (c *drivelConn, err error) {
	// Generate the initial protocol polymorphism distribution(s).
	var seed *drbg.Seed
	if seed, err = drbg.NewSeed(); err != nil {
		return
	}
	lenDist := probdist.New(seed, 0, framing.MaximumSegmentLength, biasedDist)
	var iatDist *probdist.WeightedDist
	if args.iatMode != iatNone {
		var iatSeed *drbg.Seed
		iatSeedSrc := sha256.Sum256(seed.Bytes()[:])
		if iatSeed, err = drbg.SeedFromBytes(iatSeedSrc[:]); err != nil {
			return
		}
		iatDist = probdist.New(iatSeed, 0, maxIATDelay, biasedDist)
	}

	// Allocate the client structure.
	c = &drivelConn{conn, false, lenDist, iatDist, args.iatMode, bytes.NewBuffer(nil), bytes.NewBuffer(nil), make([]byte, consumeReadSize), nil, nil}

	// Start the handshake timeout.
	deadline := time.Now().Add(clientHandshakeTimeout)
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if err = c.clientHandshake(args); err != nil {
		return nil, err
	}

	// Stop the handshake timeout.
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return
}

// Initiates a handshake with the server and waits for a response.
// This function will return detailed errors if parsing fails.
// Upon success, it returns no error and modifies conn such that future messages are obfuscated and encrypted.
func (conn *drivelConn) clientHandshake(args *drivelClientArgs) error {
	if conn.isServer {
		return fmt.Errorf("clientHandshake called on server connection")
	}
	log.Infof("This client has started a handshake")

	// Generate a new keypair
	sessionKey := args.kem.KeyGen()

	// Generate and send the client handshake.
	hs := newClientHandshake(args.okem, args.kem, args.nodeID, args.publicKey, sessionKey)
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	if _, err = conn.Conn.Write(blob); err != nil {
		return err
	}

	// Consume the server handshake.
	var hsBuf [maxHandshakeLength]byte
	for {
		n, err := conn.Conn.Read(hsBuf[:])
		if err != nil {
			// The Read() could have returned data and an error, but there is
			// no point in continuing on an EOF or whatever.
			return err
		}
		conn.receiveBuffer.Write(hsBuf[:n])

		n, seed, err := hs.parseServerHandshake(conn.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		_ = conn.receiveBuffer.Next(n)

		// Use the derived key material to intialize the link crypto.
		okm := drivelcrypto.KdfExpand(seed, mExpand, framing.KeyLength*2)
		conn.encoder = framing.NewEncoder(okm[:framing.KeyLength])
		conn.decoder = framing.NewDecoder(okm[framing.KeyLength:])

		log.Infof("This client has completed a handshake and has wrapped its connection")

		return nil
	}
}

// Initiates a handshake session with a client, reading its message from conn and sending a response.
// This function will return detailed errors if parsing fails.
// Upon success, it returns no error and modifies conn such that future messages are obfuscated and encrypted.
// Additionally, an inlineSeedFrame is sent over the wrapped connection before this returns.
func (conn *drivelConn) serverHandshake(sf *drivelServerFactory) error {
	if !conn.isServer {
		return fmt.Errorf("serverHandshake called on client connection")
	}
	log.Infof("This server has received a first handshake message")

	// Generate the server handshake, and arm the base timeout.
	hs := newServerHandshake(sf.okem, sf.kem, sf.nodeID, sf.identityKey)
	if err := conn.Conn.SetDeadline(time.Now().Add(serverHandshakeTimeout)); err != nil {
		return err
	}

	// Consume the client handshake.
	var hsBuf [maxHandshakeLength]byte
	for {
		n, err := conn.Conn.Read(hsBuf[:])
		if err != nil {
			// The Read() could have returned data and an error, but there is
			// no point in continuing on an EOF or whatever.
			return err
		}
		conn.receiveBuffer.Write(hsBuf[:n])

		seed, err := hs.parseClientHandshake(sf.replayFilter, conn.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		conn.receiveBuffer.Reset()

		if err := conn.Conn.SetDeadline(time.Time{}); err != nil {
			return nil
		}

		// Use the derived key material to intialize the link crypto.
		okm := drivelcrypto.KdfExpand(seed, mExpand, framing.KeyLength*2)
		conn.encoder = framing.NewEncoder(okm[framing.KeyLength:])
		conn.decoder = framing.NewDecoder(okm[:framing.KeyLength])

		log.Infof("This server has completed a handshake and has wrapped its connection")

		break
	}

	// Since the current and only implementation always sends a PRNG seed for
	// the length obfuscation, this makes the amount of data received from the
	// server inconsistent with the length sent from the client.
	//
	// Rebalance this by tweaking the client mimimum padding/server maximum
	// padding, and sending the PRNG seed unpadded (As in, treat the PRNG seed
	// as part of the server response).  See inlineSeedFrameLength in
	// handshake.go.

	// Generate/send the response.
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	var frameBuf bytes.Buffer
	if _, err = frameBuf.Write(blob); err != nil {
		return err
	}

	// Send the PRNG seed as the first packet.
	if err := conn.makePacket(&frameBuf, packetTypePrngSeed, sf.lenSeed.Bytes()[:], 0); err != nil {
		return err
	}
	if _, err = conn.Conn.Write(frameBuf.Bytes()); err != nil {
		return err
	}

	return nil
}

func (conn *drivelConn) Read(b []byte) (n int, err error) {
	// If there is no payload from the previous Read() calls, consume data off
	// the network.  Not all data received is guaranteed to be usable payload,
	// so do this in a loop till data is present or an error occurs.
	for conn.receiveDecodedBuffer.Len() == 0 {
		err = conn.readPackets()
		if err == framing.ErrAgain {
			// Don't proagate this back up the call stack if we happen to break
			// out of the loop.
			err = nil
			continue
		} else if err != nil {
			break
		}
	}

	// Even if err is set, attempt to do the read anyway so that all decoded
	// data gets relayed before the connection is torn down.
	if conn.receiveDecodedBuffer.Len() > 0 {
		var berr error
		n, berr = conn.receiveDecodedBuffer.Read(b)
		if err == nil {
			// Only propagate berr if there are not more important (fatal)
			// errors from the network/crypto/packet processing.
			err = berr
		}
	}

	return
}

func (conn *drivelConn) Write(b []byte) (n int, err error) {
	chopBuf := bytes.NewBuffer(b)
	var payload [maxPacketPayloadLength]byte
	var frameBuf bytes.Buffer

	// Chop the pending data into payload frames.
	for chopBuf.Len() > 0 {
		// Send maximum sized frames.
		rdLen := 0
		rdLen, err = chopBuf.Read(payload[:])
		if err != nil {
			return 0, err
		} else if rdLen == 0 {
			panic("BUG: Write(), chopping length was 0")
		}
		n += rdLen

		err = conn.makePacket(&frameBuf, packetTypePayload, payload[:rdLen], 0)
		if err != nil {
			return 0, err
		}
	}

	if conn.iatMode != iatParanoid {
		// For non-paranoid IAT, pad once per burst.  Paranoid IAT handles
		// things differently.
		if err = conn.padBurst(&frameBuf, conn.lenDist.Sample()); err != nil {
			return 0, err
		}
	}

	// Write the pending data onto the network.  Partial writes are fatal,
	// because the frame encoder state is advanced, and the code doesn't keep
	// frameBuf around.  In theory, write timeouts and whatnot could be
	// supported if this wasn't the case, but that complicates the code.
	if conn.iatMode != iatNone {
		var iatFrame [framing.MaximumSegmentLength]byte
		for frameBuf.Len() > 0 {
			iatWrLen := 0

			switch conn.iatMode {
			case iatEnabled:
				// Standard (ScrambleSuit-style) IAT obfuscation optimizes for
				// bulk transport and will write ~MTU sized frames when
				// possible.
				iatWrLen, err = frameBuf.Read(iatFrame[:])

			case iatParanoid:
				// Paranoid IAT obfuscation throws performance out of the
				// window and will sample the length distribution every time a
				// write is scheduled.
				targetLen := conn.lenDist.Sample()
				if frameBuf.Len() < targetLen {
					// There's not enough data buffered for the target write,
					// so padding must be inserted.
					if err = conn.padBurst(&frameBuf, targetLen); err != nil {
						return 0, err
					}
					if frameBuf.Len() != targetLen {
						// Ugh, padding came out to a value that required more
						// than one frame, this is relatively unlikely so just
						// resample since there's enough data to ensure that
						// the next sample will be written.
						continue
					}
				}
				iatWrLen, err = frameBuf.Read(iatFrame[:targetLen])
			}
			if err != nil {
				return 0, err
			} else if iatWrLen == 0 {
				panic("BUG: Write(), iat length was 0")
			}

			// Calculate the delay.  The delay resolution is 100 usec, leading
			// to a maximum delay of 10 msec.
			iatDelta := time.Duration(conn.iatDist.Sample() * 100)

			// Write then sleep.
			_, err = conn.Conn.Write(iatFrame[:iatWrLen])
			if err != nil {
				return 0, err
			}
			time.Sleep(iatDelta * time.Microsecond)
		}
	} else {
		_, err = conn.Conn.Write(frameBuf.Bytes())
	}

	return
}

func (conn *drivelConn) SetDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (conn *drivelConn) SetWriteDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (conn *drivelConn) closeAfterDelay(sf *drivelServerFactory, startTime time.Time) {
	// I-it's not like I w-wanna handshake with you or anything.  B-b-baka!
	defer conn.Conn.Close()

	delay := time.Duration(sf.closeDelay)*time.Second + serverHandshakeTimeout
	deadline := startTime.Add(delay)
	if time.Now().After(deadline) {
		return
	}

	if err := conn.Conn.SetReadDeadline(deadline); err != nil {
		return
	}

	// Consume and discard data on this connection until the specified interval
	// passes.
	_, _ = io.Copy(ioutil.Discard, conn.Conn)
}

func (conn *drivelConn) padBurst(burst *bytes.Buffer, toPadTo int) (err error) {
	tailLen := burst.Len() % framing.MaximumSegmentLength

	padLen := 0
	if toPadTo >= tailLen {
		padLen = toPadTo - tailLen
	} else {
		padLen = (framing.MaximumSegmentLength - tailLen) + toPadTo
	}

	if padLen > headerLength {
		err = conn.makePacket(burst, packetTypePayload, []byte{},
			uint16(padLen-headerLength))
		if err != nil {
			return
		}
	} else if padLen > 0 {
		err = conn.makePacket(burst, packetTypePayload, []byte{},
			maxPacketPayloadLength)
		if err != nil {
			return
		}
		err = conn.makePacket(burst, packetTypePayload, []byte{},
			uint16(padLen))
		if err != nil {
			return
		}
	}

	return
}

func init() {
	flag.BoolVar(&biasedDist, biasCmdArg, false, "Enable drivel using ScrambleSuit style table generation")
}

var _ base.ClientFactory = (*drivelClientFactory)(nil)
var _ base.ServerFactory = (*drivelServerFactory)(nil)
var _ base.Transport = (*Transport)(nil)
var _ net.Conn = (*drivelConn)(nil)
