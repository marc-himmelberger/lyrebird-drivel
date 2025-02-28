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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/drbg"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/okem"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/pq_obfs/drivelcrypto"
)

const (
	stateFile  = "pq_obfs_state.json"
	bridgeFile = "pq_obfs_bridgeline.txt"

	certSuffix = "=="
	certLength = drivelcrypto.NodeIDLength + drivelcrypto.PublicKeyLength
)

type jsonServerState struct {
	NodeID     string `json:"node-id"`
	PrivateKey string `json:"private-key"`
	PublicKey  string `json:"public-key"`
	DrbgSeed   string `json:"drbg-seed"`
	IATMode    int    `json:"iat-mode"`
}

type pq_obfsServerCert struct {
	raw []byte
}

func (cert *pq_obfsServerCert) String() string {
	return strings.TrimSuffix(base64.StdEncoding.EncodeToString(cert.raw), certSuffix)
}

func (cert *pq_obfsServerCert) unpack() (*drivelcrypto.NodeID, *okem.PublicKey) {
	if len(cert.raw) != certLength {
		panic(fmt.Sprintf("cert length %d is invalid", len(cert.raw)))
	}

	nodeID, _ := drivelcrypto.NewNodeID(cert.raw[:drivelcrypto.NodeIDLength])
	pubKey, _ := okem.NewPublicKey(cert.raw[drivelcrypto.NodeIDLength:])

	return nodeID, pubKey
}

func serverCertFromString(encoded string) (*pq_obfsServerCert, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded + certSuffix)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cert: %s", err)
	}

	if len(decoded) != certLength {
		return nil, fmt.Errorf("cert length %d is invalid", len(decoded))
	}

	return &pq_obfsServerCert{raw: decoded}, nil
}

func serverCertFromState(st *pq_obfsServerState) *pq_obfsServerCert {
	cert := new(pq_obfsServerCert)
	cert.raw = append(st.nodeID.Bytes()[:], st.identityKey.Public().Bytes()...)
	return cert
}

type pq_obfsServerState struct {
	nodeID      *drivelcrypto.NodeID
	identityKey *okem.Keypair
	drbgSeed    *drbg.Seed
	iatMode     int

	cert *pq_obfsServerCert
}

func (st *pq_obfsServerState) clientString() string {
	return fmt.Sprintf("%s=%s %s=%d", certArg, st.cert, iatArg, st.iatMode)
}

func serverStateFromArgs(stateDir string, args *pt.Args) (*pq_obfsServerState, error) {
	var js jsonServerState
	var nodeIDOk, privKeyOk, seedOk bool

	js.NodeID, nodeIDOk = args.Get(nodeIDArg)
	js.PrivateKey, privKeyOk = args.Get(privateKeyArg)
	js.DrbgSeed, seedOk = args.Get(seedArg)
	iatStr, iatOk := args.Get(iatArg)

	// Either a private key, node id, and seed are ALL specified, or
	// they should be loaded from the state file.
	if !privKeyOk && !nodeIDOk && !seedOk {
		if err := jsonServerStateFromFile(stateDir, &js); err != nil {
			return nil, err
		}
	} else if !privKeyOk {
		return nil, fmt.Errorf("missing argument '%s'", privateKeyArg)
	} else if !nodeIDOk {
		return nil, fmt.Errorf("missing argument '%s'", nodeIDArg)
	} else if !seedOk {
		return nil, fmt.Errorf("missing argument '%s'", seedArg)
	}

	// The IAT mode should be independently configurable.
	if iatOk {
		// If the IAT mode is specified, attempt to parse and apply it
		// as an override.
		iatMode, err := strconv.Atoi(iatStr)
		if err != nil {
			return nil, fmt.Errorf("malformed iat-mode '%s'", iatStr)
		}
		js.IATMode = iatMode
	}

	return serverStateFromJSONServerState(stateDir, &js)
}

func serverStateFromJSONServerState(stateDir string, js *jsonServerState) (*pq_obfsServerState, error) {
	var err error

	st := new(pq_obfsServerState)
	if st.nodeID, err = drivelcrypto.NodeIDFromHex(js.NodeID); err != nil {
		return nil, err
	}
	if st.identityKey, err = okem.KeypairFromHex(js.PrivateKey, js.PublicKey); err != nil {
		return nil, err
	}
	if st.drbgSeed, err = drbg.SeedFromHex(js.DrbgSeed); err != nil {
		return nil, err
	}
	if js.IATMode < iatNone || js.IATMode > iatParanoid {
		return nil, fmt.Errorf("invalid iat-mode '%d'", js.IATMode)
	}
	st.iatMode = js.IATMode
	st.cert = serverCertFromState(st)

	// Generate a human readable summary of the configured endpoint.
	if err = newBridgeFile(stateDir, st); err != nil {
		return nil, err
	}

	// Write back the possibly updated server state.
	return st, writeJSONServerState(stateDir, js)
}

func jsonServerStateFromFile(stateDir string, js *jsonServerState) error {
	fPath := path.Join(stateDir, stateFile)
	f, err := ioutil.ReadFile(fPath)
	if err != nil {
		if os.IsNotExist(err) {
			if err = newJSONServerState(stateDir, js); err == nil {
				return nil
			}
		}
		return err
	}

	if err := json.Unmarshal(f, js); err != nil {
		return fmt.Errorf("failed to load statefile '%s': %s", fPath, err)
	}

	return nil
}

func newJSONServerState(stateDir string, js *jsonServerState) (err error) {
	// Generate everything a server needs, using the cryptographic PRNG.
	// TODO this generates the initial identity!
	var st pq_obfsServerState
	rawID := make([]byte, drivelcrypto.NodeIDLength)
	if err = csrand.Bytes(rawID); err != nil {
		return
	}
	if st.nodeID, err = drivelcrypto.NewNodeID(rawID); err != nil {
		return
	}
	if st.identityKey, err = okem.NewKeypair(); err != nil {
		return
	}
	if st.drbgSeed, err = drbg.NewSeed(); err != nil {
		return
	}
	st.iatMode = iatNone

	// Encode it into JSON format and write the state file.
	js.NodeID = st.nodeID.Hex()
	js.PrivateKey = st.identityKey.Private().Hex()
	js.PublicKey = st.identityKey.Public().Hex()
	js.DrbgSeed = st.drbgSeed.Hex()
	js.IATMode = st.iatMode

	return writeJSONServerState(stateDir, js)
}

func writeJSONServerState(stateDir string, js *jsonServerState) error {
	var err error
	var encoded []byte
	if encoded, err = json.Marshal(js); err != nil {
		return err
	}
	if err = ioutil.WriteFile(path.Join(stateDir, stateFile), encoded, 0600); err != nil {
		return err
	}

	return nil
}

func newBridgeFile(stateDir string, st *pq_obfsServerState) error {
	const prefix = "# pq_obfs torrc client bridge line\n" +
		"#\n" +
		"# This file is an automatically generated bridge line based on\n" +
		"# the current lyrebird configuration.  EDITING IT WILL HAVE NO\n" +
		"# EFFECT.\n" +
		"#\n" +
		"# Before distributing this Bridge, edit the placeholder fields\n" +
		"# to contain the actual values:\n" +
		"#  <IP ADDRESS>  - The public IP address of your pq_obfs bridge.\n" +
		"#  <PORT>        - The TCP/IP port of your pq_obfs bridge.\n" +
		"#  <FINGERPRINT> - The bridge's fingerprint.\n\n"

	bridgeLine := fmt.Sprintf("Bridge pq_obfs <IP ADDRESS>:<PORT> <FINGERPRINT> %s\n",
		st.clientString())

	tmp := []byte(prefix + bridgeLine)
	if err := ioutil.WriteFile(path.Join(stateDir, bridgeFile), tmp, 0600); err != nil {
		return err
	}

	return nil
}
