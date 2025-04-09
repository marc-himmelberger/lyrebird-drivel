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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/drbg"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/okems"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/drivel/drivelcrypto"
)

const (
	stateFile     = "drivel_state.json"
	bridgeFile    = "drivel_bridgeline.txt"
	keyFileFormat = "key-%s.pub.json"
)

type jsonPublicKey struct {
	OkemName  string `json:"okem"`
	NodeID    string `json:"node-id"`
	PublicKey string `json:"public-key"`
}

type jsonServerState struct {
	KemName    string `json:"kem"`
	OkemName   string `json:"okem"`
	NodeID     string `json:"node-id"`
	PrivateKey string `json:"private-key"`
	PublicKey  string `json:"public-key"`
	DrbgSeed   string `json:"drbg-seed"`
	IATMode    int    `json:"iat-mode"`
}

type drivelServerState struct {
	nodeID      *drivelcrypto.NodeID
	identityKey *okems.Keypair
	drbgSeed    *drbg.Seed
	iatMode     int
}

func (st *drivelServerState) clientString() string {
	return fmt.Sprintf("%s=%s %s=%d", nodeIDArg, st.nodeID.Hex(), iatArg, st.iatMode)
}

func serverStateFromArgs(stateDir string, args *pt.Args, okem okems.ObfuscatedKem) (*drivelServerState, error) {
	var js jsonServerState
	var nodeIDOk, privKeyOk, seedOk bool

	// HACK: Should be loaded from args, but that would still require hardcoding them for the client
	// our only goal is to check that the file content is consistent
	js.KemName = kemScheme.Name()
	js.OkemName = okemScheme.Name()
	js.NodeID, nodeIDOk = args.Get(nodeIDArg)
	js.PrivateKey, privKeyOk = args.Get(privateKeyArg)
	js.DrbgSeed, seedOk = args.Get(seedArg)
	iatStr, iatOk := args.Get(iatArg)

	// Either a private key, node id, and seed are ALL specified, or
	// they should be loaded from the state file.
	if !privKeyOk && !nodeIDOk && !seedOk {
		if err := jsonServerStateFromFile(stateDir, &js, okem); err != nil {
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

	return serverStateFromJSONServerState(stateDir, &js, okem)
}

func serverStateFromJSONServerState(stateDir string, js *jsonServerState, okem okems.ObfuscatedKem) (*drivelServerState, error) {
	var err error

	st := new(drivelServerState)
	if js.KemName != kemScheme.Name() {
		return nil, fmt.Errorf("invalid kemName '%s', should be '%s'", js.KemName, kemScheme.Name())
	}
	if js.OkemName != okemScheme.Name() {
		return nil, fmt.Errorf("invalid okemName '%s', should be '%s'", js.OkemName, okemScheme.Name())
	}
	if st.nodeID, err = drivelcrypto.NodeIDFromHex(js.NodeID); err != nil {
		return nil, err
	}
	if st.identityKey, err = okems.KeypairFromHex(okem, js.PrivateKey, js.PublicKey); err != nil {
		return nil, err
	}
	if st.drbgSeed, err = drbg.SeedFromHex(js.DrbgSeed); err != nil {
		return nil, err
	}
	if js.IATMode < iatNone || js.IATMode > iatParanoid {
		return nil, fmt.Errorf("invalid iat-mode '%d'", js.IATMode)
	}
	st.iatMode = js.IATMode

	// Generate a human readable summary of the configured endpoint.
	if err = newBridgeFile(stateDir, st); err != nil {
		return nil, err
	}

	// Write back the possibly updated server state.
	return st, writeJSONServerState(stateDir, js)
}

func jsonServerStateFromFile(stateDir string, js *jsonServerState, okem okems.ObfuscatedKem) error {
	fPath := path.Join(stateDir, stateFile)
	f, err := ioutil.ReadFile(fPath)
	if err != nil {
		if os.IsNotExist(err) {
			if err = newJSONServerState(stateDir, js, okem); err == nil {
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

func publicKeyFileNameFromNodeIdHex(nodeIdHex string) string {
	return fmt.Sprintf(keyFileFormat, nodeIdHex[:16])
}

func publicKeyStrFromFile(stateDir string, nodeID *drivelcrypto.NodeID) (string, error) {
	fPath := path.Join(stateDir, publicKeyFileNameFromNodeIdHex(nodeID.Hex()))
	f, err := ioutil.ReadFile(fPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("cannot find required public key file '%s': %s", fPath, err)
		}
		return "", err
	}

	js := new(jsonPublicKey)

	if err := json.Unmarshal(f, js); err != nil {
		return "", fmt.Errorf("failed to load keyfile '%s': %s", fPath, err)
	}

	if js.NodeID != nodeID.Hex() {
		return "", fmt.Errorf("failed to load keyfile '%s': invalid nodeID '%s', should be '%s'", fPath, js.NodeID, nodeID.Hex())
	}
	if js.OkemName != okemScheme.Name() {
		return "", fmt.Errorf("failed to load keyfile '%s': invalid okemName '%s', should be '%s'", fPath, js.OkemName, okemScheme.Name())
	}

	return js.PublicKey, nil
}

func newJSONServerState(stateDir string, js *jsonServerState, okem okems.ObfuscatedKem) (err error) {
	// Generate everything a server needs, using the cryptographic PRNG.
	// INFO this generates the initial identity!
	var st drivelServerState
	rawID := make([]byte, drivelcrypto.NodeIDLength)
	if err = csrand.Bytes(rawID); err != nil {
		return
	}
	if st.nodeID, err = drivelcrypto.NewNodeID(rawID); err != nil {
		return
	}
	st.identityKey = okem.KeyGen()
	if st.drbgSeed, err = drbg.NewSeed(); err != nil {
		return
	}
	st.iatMode = iatNone

	// Encode it into JSON format and write the state file.
	js.KemName = kemScheme.Name()
	js.OkemName = okemScheme.Name()
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

// Writes the bridge line to its own file every time the server starts.
// Additionally, the public key is also written to its own file for distribution.
func newBridgeFile(stateDir string, st *drivelServerState) error {
	const prefix = "# drivel torrc client bridge line\n" +
		"#\n" +
		"# This file is an automatically generated bridge line based on\n" +
		"# the current lyrebird configuration.  EDITING IT WILL HAVE NO\n" +
		"# EFFECT.\n" +
		"#\n" +
		"# Before distributing this Bridge, edit the placeholder fields\n" +
		"# to contain the actual values:\n" +
		"#  <IP ADDRESS>  - The public IP address of your drivel bridge.\n" +
		"#  <PORT>        - The TCP/IP port of your drivel bridge.\n" +
		"#  <FINGERPRINT> - The bridge's fingerprint.\n" +
		"# Also distribute the public key file key-<KEYID>.pub.json in\n" +
		"# unmodified form, where <KEYID> is the beginning of the\n" +
		"# 'node-id' value below. Clients need to put this file\n" +
		"# into which clients require.\n\n"

	bridgeLine := fmt.Sprintf("Bridge drivel <IP ADDRESS>:<PORT> <FINGERPRINT> %s\n",
		st.clientString())

	tmp := []byte(prefix + bridgeLine)
	if err := ioutil.WriteFile(path.Join(stateDir, bridgeFile), tmp, 0600); err != nil {
		return err
	}

	// Also encode public key for its own file
	jsPk := new(jsonPublicKey)

	jsPk.OkemName = okemScheme.Name()
	jsPk.NodeID = st.nodeID.Hex()
	jsPk.PublicKey = st.identityKey.Public().Hex()

	return writeJSONPublicKey(stateDir, jsPk)
}

func writeJSONPublicKey(stateDir string, js *jsonPublicKey) error {
	fPath := path.Join(stateDir, publicKeyFileNameFromNodeIdHex(js.NodeID))

	encoded, err := json.Marshal(js)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fPath, encoded, 0644)
	if err != nil {
		return err
	}

	return nil
}
