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

// Package cryptofactory collects implementations and constructions for KEMs/OKEMs
package cryptofactory // import "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory"

import (
	"slices"
	"strings"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory/encaps_encode"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory/encoding_classic_mceliece"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory/encoding_kemeleon"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory/oqs_wrapper"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/okems"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/x25519ell2"
)

// Atomic KEMs. Additional KEMs are added during [init()]
var allKemNames = []string{
	"x25519",
}

func init() {
	// Adds OQS KEMs for use in cryptofactory.
	// Import dependency guarantees that oqs_wrapper is initialized first.
	allKemNames = append(allKemNames, oqs_wrapper.OqsEnabledKEMs...)
}

// List of all supported KEM names.
func KemNames() []string {
	res := make([]string, len(allKemNames))
	copy(res, allKemNames)
	return res
}

// List of all supported KEM names.
func OkemNames() []string {
	allOkemNames := make([]string, 0, len(allKemNames))
	for _, kemName := range KemNames() {
		if slices.Contains(allEncodedKems, kemName) {
			allOkemNames = append(allOkemNames, etePrefix+kemName)
		}
	}
	return allOkemNames
}

const etePrefix = "EtE-"

// All KEMs for which encoders are available. This list must not be modified at runtime.
// New entries must be reflected in NewOkem.
var allEncodedKems = []string{
	"x25519",
	"Classic-McEliece-348864",
	"Classic-McEliece-460896",
	"Classic-McEliece-6688128",
	"Classic-McEliece-6960119",
	"Classic-McEliece-8192128",
	"ML-KEM-512",
	"ML-KEM-768",
	"ML-KEM-1024",
}

/*
Constructs a KEM scheme given a name.
Legal values for names are:
  - "x25519" for a wrapper around the corresponding obfs4 implementation without obfuscation,
    but suitable for elligator2 encoding provided via [okems.NewOkem] as "EtE-x25519"
  - Any valid name for a KEM enabled in the open-quantum-safe library.
    These can be viewed via KemNames().
*/
func NewKem(kemName string) kems.KeyEncapsulationMechanism {
	if kemName == "x25519" {
		return &x25519ell2.X25519KEM{}
	} else if slices.Contains(oqs_wrapper.OqsEnabledKEMs, kemName) {
		return oqs_wrapper.NewOqsWrapper(kemName)
	} else {
		panic("cryptofactory: no KEM found for name: " + kemName)
	}
}

/*
Constructs an OKEM scheme given a name.
Legal values for names are:
  - "EtE-<kem_name>" if "<kem_name>" is a valid name for
    [kems.NewKem], and a corresponding [EncapsThenEncode] is implemented.

Possible names for future additions:
  - "OEINC[<okem1>,<okem2>]" if "<okem1>" and "<okem2>" are both
    valid names for [okems.NewOkem]
*/
func NewOkem(okemName string) okems.ObfuscatedKem {
	if strings.HasPrefix(okemName, etePrefix) {
		// "EtE-<kem_name>" if "<kem_name>" is a valid name for [kems.NewKem]
		// Construct KEM
		kemName := okemName[len(etePrefix):]
		if !slices.Contains(allEncodedKems, kemName) {
			panic("cryptofactory: no encoding mapped for KEM " + kemName)
		}
		kem := NewKem(kemName)
		// Select encoder
		var encoder encaps_encode.EncapsThenEncode
		switch kemName {
		case "x25519":
			encoder = &x25519ell2.Elligator2Encoder{}
		case "Classic-McEliece-348864",
			"Classic-McEliece-460896",
			"Classic-McEliece-6688128",
			"Classic-McEliece-8192128":
			encoder = nil
		case "Classic-McEliece-6960119":
			encoder = &encoding_classic_mceliece.ClassicMcEliecePadder{}
		case "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024":
			encoder = &encoding_kemeleon.KemeleonEncoder{}
		default:
			panic("cryptofactory: contradictory 'allEncodedKems' and switch-case " + kemName)
		}
		// Initialize and Combine
		if encoder != nil {
			encoder.Init(kem)
		}
		return encaps_encode.NewEncapsThenEncodeOKEM(kem, encoder)
	} else if strings.HasPrefix(okemName, "OEINC[") && strings.HasSuffix(okemName, "]") {
		panic("cryptofactory: OEINC not yet implemented")

		// // "OEINC[<okem1>,<okem2>]" if "<okem1>" and "<okem2>" are both valid names for [okems.NewOkem]
		// // Extract names
		// componentNames := okemName[6 : len(okemName)-1]
		// components := strings.Split(componentNames, ",")
		// if len(components) != 2 {
		// 	  panic("okem: invalid number of OEINC component OKEMs: " + okemName)
		// }
		// okemName1 := components[0]
		// okemName2 := components[1]
		// // Construct OKEMs
		// okem1 := NewOkem(okemName1)
		// okem2 := NewOkem(okemName2)
		// // Combine
		// return NewOEINC(okem1, okem2) --> new struct analogous to encaps_encode.go
	} else {
		panic("cryptofactory: no OKEM construction found for name: " + okemName)
	}
}
