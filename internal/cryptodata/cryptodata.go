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

// Package cryptodata provides basic data types around byte slices which allow
// length assertions and conversions using simple interfaces.
// Implementation leans heavily on parts of
// gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor/ntor.go

package cryptodata // import "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptodata"

import (
	"encoding/hex"
	"fmt"
)

// CryptoDataLengthError is the error returned when the crpyo data
// being used for an operation is of the wrong size.
type CryptoDataLengthError int

func (e CryptoDataLengthError) Error() string {
	return fmt.Sprintf("cryptodata: Invalid crypto data length: %d", int(e))
}

type CryptoData []byte

// AssertSize checks if the data exactly matches a given length
func (data CryptoData) AssertSize(numBytes int) error {
	if len(data) != numBytes {
		return CryptoDataLengthError(len(data))
	} else {
		return nil
	}
}

// Bytes returns a slice to the raw data.
func (data CryptoData) Bytes() []byte {
	return data
}

// Hex returns the hexdecimal representation of the data.
func (data CryptoData) Hex() string {
	return hex.EncodeToString(data.Bytes())
}

// New creates a CryptoData from the raw bytes.
func New(raw []byte, expectedSize int) (CryptoData, error) {
	data := (CryptoData)(make([]byte, len(raw)))
	copy(data, raw)

	err := data.AssertSize(expectedSize)

	return data, err
}

// NewFromHex returns a  CryptoData from the hexdecimal representation.
func NewFromHex(encoded string, expectedSize int) (CryptoData, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return New(raw, expectedSize)
}
