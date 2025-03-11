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

package drivelcrypto

import (
	"bytes"
	"testing"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptodata"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/okems"
)

const (
	maxOkmLen = 256
)

// Test Client/Server handshake.
func TestHandshake(t *testing.T) {
	csrand.Rand.Seed(1234)

	var pseudorandomKey = make([]byte, 32)
	var info = make([]byte, 16)

	csrand.Bytes(pseudorandomKey)
	csrand.Bytes(info)

	// KdfExpand
	for okmLen := 1; okmLen < maxOkmLen; okmLen++ {
		okm := KdfExpand(pseudorandomKey, info, okmLen)
		if okm == nil {
			t.Fatal("Failed to expand using KDF: output is nil")
		}
		if len(okm) != okmLen {
			t.Fatal("Failed to expand using KDF: wrong output length")
		}
	}

	// PrfCombine
	var input1 = make([]byte, 32)
	var input2 = make([]byte, 32)

	csrand.Bytes(input1)
	csrand.Bytes(input2)

	okm := PrfCombine(input1, input2)
	if okm == nil {
		t.Fatal("Failed to combine using PRF: output is nil")
	}
	if len(okm) != KdfOutLength {
		t.Fatal("Failed to combine using PRF: wrong output length")
	}

	// XorEncryptDecrypt
	var msg = make([]byte, 32)

	csrand.Bytes(msg)

	encMsg := XorEncryptDecrypt(pseudorandomKey, msg)
	if encMsg == nil {
		t.Fatal("Failed to do symmetric encryption: output is nil")
	}
	if len(encMsg) != len(msg) {
		t.Fatal("Failed to do symmetric encryption: wrong output length")
	}

	msg2 := XorEncryptDecrypt(pseudorandomKey, encMsg)
	if encMsg == nil {
		t.Fatal("Failed to do symmetric decryption: output is nil")
	}
	if len(encMsg) != len(msg2) {
		t.Fatal("Failed to do symmetric decryption: wrong output length")
	}
	if 0 != bytes.Compare(msg, msg2) {
		t.Fatal("Failed to do symmetric decryption: message mismatch after decryption")
	}

	// MessageMark
	markClient := MessageMark(pseudorandomKey, true, msg)
	if markClient == nil {
		t.Fatal("Failed to make client mark: output is nil")
	}
	if len(markClient) != KdfOutLength {
		t.Fatal("Failed to make client mark: wrong output length")
	}
	markServer := MessageMark(pseudorandomKey, false, msg)
	if markServer == nil {
		t.Fatal("Failed to make server mark: output is nil")
	}
	if len(markServer) != KdfOutLength {
		t.Fatal("Failed to make server mark: wrong output length")
	}
	if 0 == bytes.Compare(msg, msg2) {
		t.Fatal("Failed to make marks: marks match between client/server")
	}

	// MessageMAC
	epoch := int64(csrand.IntRange(1, (2300-1970)*365*24))
	macClient := MessageMAC(pseudorandomKey, true, msg, epoch)
	if macClient == nil {
		t.Fatal("Failed to make client mac: output is nil")
	}
	if len(macClient) != KdfOutLength {
		t.Fatal("Failed to make client mac: wrong output length")
	}
	macServer := MessageMAC(pseudorandomKey, false, msg, epoch)
	if macServer == nil {
		t.Fatal("Failed to make server mac: output is nil")
	}
	if len(macServer) != KdfOutLength {
		t.Fatal("Failed to make server mac: wrong output length")
	}
	if 0 == bytes.Compare(msg, msg2) {
		t.Fatal("Failed to make macs: macs match between client/server")
	}

	// DrivelCommon
	var input3 = make([]byte, 45)
	var input4 = make([]byte, 560)
	var input5 = make([]byte, 1200)

	cdSS, err := cryptodata.New(input1, len(input1))
	if err != nil {
		t.Fatal("DrivelCommon could not mock KEM Shared Secret")
	}
	cdPK, err := cryptodata.New(input2, len(input2))
	if err != nil {
		t.Fatal("DrivelCommon could not mock OKEM Public Key")
	}
	cdOCT, err := cryptodata.New(input3, len(input3))
	if err != nil {
		t.Fatal("DrivelCommon could not mock OKEM Ciphertext")
	}
	cdPK2, err := cryptodata.New(input4, len(input4))
	if err != nil {
		t.Fatal("DrivelCommon could not mock KEM Public Key")
	}
	cdCT, err := cryptodata.New(input5, len(input5))
	if err != nil {
		t.Fatal("DrivelCommon could not mock KEM Ciphertext")
	}
	sharedKemSecret := kems.SharedSecret(cdSS)
	serverOkemPublicKey := okems.PublicKey(cdPK)
	okemCiphertext := okems.ObfuscatedCiphertext(cdOCT)
	clientKemPublicKey := kems.PublicKey(cdPK2)
	kemCiphertext := kems.Ciphertext(cdCT)

	serverSeed, serverAuth := DrivelCommon(pseudorandomKey, sharedKemSecret, serverOkemPublicKey, okemCiphertext, clientKemPublicKey, kemCiphertext)
	if serverSeed == nil {
		t.Fatal("DrivelCommon returned nil KEY_SEED")
	}
	if serverAuth == nil {
		t.Fatal("DrivelCommon returned nil AUTH")
	}
}
