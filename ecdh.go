package secp256k1

/*
#include "include/secp256k1_ecdh.h"
#cgo CFLAGS: -I${SRCDIR}/secp256k1-zkp -I${SRCDIR}/secp256k1-zkp/src
inline secp256k1_pubkey** makePubkeyArray(int size) { return calloc(sizeof(secp256k1_pubkey*), size); }
inline void setArrayPubkey(secp256k1_pubkey **a, secp256k1_pubkey *pubkey, int n) { a[n] = pubkey; }
inline void freePubkeyArray(secp256k1_pubkey * *a) { free(a); }
*/
import "C"

import (
	"errors"
	"unsafe"
)

const (
	// Flags for EcPubkeySerialize
	EcCompressed   = uint(C.SECP256K1_EC_COMPRESSED)
	EcUncompressed = uint(C.SECP256K1_EC_UNCOMPRESSED)

	// Length of elements byte representations
	LenPrivateKey   int = 32
	LenCompressed   int = 33
	LenUncompressed int = 65

	ErrorPrivateKeySize     string = "private key must be exactly 32 bytes"
	ErrorEcdh               string = "unable to do ecdh"
	ErrorPublicKeyCreate    string = "unable to produce public key"
	ErrorPublicKeySize      string = "public key must be 33 or 65 bytes"
	ErrorPublicKeyParse     string = "unable to parse this public key"
	ErrorTweakingPublicKey  string = "unable to tweak this public key"
	ErrorTweakSize          string = "tweak must be exactly 32 bytes"
	ErrorPublicKeyCombine   string = "unable to combine public key"
	ErrorTweakingPrivateKey string = "unable to tweak this private key"
)

// PublicKey wraps a *secp256k1_pubkey, which contains the prefix plus
// the X+Y coordidnates
type PublicKey struct {
	pk *C.secp256k1_pubkey
}

// EcPubkeyCreate will compute the public key for a secret key. The
// return code is 1 and the key returned if the secret was valid.
// Otherwise, the return code is 0, and an error is returned. The key
// length must be 32-bytes.
func EcPubkeyCreate(ctx *Context, seckey []byte) (int, *PublicKey, error) {
	if len(seckey) != LenPrivateKey {
		return 0, nil, errors.New(ErrorPrivateKeySize)
	}

	pk := newPublicKey()
	result := int(C.secp256k1_ec_pubkey_create(ctx.ctx, pk.pk, cBuf(seckey[:])))
	if result != 1 {
		return result, nil, errors.New(ErrorPublicKeyCreate)
	}
	return result, pk, nil
}

func newPublicKey() *PublicKey {
	return &PublicKey{
		pk: &C.secp256k1_pubkey{},
	}
}

// EcPubkeyParse deserializes a variable-length public key into a *Pubkey
// object. The function will reject any input of zero bytes in length.
// This function supports parsing compressed (33 bytes, header byte 0x02 or
// 0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes,
// header byte 0x06 or 0x07) format public keys. The return code is 1 if
// the public key was fully valid, or 0 if the public key was invalid or
// could not be parsed.
func EcPubkeyParse(ctx *Context, publicKey []byte) (int, *PublicKey, error) {
	l := len(publicKey)
	if l < 1 {
		return 0, nil, errors.New(ErrorPublicKeySize)
	}

	pk := newPublicKey()
	result := int(C.secp256k1_ec_pubkey_parse(ctx.ctx, pk.pk, cBuf(publicKey), C.size_t(l)))
	if result != 1 {
		return result, nil, errors.New(ErrorPublicKeyParse)
	}
	return result, pk, nil
}

// EcPubkeySerialize serializes a pubkey object into a []byte. The output
// is an array of 65-bytes (if compressed==0), or 33-bytes (if compressed==1).
// Use EcCompressed or EcUncompressed to request a certain format. The
// function will always return 1, because the only
// public key objects are valid ones.
func EcPubkeySerialize(ctx *Context, publicKey *PublicKey, flags uint) (int, []byte, error) {
	var size int
	if flags == EcCompressed {
		size = LenCompressed
	} else {
		size = LenUncompressed
	}

	output := make([]C.uchar, size)
	outputLen := C.size_t(size)
	result := int(C.secp256k1_ec_pubkey_serialize(ctx.ctx, &output[0], &outputLen, publicKey.pk, C.uint(flags)))
	return result, goBytes(output, C.int(outputLen)), nil
}

// Compute an EC Diffie-Hellman secret in constant time. Return code is
// 1 if exponentiation was successful, or 0 if the scalar was invalid.
func Ecdh(ctx *Context, pubKey *PublicKey, privKey []byte) (int, []byte, error) {
	if len(privKey) != LenPrivateKey {
		return 0, []byte{}, errors.New(ErrorPrivateKeySize)
	}
	secret := make([]byte, LenPrivateKey)
	result := int(C.secp256k1_ecdh(ctx.ctx, cBuf(secret[:]), pubKey.pk, cBuf(privKey[:]), nil, nil))
	if result != 1 {
		return result, []byte{}, errors.New(ErrorEcdh)
	}
	return result, secret, nil
}

// Tweak a public key by adding tweak times the generator to it. The
// return code is 0 if the tweak was out of range (chance of around 1 in
// 2^128 for uniformly random 32-byte arrays) or if the resulting public
// key would be invalid. The return code is 1 otherwise.
func EcPubKeyTweakAdd(ctx *Context, pk *PublicKey, tweak []byte) (int, error) {
	if len(tweak) != LenPrivateKey {
		return 0, errors.New(ErrorTweakSize)
	}

	result := int(C.secp256k1_ec_pubkey_tweak_add(ctx.ctx, pk.pk, cBuf(tweak)))
	if result != 1 {
		return result, errors.New(ErrorTweakingPublicKey)
	}
	return result, nil
}

// EcPrivKeyTweakAdd modifies the provided `seckey` by adding tweak to
// it. The return code is 0 if `tweak` was out of range (chance of
// around 1 in 2^128 for uniformly random 32-byte arrays), or if the
// resulting private key would be invalid (only when the tweak is the
// complement of the private key). The return code is 1 otherwise.
func EcPrivKeyTweakAdd(ctx *Context, seckey []byte, tweak []byte) (int, error) {
	if len(tweak) != LenPrivateKey {
		return 0, errors.New(ErrorTweakSize)
	}
	if len(seckey) != LenPrivateKey {
		return 0, errors.New(ErrorPrivateKeySize)
	}

	result := int(C.secp256k1_ec_privkey_tweak_add(ctx.ctx, (*C.uchar)(unsafe.Pointer(&seckey[0])), cBuf(tweak[:])))
	if result != 1 {
		return result, errors.New(ErrorTweakingPrivateKey)
	}
	return result, nil
}

// EcPubKeyNegate will negate a public key object in place. The return code
// is always 1.
func EcPubKeyNegate(ctx *Context, pubkey *PublicKey) (int, error) {
	result := int(C.secp256k1_ec_pubkey_negate(ctx.ctx, pubkey.pk))
	return result, nil
}

// EcPrivKeyNegate will negate a public key in place. The return code is
// 1 if the operation was successful, or 0 if the length was invalid.
func EcPrivKeyNegate(ctx *Context, seckey []byte) (int, error) {
	if len(seckey) != LenPrivateKey {
		return 0, errors.New(ErrorPrivateKeySize)
	}

	result := int(C.secp256k1_ec_privkey_negate(ctx.ctx, (*C.uchar)(unsafe.Pointer(&seckey[0]))))
	return result, nil
}

// EcPubKeyCombine will compute sum of all the provided public keys,
// returning a new point. The error code is 1 if the sum is valid, 0
// otherwise. There must be at least one public key.
func EcPubKeyCombine(ctx *Context, vPk []*PublicKey) (int, *PublicKey, error) {
	l := len(vPk)
	if l < 1 {
		return 0, nil, errors.New("must provide at least one public key")
	}

	array := C.makePubkeyArray(C.int(l))
	for i := 0; i < l; i++ {
		C.setArrayPubkey(array, vPk[i].pk, C.int(i))
	}

	defer C.freePubkeyArray(array)

	pkOut := newPublicKey()
	result := int(C.secp256k1_ec_pubkey_combine(ctx.ctx, pkOut.pk, array, C.size_t(l)))
	if result != 1 {
		return result, nil, errors.New(ErrorPublicKeyCombine)
	}
	return result, pkOut, nil
}
