package secp256k1_test

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-secp256k1-zkp"
)

func TestEcdh(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		t.Error(err)
	}
	file, err := ioutil.ReadFile("testdata/ecdh.json")
	if err != nil {
		t.Fatal(err)
	}

	var tests map[string]interface{}
	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Error(err)
	}

	vectors := tests["ecdh"].([]interface{})

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		privKey := v["privKey"].(string)
		pubKey := v["pubkey"].(string)
		expected := v["expected"].(string)

		alicePrivateKeyBytes, err := hex.DecodeString(privKey)
		if err != nil {
			t.Error(err)
		}

		bobPubKeyBytes, err := hex.DecodeString(pubKey)
		if err != nil {
			t.Error(err)
		}

		_, bobPubKey, err := secp256k1.EcPubkeyParse(ctx, bobPubKeyBytes)
		if err != nil {
			t.Error(err)
		}
		_, secKey, err := secp256k1.Ecdh(ctx, bobPubKey, alicePrivateKeyBytes)

		assert.Equal(t, expected, hex.EncodeToString(secKey))
		assert.NoError(t, err)
	}

}

func TestPubKeyTweakAddFixtures(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	file, err := ioutil.ReadFile("testdata/pubkey_tweak_add_vectors.json")
	if err != nil {
		t.Fatal(err)
	}

	var tests map[string]interface{}
	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Error(err)
	}

	vectors := tests["tweak_add"].([]interface{})

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		pubKeyBytes, err := hex.DecodeString(v["publicKey"].(string))
		if err != nil {
			t.Error(err)
		}
		_, pubKey, err := secp256k1.EcPubkeyParse(ctx, pubKeyBytes)
		if err != nil {
			t.Error(err)
		}

		tweakBytes, err := hex.DecodeString(v["tweak"].(string))
		if err != nil {
			t.Error(err)
		}

		r, err := secp256k1.EcPubKeyTweakAdd(ctx, pubKey, tweakBytes)
		spOK(t, r, err)

		r, serialized, err := secp256k1.EcPubkeySerialize(ctx, pubKey, secp256k1.EcUncompressed)
		spOK(t, r, err)

		tweakedBytes, err := hex.DecodeString(v["tweaked"].(string))
		if err != nil {
			panic(err)
		}

		assert.Equal(t, tweakedBytes, serialized)
	}
}

func TestPubKeyCombine(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	privkey := []byte(`abcd1234abcd1234abcd1234abcd1234`)

	// privkey * G
	r, pubkey, err := secp256k1.EcPubkeyCreate(ctx, privkey)
	spOK(t, r, err)

	// tweak * G
	tweak := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1}
	r, tweakPub, err := secp256k1.EcPubkeyCreate(ctx, tweak)
	spOK(t, r, err)

	// tweakedPriv: privkey + tweak
	// tweakedToPoint: (privkey+tweak) * G
	tweakedPriv := privkey
	r, err = secp256k1.EcPrivKeyTweakAdd(ctx, tweakedPriv, tweak)
	spOK(t, r, err)
	r, tweakedToPoint, err := secp256k1.EcPubkeyCreate(ctx, tweakedPriv)
	spOK(t, r, err)

	vPoint := []*secp256k1.PublicKey{pubkey, tweakPub}
	r, combinedPoint, err := secp256k1.EcPubKeyCombine(ctx, vPoint)
	spOK(t, r, err)

	assert.Equal(t, tweakedToPoint, combinedPoint)
}

func TestPubKeyNegate(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	privkey := []byte(`abcd1234abcd1234abcd1234abcd1234`)

	// (-1*k)*G == -1*(k*G)
	privkeyCopy := []byte(`abcd1234abcd1234abcd1234abcd1234`)
	r, err := secp256k1.EcPrivKeyNegate(ctx, privkeyCopy)
	spOK(t, r, err)
	r, LHS, err := secp256k1.EcPubkeyCreate(ctx, privkeyCopy)
	spOK(t, r, err)

	r, rhs, err := secp256k1.EcPubkeyCreate(ctx, privkey)
	spOK(t, r, err)
	r, err = secp256k1.EcPubKeyNegate(ctx, rhs)
	assert.Equal(t, 1, r)
	assert.NoError(t, err)

	assert.Equal(t, LHS, rhs)

}

func spOK(t *testing.T, result interface{}, err error) {
	assert.NoError(t, err)
	switch result := result.(type) {
	case int:
		assert.Equal(t, 1, result)
	case bool:
		assert.True(t, result)
	}
}
