package secp256k1_test

import (
	"encoding/hex"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
	"vulpemventures/go-secp256k1-zkp"
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
