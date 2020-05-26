package secp256k1

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratorParseAndSerialize(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/generator.json")
	if err != nil {
		t.Fatal(err)
	}

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["parseAndSerialize"].([]interface{})

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		gen, err := GeneratorFromString(v["generator"].(string))
		assert.NoError(t, err)
		assert.NotNil(t, gen)
		assert.Equal(
			t,
			v["generator"].(string),
			gen.String(),
			"",
		)
	}
}

func TestGeneratorGenerateBlinded(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/generator.json")
	if err != nil {
		t.Fatal(err)
	}

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["generateBlinded"].([]interface{})

	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		seed, _ := hex.DecodeString(v["seed"].(string))
		blind, _ := hex.DecodeString(v["blind"].(string))
		gen, err := GeneratorGenerateBlinded(ctx, seed, blind)
		assert.NoError(t, err)
		assert.NotNil(t, gen)
		assert.Equal(t, v["expected"].(string), gen.String(), "")
	}
}

func TestGeneratorGenerate(t *testing.T) {
	ctxNone, _ := ContextCreate(ContextNone)
	defer ContextDestroy(ctxNone)
	ctxSign, _ := ContextCreate(ContextSign)
	defer ContextDestroy(ctxSign)
	ctxVerify, _ := ContextCreate(ContextVerify)
	defer ContextDestroy(ctxVerify)
	ctxBoth, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctxBoth)

	var key [32]byte
	_, err := rand.Read(key[:])
	assert.NoError(t, err)

	genNone, err := GeneratorGenerate(ctxNone, key[:])
	assert.NoError(t, err)
	assert.NotNil(t, genNone)
	assert.IsType(t, Generator{}, *genNone)

	genSign, err := GeneratorGenerate(ctxSign, key[:])
	assert.NoError(t, err)
	assert.NotNil(t, genSign)
	assert.IsType(t, Generator{}, *genSign)

	genVerify, err := GeneratorGenerate(ctxVerify, key[:])
	assert.NoError(t, err)
	assert.NotNil(t, genVerify)
	assert.IsType(t, Generator{}, *genVerify)

	genBoth, err := GeneratorGenerate(ctxBoth, key[:])
	assert.NoError(t, err)
	assert.NotNil(t, genBoth)
	assert.IsType(t, Generator{}, *genBoth)
}
