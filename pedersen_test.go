package secp256k1

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPedersenCommitmentParseAndSerialize(t *testing.T) {
	test := "09c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

	com, _ := hex.DecodeString(test)
	ctx, _ := ContextCreate(ContextNone)
	defer ContextDestroy(ctx)

	commit, err := CommitmentParse(ctx, com)
	assert.NoError(t, err)
	assert.NotNil(t, commit)

	commitSer, err := CommitmentSerialize(ctx, commit)
	assert.NoError(t, err)
	res := hex.EncodeToString(commitSer[:])
	assert.Equal(
		t,
		res,
		test,
		fmt.Sprintf(
			"Got: %s, expected: %s",
			res,
			test,
		),
	)
}

func TestPedersenCommitmentCommit(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/pedersen.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["commit"].([]interface{})

	ctx, _ := ContextCreate(ContextSign)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		blindingFactor, _ := hex.DecodeString(v["blind"].(string))
		value := uint64(v["value"].(float64))
		blindingGenerator, err := GeneratorFromString(v["generator"].(string))
		if err != nil {
			t.Error(err)
		}

		commit, err := Commit(ctx, blindingFactor, value, blindingGenerator)
		assert.NoError(t, err)
		assert.NotNil(t, commit)
		assert.Equal(t, v["expected"].(string), commit.String())

	}
}

func TestPedersenBlindSum(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/pedersen.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["blindSum"].([]interface{})

	ctx, _ := ContextCreate(ContextNone)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		negativeBlinds := [][]byte{}
		for _, nb := range v["negativeBlinds"].([]interface{}) {
			blind, _ := hex.DecodeString(nb.(string))
			negativeBlinds = append(negativeBlinds, blind)
		}
		positiveBlinds := [][]byte{}
		for _, pb := range v["positiveBlinds"].([]interface{}) {
			blind, _ := hex.DecodeString(pb.(string))
			positiveBlinds = append(positiveBlinds, blind)
		}

		sum, err := BlindSum(ctx, positiveBlinds, negativeBlinds)
		assert.NoError(t, err)
		assert.NotNil(t, sum)
		assert.Equal(t, v["expected"].(string), hex.EncodeToString(sum[:]))
	}
}

// func TestPedersenBlindGeneratorBlindSum(t *testing.T) {
// 	file, err := ioutil.ReadFile("testdata/pedersen.json")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	var tests map[string]interface{}
// 	json.Unmarshal(file, &tests)
// 	vectors := tests["blindGeneratorBlindSum"].([]interface{})

// 	ctx, _ := ContextCreate(ContextNone)
// 	defer ContextDestroy(ctx)

// 	for _, testVector := range vectors {
// 		v := testVector.(map[string]interface{})

// 		nInputs := int(v["nInputs"].(float64))
// 		values := []uint64{}
// 		for _, val := range v["values"].([]interface{}) {
// 			values = append(values, uint64(val.(float64)))
// 		}
// 		blindGenerators := [][]byte{}
// 		for _, bg := range v["blindGenerators"].([]interface{}) {
// 			blindGen, _ := hex.DecodeString(bg.(string))
// 			blindGenerators = append(blindGenerators, blindGen)
// 		}
// 		blindFactors := [][]byte{}
// 		for _, bf := range v["blindFactors"].([]interface{}) {
// 			blindFct, _ := hex.DecodeString(bf.(string))
// 			blindFactors = append(blindFactors, blindFct)
// 		}

// 		res, err := BlindGeneratorBlindSum(ctx, values, blindGenerators, blindFactors, nInputs)
// 		assert.NoError(t, err)
// 		assert.NotNil(t, res)
// 		assert.Equal(t, v["expected"].(string), hex.EncodeToString(res[:]))
// 	}
// }
