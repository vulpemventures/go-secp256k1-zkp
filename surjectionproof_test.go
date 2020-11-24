package secp256k1

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSurjectionProofInitializeAndSerialize(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/surjectionproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["initializeAndSerialize"].([]interface{})

	ctx, _ := ContextCreate(ContextNone)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		seed, _ := hex.DecodeString(v["seed"].(string))
		nInputTagsToUse := int(v["inputTagsToUse"].(float64))
		nMaxIterations := int(v["maxIterations"].(float64))
		fixedOutputTag, err := FixedAssetTagFromHex(v["outputTag"].(string))
		assert.NoError(t, err)
		fixedInputTags := []*FixedAssetTag{}
		for _, inTag := range v["inputTags"].([]interface{}) {
			fixedAssetTag, err := FixedAssetTagFromHex(inTag.(string))
			assert.NoError(t, err)
			fixedInputTags = append(fixedInputTags, fixedAssetTag)
		}

		proof, inputIndex, err := SurjectionProofInitialize(
			ctx,
			fixedInputTags,
			nInputTagsToUse,
			fixedOutputTag,
			nMaxIterations,
			seed,
		)
		assert.NoError(t, err)
		expected := v["expected"].(map[string]interface{})
		assert.Equal(t, int(expected["inputIndex"].(float64)), inputIndex)
		assert.Equal(t, expected["proof"].(string), proof.String())
		assert.Equal(t, int(expected["nInputs"].(float64)), SurjectionProofNTotalInputs(ctx, proof))
		assert.Equal(t, int(expected["nUsedInputs"].(float64)), SurjectionProofNUsedInputs(ctx, proof))
	}
}

func TestSurjectionProofGenerateAndVerify(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/surjectionproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["generateAndVerify"].([]interface{})

	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		inIndex := int(v["inputIndex"].(float64))
		inBlindingKey, _ := hex.DecodeString(v["inputBlindingKey"].(string))
		outBlindingKey, _ := hex.DecodeString(v["outputBlindingKey"].(string))
		proof, err := SurjectionProofFromString(v["proof"].(string))
		assert.NoError(t, err)
		ephemeralOutTag, err := GeneratorFromString(v["ephemeralOutputTag"].(string))
		assert.NoError(t, err)
		ephemeralInTags := []*Generator{}
		for _, inTag := range v["ephemeralInputTags"].([]interface{}) {
			ephemeralInTag, err := GeneratorFromString(inTag.(string))
			assert.NoError(t, err)
			ephemeralInTags = append(ephemeralInTags, ephemeralInTag)
		}

		err = SurjectionProofGenerate(
			ctx,
			proof,
			ephemeralInTags,
			ephemeralOutTag,
			inIndex,
			inBlindingKey,
			outBlindingKey,
		)
		assert.NoError(t, err)
		assert.NotNil(t, proof)
		assert.Equal(t, v["expected"].(string), proof.String())
		assert.Equal(t, true, SurjectionProofVerify(ctx, proof, ephemeralInTags, ephemeralOutTag))
	}
}
