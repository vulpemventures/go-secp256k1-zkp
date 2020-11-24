package secp256k1

/*
    #cgo CFLAGS: -I${SRCDIR}/secp256k1-zkp -I${SRCDIR}/secp256k1-zkp/src
    #include <stdlib.h>
    #include <string.h>
    #include "./secp256k1-zkp/include/secp256k1_surjectionproof.h"
    static int surjectionproofSerializationBytes(int nInputs, int nUsedInputs) { return SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(nInputs, nUsedInputs); }
    static secp256k1_fixed_asset_tag* makeFixedAssetTagsArray(int size) { return !size ? NULL : calloc(sizeof(secp256k1_fixed_asset_tag), size); }
    static int setFixedAssetTagsArray(secp256k1_fixed_asset_tag* a, secp256k1_fixed_asset_tag* v, size_t i) { if (!a || !v) return 0; memcpy((a + i)->data, v->data, sizeof(v->data)); return sizeof(v->data); }
    static void freeFixedAssetTagsArray(secp256k1_fixed_asset_tag* a) { if (a) free(a); }
    static secp256k1_generator** makeGeneratorsArray(int size) { return !size ? NULL : calloc(sizeof(secp256k1_generator*), size); }
    static void setGeneratorsArray(secp256k1_generator** a, secp256k1_generator* v, int i) { if (a) a[i] = v; }
    static void freeGeneratorsArray(secp256k1_generator** a) { if (a) free(a); }
#ifdef USE_REDUCED_SURJECTION_PROOF_SIZE
    static int useReducePSurjectionproofSize = 1;
#else
    static int useReducedSurjectionproofSize = 0;
#endif
    static int asset_from_bytes(secp256k1_fixed_asset_tag* dst, const unsigned char* src) { memcpy(&dst->data[0], &src[0], 32); return 32; }
    static int asset_to_bytes(unsigned char* dst, const secp256k1_fixed_asset_tag* src) { memcpy(&dst[0], &src->data[0], 32); return 32; }
*/
import "C"
import (
	"encoding/hex"
	"errors"
)

const (
	// SurjectionProofSerializationBytesMax is the maximum number of bytes a serialized surjection proof requires
	SurjectionProofSerializationBytesMax = C.SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX

	// ErrSurjectionProofParsing error message for proof parsing function
	ErrSurjectionProofParsing string = "surjection proof parsing failed"
	// ErrSurjectionProofGeneration error message for proof generation function
	ErrSurjectionProofGeneration string = "surjection proof generation failed"
	// ErrSurjectionProofAllocation error message for proof allocation function
	ErrSurjectionProofAllocation string = "surjection proof allocation/initialization failed"
	// ErrSurjectionProofInitialization error message for proof initilization function
	ErrSurjectionProofInitialization string = "surjection proof initialization failed"
	// ErrSurjectionProofSerialization error message for proof serialization function
	ErrSurjectionProofSerialization string = "surjection proof serialization failed"
)

// SurjectionProofSerializationBytesCalc calculates the number of bytes a
// serialized  surjection proof requires given the number of inputs and the
// number of used inputs.
func SurjectionProofSerializationBytesCalc(nInputs int, nUsedInputs int) int {
	return int(C.surjectionproofSerializationBytes(C.int(nInputs), C.int(nUsedInputs)))
}

// SurjectionProof opaque data structure that holds a parsed surjection proof
//
//  The exact representation of data inside is implementation defined and not
//  guaranteed to be portable between different platforms or versions. Nor is
//  it guaranteed to have any particular size, nor that identical proofs
//  will have identical representation. (That is, memcmp may return nonzero
//  even for identical proofs.)
//
//  To obtain these properties, instead use secp256k1_surjectionproof_parse
//  and secp256k1_surjectionproof_serialize to encode/decode proofs into a
//  well-defined format.
//
//  The representation is exposed to allow creation of these objects on the
//  stack; please *do not* use these internals directly.
type SurjectionProof struct {
	proof *C.secp256k1_surjectionproof
}

// Bytes converts a surjection proof object to a byte slice
func (proof *SurjectionProof) Bytes() (bytes []byte) {
	bytes, _ = SurjectionProofSerialize(SharedContext(ContextNone), proof)
	return
}

// String converts a surjection proof object to an hex encoded string
func (proof *SurjectionProof) String() string {
	bytes := proof.Bytes()

	return hex.EncodeToString(bytes)
}

// SurjectionProofFromString returns a surjection proof object from an hex
// encoded string
func SurjectionProofFromString(str string) (proof *SurjectionProof, err error) {
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return

	}
	proof, err = SurjectionProofParse(SharedContext(ContextNone), bytes)

	return
}

func newSurjectionProof() *SurjectionProof {
	return &SurjectionProof{
		proof: &C.secp256k1_surjectionproof{},
	}
}

// SurjectionProofParse parses a surjection proof
//   Returns: 1: when the proof could be parsed
//						0: otherwise
//   Args: 		ctx: a secp256k1 context object
//   Out:  		proof: a pointer to a proof object
//   In:   		input: a pointer to the array to parse
//        		inputlen: length of the array pointed to by input
//
//  The proof must consist of:
//    - A 2-byte little-endian total input count `n`
//    - A ceil(n/8)-byte bitmap indicating which inputs are used.
//    - A big-endian 32-byte borromean signature e0 value
//    - `m` big-endian 32-byte borromean signature s values, where `m`
//      is the number of set bits in the bitmap
func SurjectionProofParse(
	context *Context,
	bytes []byte,
) (
	proof *SurjectionProof,
	err error,
) {
	proof = newSurjectionProof()
	if 1 != C.secp256k1_surjectionproof_parse(
		context.ctx,
		proof.proof,
		cBuf(bytes),
		C.size_t(len(bytes))) {

		err = errors.New(ErrSurjectionProofParsing)
	}

	return
}

// SurjectionProofSerialize serializes a surjection proof
//   Returns: 1 if enough space was available to serialize, 0 otherwise
//   Args:    ctx: a secp256k1 context object
//   Out:     output: a pointer to an array to store the serialization
//   In/Out:  outputlen: a pointer to an integer which is initially set to the
//                       size of output, and is overwritten with the written
//                       size.
//   In:      proof: a pointer to an initialized proof object
// See secp256k1_surjectionproof_parse for details about the encoding.
func SurjectionProofSerialize(
	context *Context,
	proof *SurjectionProof,
) (
	bytes []byte,
	err error,
) {
	var data [SurjectionProofSerializationBytesMax]C.uchar
	size := C.size_t(len(data))
	if 1 != C.secp256k1_surjectionproof_serialize(
		context.ctx,
		&data[0],
		&size,
		proof.proof,
	) {

		return nil, errors.New(ErrSurjectionProofSerialization)
	}

	return goBytes(data[:], C.int(size)), nil
}

// FixedAssetTag holds a fixed asset tag.
// This data type is//not* opaque. It will always be 32 bytes of whatever
// data the API user wants to use as an asset tag. Its contents have no
// semantic meaning to libsecp whatsoever.
type FixedAssetTag struct {
	tag *C.secp256k1_fixed_asset_tag
}

func newFixedAssetTag() *FixedAssetTag {
	return &FixedAssetTag{tag: &C.secp256k1_fixed_asset_tag{}}
}

// FixedAssetTagParse parses a sequence of bytes as a FixedAssetTag
//	 Returns: 1 if input contains a valid FixedAssetTag
//   In:   		data32: pointer to a 33-byte serialized data
//   Out:  		nil/FixedAssetTag
func FixedAssetTagParse(
	data32 []byte,
) (
	*FixedAssetTag,
	error,
) {
	asset := newFixedAssetTag()
	C.asset_from_bytes(asset.tag, cBuf(data32))

	return asset, nil
}

// FixedAssetTagFromHex parses a string a a FixedAssetTag
func FixedAssetTagFromHex(str string) (com *FixedAssetTag, err error) {
	bytes, _ := hex.DecodeString(str)
	com, err = FixedAssetTagParse(bytes)

	return
}

// FixedAssetTagSerialize serializes FixedAssetTag into sequence of bytes.
//	 Returns: 1 always.
//	 In:      FixedAssetTag - fixed asset tag object
//	 Out:     serialized data: 32-byte byte array
func FixedAssetTagSerialize(
	asset *FixedAssetTag,
) (
	data [32]byte,
	err error,
) {
	C.asset_to_bytes(cBuf(data[:]), asset.tag)

	return
}

// Bytes converts a fixed asset tag object to a 32-byte array
func (asset *FixedAssetTag) Bytes() (bytes [32]byte) {
	bytes, _ = FixedAssetTagSerialize(asset)
	return
}

// Slice converts a fixed asset tag object to a byte slice
func (asset *FixedAssetTag) Slice() []byte {
	bytes := asset.Bytes()
	return bytes[:]
}

func sliceBytes32(bytes [32]byte) []byte {

	return bytes[:]
}

// Hex converts a surjection proof object to an hex encoded string
func (asset *FixedAssetTag) Hex() string {
	bytes := asset.Bytes()

	return hex.EncodeToString(bytes[:])
}

// SurjectionProofNTotalInputs returns the total number of inputs a proof expects to be over.
// 	 Returns: the number of inputs for the given proof
// 	 In:   		ctx: pointer to a context object
//     				proof: a pointer to a proof object
func SurjectionProofNTotalInputs(
	context *Context,
	proof *SurjectionProof,
) (
	number int,
) {
	return int(C.secp256k1_surjectionproof_n_total_inputs(
		context.ctx,
		proof.proof,
	))
}

// SurjectionProofNUsedInputs returns the actual number of inputs that a proof uses
// 	 Returns: the number of inputs for the given proof
// 	 In:   	 	ctx: pointer to a context object
//     			 	proof: a pointer to a proof object
func SurjectionProofNUsedInputs(
	context *Context,
	proof *SurjectionProof,
) (
	number int,
) {
	return int(C.secp256k1_surjectionproof_n_used_inputs(
		context.ctx,
		proof.proof,
	))
}

// SurjectionProofInitialize proof initialization function; decides on inputs to use
// To be used to initialize stack-allocated secp256k1_surjectionproof struct
// 	 Returns 0: inputs could not be selected
//         	 n: inputs were selected after n iterations of random selection
// 	 In:		 ctx: pointer to a context object
//      		 fixed_input_tags: fixed input tags `A_i` for all inputs. (If the fixed tag is not known,
//                        		 e.g. in a coinjoin with others' inputs, an ephemeral tag can be given;
//                        		 this won't match the output tag but might be used in the anonymity set.)
//   				 n_input_tags_to_use: the number of inputs to select randomly to put in the anonymity set
//                        				Must be <= SECP256K1_SURJECTIONPROOF_MAX_USED_INPUTS
//      		 fixed_output_tag: fixed output tag
//      		 max_n_iterations: the maximum number of iterations to do before giving up. Because the
//                        		 maximum number of inputs (SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS) is
//                        		 limited to 256 the probability of giving up is smaller than
//                        		 (255/256)^(n_input_tags_to_use*max_n_iterations).
//         	 random_seed32: a random seed to be used for input selection
// 	 Out:    proof: The proof whose bitvector will be initialized. In case of failure,
//                  the state of the proof is undefined.
//           input_index: The index of the actual input that is secretly mapped to the output
func SurjectionProofInitialize(
	context *Context,
	fixedInputTags []*FixedAssetTag,
	nInputTagsToUse int,
	fixedOutputTag *FixedAssetTag,
	nMaxIterations int,
	seed32 []byte,
) (*SurjectionProof, int, error) {
	return surjectionProofInitialize(
		context,
		fixedInputTags,
		len(fixedInputTags),
		nInputTagsToUse,
		fixedOutputTag,
		nMaxIterations,
		seed32,
	)
}

// SurjectionProofAllocateInitialized proof allocation and initialization function; decides on inputs to use
// 	 Returns 0: inputs could not be selected, or malloc failure
//         	 n: inputs were selected after n iterations of random selection
// 	 In:     ctx: pointer to a context object
//           proof_out_p: a pointer to a pointer to `secp256k1_surjectionproof*`.
//                        the newly-allocated struct pointer will be saved here.
//      		 fixed_input_tags: fixed input tags `A_i` for all inputs. (If the fixed tag is not known,
//                        		 e.g. in a coinjoin with others' inputs, an ephemeral tag can be given;
//                        		 this won't match the output tag but might be used in the anonymity set.)
//      		 n_input_tags_to_use: the number of inputs to select randomly to put in the anonymity set
//      		 fixed_output_tag: fixed output tag
//      		 max_n_iterations: the maximum number of iterations to do before giving up. Because the
//                        		 maximum number of inputs (SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS) is
//                        	 	 limited to 256 the probability of giving up is smaller than
//                        		 (255/256)^(n_input_tags_to_use*max_n_iterations).
//         	 random_seed32: a random seed to be used for input selection
// 	 Out:    proof_out_p: The pointer to newly-allocated proof whose bitvector will be initialized.
//                        In case of failure, the pointer will be NULL.
//           input_index: The index of the actual input that is secretly mapped to the output
func SurjectionProofAllocateInitialized(
	context *Context,
	fixedInputTags []*FixedAssetTag,
	nInputTagsToUse int,
	fixedOutputTag *FixedAssetTag,
	nMaxIterations int,
	seed32 []byte,
) (
	int,
	*SurjectionProof,
	int,
	error,
) {
	return surjectionProofAllocateInitialized(
		context,
		fixedInputTags,
		len(fixedInputTags),
		nInputTagsToUse,
		fixedOutputTag,
		nMaxIterations,
		seed32,
	)
}

// SurjectionProofDestroy proof destroy function
// deallocates the struct that was allocated with secp256k1_surjectionproof_allocate_initialized
//	 In: proof: pointer to SurjectionProof struct
func SurjectionProofDestroy(
	proof *SurjectionProof,
) {
	C.secp256k1_surjectionproof_destroy(proof.proof)
}

// SurjectionProofGenerate proof generation function
// 	 Returns 0: proof could not be created
//         	 1: proof was successfully created
// 	 In:     ctx: pointer to a context object, initialized for signing and verification
//      	 	 ephemeral_input_tags: the ephemeral asset tag of all inputs
//      		 ephemeral_output_tag: the ephemeral asset tag of the output
//           input_index: the index of the input that actually maps to the output
//        	 input_blinding_key: the blinding key of the input
//       		 output_blinding_key: the blinding key of the output
// 	 In/Out: proof: the produced surjection proof. Must have already gone through SurjectionProofGenerate
func SurjectionProofGenerate(context *Context,
	proof *SurjectionProof,
	ephemeralInputTags []*Generator,
	ephemeralOutputTag *Generator,
	inputIndex int,
	inputBlindingKey []byte,
	outputBlindingKey []byte,
) error {
	return surjectionProofGenerate(
		context,
		proof,
		ephemeralInputTags,
		len(ephemeralInputTags),
		ephemeralOutputTag,
		inputIndex,
		inputBlindingKey,
		outputBlindingKey,
	)
}

// SurjectionProofVerify  proof verification function
// 	 Returns 0: proof was invalid
//         	 1: proof was valid
// 	 In:     ctx: pointer to a context object, initialized for signing and verification
//         	 proof: proof to be verified
//      		 ephemeral_input_tags: the ephemeral asset tag of all inputs
//    	  	 n_ephemeral_input_tags: the number of entries in the ephemeral_input_tags array
//      	 	 ephemeral_output_tag: the ephemeral asset tag of the output
func SurjectionProofVerify(
	context *Context,
	proof *SurjectionProof,
	ephemeralInputTags []*Generator,
	ephemeralOutputTag *Generator,
) bool {
	return surjectionProofVerify(
		context,
		proof,
		ephemeralInputTags,
		len(ephemeralInputTags),
		ephemeralOutputTag,
	)
}

func surjectionProofInitialize(
	context *Context,
	fixedInputTags []*FixedAssetTag,
	nInputs int,
	nInputTagsToUse int,
	fixedOutputTag *FixedAssetTag,
	nMaxIterations int,
	seed32 []byte,
) (*SurjectionProof, int, error) {
	// cache data locally to prevent unexpected modifications
	data := make([]C.secp256k1_fixed_asset_tag, nInputs)
	ptrs := make([]*C.secp256k1_fixed_asset_tag, nInputs)
	for i := 0; i < nInputs; i++ {
		e := fixedInputTags[i]
		data[i] = *(e.tag)
		ptrs[i] = &data[i]
	}

	inputIndex := C.size_t(0)
	proof := newSurjectionProof()
	if 0 == int(C.secp256k1_surjectionproof_initialize(
		context.ctx,
		proof.proof,
		&inputIndex,
		ptrs[0],
		C.size_t(nInputs),
		C.size_t(nInputTagsToUse),
		fixedOutputTag.tag,
		C.size_t(nMaxIterations),
		cBuf(seed32),
	)) {
		return nil, 0, errors.New(ErrSurjectionProofInitialization)
	}

	return proof, int(inputIndex), nil
}

func surjectionProofAllocateInitialized(
	context *Context,
	fixedInputTags []*FixedAssetTag,
	nInputs int,
	nInputTagsToUse int,
	fixedOutputTag *FixedAssetTag,
	nMaxIterations int,
	seed32 []byte,
) (int, *SurjectionProof, int, error) {
	// cache data locally to prevent unexpected modifications
	data := make([]C.secp256k1_fixed_asset_tag, nInputs)
	ptrs := make([]*C.secp256k1_fixed_asset_tag, nInputs)
	for i := 0; i < nInputs; i++ {
		e := fixedInputTags[i]
		data[i] = *(e.tag)
		ptrs[i] = &data[i]
	}

	inputIndex := C.size_t(0)
	proof := SurjectionProof{}
	nIters := int(C.secp256k1_surjectionproof_allocate_initialized(
		context.ctx,
		&proof.proof,
		&inputIndex,
		ptrs[0],
		C.size_t(nInputs),
		C.size_t(nInputTagsToUse),
		fixedOutputTag.tag,
		C.size_t(nMaxIterations),
		cBuf(seed32),
	))
	if nIters <= 0 {
		return -1, nil, -1, errors.New(ErrSurjectionProofAllocation)
	}

	return nIters, &proof, int(inputIndex), nil
}

func surjectionProofGenerate(
	context *Context,
	proof *SurjectionProof,
	ephemeralInputTags []*Generator,
	nInputs int,
	ephemeralOutputTag *Generator,
	inputIndex int,
	inputBlindingKey []byte,
	outputBlindingKey []byte,
) error {
	data := make([]C.secp256k1_generator, nInputs)
	ptrs := make([]*C.secp256k1_generator, nInputs)
	for i := 0; i < nInputs; i++ {
		// cache data locally to prevent unexpected modifications
		e := ephemeralInputTags[i]
		data[i] = *(e.gen)
		ptrs[i] = &data[i]
	}

	if 1 != C.secp256k1_surjectionproof_generate(
		context.ctx,
		proof.proof,
		ptrs[0],
		C.size_t(nInputs), //len(ephemeralInputTags)),
		ephemeralOutputTag.gen,
		C.size_t(inputIndex),
		cBuf(inputBlindingKey),
		cBuf(outputBlindingKey),
	) {
		return errors.New(ErrSurjectionProofGeneration)
	}
	return nil
}

func surjectionProofVerify(
	context *Context,
	proof *SurjectionProof,
	ephemeralInputTags []*Generator,
	nInputs int,
	ephemeralOutputTag *Generator,
) bool {
	// cache data locally to prevent unexpected modifications
	data := make([]C.secp256k1_generator, nInputs)
	ptrs := make([]*C.secp256k1_generator, nInputs)
	for i := 0; i < nInputs; i++ {
		e := ephemeralInputTags[i]
		data[i] = *(e.gen)
		ptrs[i] = &data[i]
	}
	return 1 == C.secp256k1_surjectionproof_verify(
		context.ctx,
		proof.proof,
		ptrs[0],
		C.size_t(nInputs),
		ephemeralOutputTag.gen,
	)
}
