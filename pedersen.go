package secp256k1

// #include <stdlib.h>
// #include "./secp256k1-zkp/include/secp256k1_rangeproof.h"
// static const unsigned char** makeBytesArray(int size) { return !size ? NULL : calloc(sizeof(unsigned char*), size); }
// static void setBytesArray(unsigned char** a, unsigned char* v, int i) { if (a) a[i] = v; }
// static unsigned char* getBytesArray(unsigned char** a, int i) { return !a ? NULL : a[i]; }
// static void freeBytesArray(unsigned char** a) { if (a) free(a); }
import "C"
import (
	"encoding/hex"
	"errors"
	"unsafe"
)

const (
	ErrCommitmentParse     string = "unable to parse the data as a commitment"
	ErrCommitmentSerialize string = "unable to serialize commitment"
	ErrCommitmentCount     string = "number of elements differ in input arrays"
	// ErrCommitmentTally     string = "sums of inputs and outputs are not equal"
	ErrCommitmentCommit   string = "failed to create a commitment"
	ErrCommitmentBlindSum string = "failed to calculate sum of blinding factors"
	ErrCommitmentPubkey   string = "failed to create public key from commitment"
)

// Commitment cointains a pointer to opaque data structure that stores a base point
// The exact representation of data inside is implementation defined and not
// guaranteed to be portable between different platforms or versions. It is
// however guaranteed to be 64 bytes in size, and can be safely copied/moved.
// If you need to convert to a format suitable for storage, transmission, or
// comparison, use appropriate serialize and parse functions.
type Commitment struct {
	com *C.secp256k1_pedersen_commitment
}

// Bytes converts a commitment object to array of bytes
func (commit *Commitment) Bytes() (bytes [33]byte) {
	bytes, _ = CommitmentSerialize(SharedContext(ContextNone), commit)
	return
}

// String converts a commitment object to an hex encoded string
func (commit *Commitment) String() string {
	bytes := commit.Bytes()

	return hex.EncodeToString(bytes[:])
}

// CommitmentFromString takes a commitment in hex encoded format and returns
// a commitment object
func CommitmentFromString(str string) (com *Commitment, err error) {
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return

	}
	com, err = CommitmentParse(SharedContext(ContextNone), bytes)

	return
}

func newCommitment() *Commitment {
	return &Commitment{
		com: &C.secp256k1_pedersen_commitment{},
	}
}

// CommitmentParse parses a sequence of bytes as a Pedersen commitment.
// Returns: 1 if input contains a valid commitment.
// Args: ctx:  a secp256k1 context object.
// In:   data: pointer to a 33-byte serialized data
// Out:  nil/Commitment
func CommitmentParse(
	context *Context,
	data33 []byte,
) (
	*Commitment,
	error,
) {
	commit := newCommitment()
	if 1 != C.secp256k1_pedersen_commitment_parse(
		context.ctx,
		commit.com,
		cBuf(data33)) {

		return nil, errors.New(ErrCommitmentParse + " \"" + hex.EncodeToString(data33) + "\"")
	}

	return commit, nil
}

// CommitmentSerialize serializes a commitment into sequence of bytes.
//
//	Returns: 1 always.
//	Args:   ctx:        a secp256k1 context object.
//	In:     Commitment  a commitment object
//	Out:    serialized data: 33-byte byte array
func CommitmentSerialize(
	context *Context,
	commit *Commitment,
) (
	data [33]byte,
	err error,
) {
	if 1 != C.secp256k1_pedersen_commitment_serialize(
		context.ctx,
		cBuf(data[:]),
		commit.com) {

		err = errors.New(ErrCommitmentSerialize)
	}
	return
}

// Commit generates a commitment
//
//				Returns: 1:  Commitment successfully created.
//	  						 0:  Error. The blinding factor is larger than the group order *
//	      						 (probability for random 32 byte number < 2^-127) or results in the
//	      						 point at infinity. Retry with a different factor.
//
//	     Args ctx:  pointer to a context object (cannot be NULL)
//				Out: commit:  pointer to the commitment (cannot be NULL)
//	     In:  blind:  32-byte blinding factor (cannot be NULL)
//	  				 value:  unsigned 64-bit integer value to commit to.
//		 				 value_gen:  value generator 'h'
//
// Blinding factors can be generated and verified in the same way as secp256k1
// private keys for ECDSA.
func Commit(
	context *Context,
	blind []byte,
	value uint64,
	valuegen *Generator,
) (
	commit *Commitment,
	err error,
) {
	commit = newCommitment()
	if 1 != C.secp256k1_pedersen_commit(
		context.ctx,
		commit.com,
		cBuf(blind),
		C.uint64_t(value),
		valuegen.gen) {

		return nil, errors.New(ErrCommitmentCommit)
	}
	return
}

// BlindSum computes the sum of multiple positive and negative blinding factors.
//
//	Returns 1: Sum successfully computed.
//	        0: Error. A blinding factor is larger than the group order
//	           (probability for random 32 byte number < 2^-127). Retry with
//	           different factors.
//
//	In:     ctx:        pointer to a context object (cannot be NULL)
//	        blinds:     pointer to pointers to 32-byte character arrays for blinding factors. (cannot be NULL)
//	        n:          number of factors pointed to by blinds.
//	        npositive:  how many of the input factors should be treated with a positive sign.
//
//	Out:    blind_out:  pointer to a 32-byte array for the sum (cannot be NULL)
func BlindSum(
	context *Context,
	posblinds [][]byte,
	negblinds [][]byte,
) (
	sum [32]byte,
	err error,
) {
	npositive := len(posblinds)
	ntotal := npositive + len(negblinds)

	blinds := C.makeBytesArray(C.int(ntotal))
	defer C.freeBytesArray(blinds)

	for pi, pb := range posblinds {
		C.setBytesArray(blinds, cBuf(pb), C.int(pi))
	}

	for ni, nb := range negblinds {
		C.setBytesArray(blinds, cBuf(nb), C.int(npositive+ni))
	}

	if 1 != C.secp256k1_pedersen_blind_sum(
		context.ctx,
		cBuf(sum[:]),
		blinds,
		C.size_t(C.int(ntotal)),
		C.size_t(C.int(npositive))) {

		err = errors.New("error calculating sum of blinds")
	}

	return
}

// BlindGeneratorBlindSum sets the final Pedersen blinding factor correctly
// when the generators themselves have blinding factors.
//
// Consider a generator of the form A' = A + rG, where A is the "real" generator
// but A' is the generator provided to verifiers. Then a Pedersen commitment
// P = vA' + r'G really has the form vA + (vr + r')G. To get all these (vr + r')
// to sum to zero for multiple commitments, we take three arrays consisting of
// the `v`s, `r`s, and `r'`s, respectively called `value`s, `generator_blind`s
// and `blinding_factor`s, and sum them.
//
// The function then subtracts the sum of all (vr + r') from the last element
// of the `blinding_factor` array, setting the total sum to zero.
//
// Returns 1: Blinding factor successfully computed.
//
//	0: Error. A blinding_factor or generator_blind are larger than the group
//	   order (probability for random 32 byte number < 2^-127). Retry with
//	   different values.
//
// In:                 ctx: pointer to a context object
//
//	          value: array of asset values, `v` in the above paragraph.
//	                 May not be NULL unless `n_total` is 0.
//	generator_blind: array of asset blinding factors, `r` in the above paragraph
//	                 May not be NULL unless `n_total` is 0.
//	        n_total: Total size of the above arrays
//	       n_inputs: How many of the initial array elements represent commitments that
//	                 will be negated in the final sum
//
// In/Out: blinding_factor: array of commitment blinding factors, `r'` in the above paragraph
//
//	May not be NULL unless `n_total` is 0.
//	the last value will be modified to get the total sum to zero.
func BlindGeneratorBlindSum(
	context *Context,
	value []uint64,
	generatorblind [][]byte,
	blindingfactor [][]byte,
	ninputs int,
) (
	blindout [32]byte,
	err error,
) {
	vbl := len(value)
	gbl := len(generatorblind)
	fbl := len(blindingfactor)

	if vbl != gbl || gbl != (fbl+1) {
		err = errors.New(ErrCommitmentCount)
		return
	}

	gbls := C.makeBytesArray(C.int(vbl))
	fbls := C.makeBytesArray(C.int(vbl))
	for i := 0; i < vbl; i++ {
		C.setBytesArray(gbls, cBuf(generatorblind[i]), C.int(i))
		if i != fbl {
			C.setBytesArray(fbls, cBuf(blindingfactor[i]), C.int(i))
		} else {
			out := make([]byte, 32)
			C.setBytesArray(fbls, cBuf(out), C.int(i))
		}
	}
	defer C.freeBytesArray(gbls)
	defer C.freeBytesArray(fbls)

	if 1 != C.secp256k1_pedersen_blind_generator_blind_sum(
		context.ctx,
		u64Arr(value),
		gbls,
		fbls,
		C.size_t(vbl),
		C.size_t(ninputs)) {
		err = errors.New(ErrCommitmentCommit)
		return
	}

	results := make([][32]byte, vbl)
	for i := 0; i < vbl; i++ {
		b := C.getBytesArray(fbls, C.int(i))
		copy(results[i][:], C.GoBytes(unsafe.Pointer(b), 32))
	}
	blindout = results[fbl]
	return
}
