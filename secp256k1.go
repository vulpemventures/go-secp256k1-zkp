package secp256k1

/*
#define USE_BASIC_CONFIG 1
#include "./secp256k1-zkp/src/basic-config.h"

#define ENABLE_MODULE_ECDH 1
#define ENABLE_MODULE_GENERATOR 1
#define ENABLE_MODULE_RANGEPROOF 1
#define ENABLE_MODULE_SURJECTIONPROOF 1

#include "secp256k1-zkp/src/secp256k1.c"

#cgo CFLAGS: -I${SRCDIR}/secp256k1-zkp -I${SRCDIR}/secp256k1-zkp/src
*/
import "C"
import (
	"fmt"
	"unsafe"
)

const (
	// ContextNone wraps the SECP256K1_CONTEXT_NONE constant
	ContextNone = uint(C.SECP256K1_CONTEXT_NONE)
	// ContextSign wraps the SECP256K1_CONTEXT_SIGN constant
	ContextSign = uint(C.SECP256K1_CONTEXT_SIGN)
	// ContextVerify wraps the SECP256K1_CONTEXT_VERIFY constant
	ContextVerify = uint(C.SECP256K1_CONTEXT_VERIFY)
	// ContextBoth includes all context types
	ContextBoth = ContextSign | ContextVerify
)

var ctxmap map[uint]*Context

// Context wraps a *secp256k1_context, required to use all functions.
// It can be initialized for signing, verification, or both.
type Context struct {
	ctx *C.secp256k1_context
}

func init() {
	ctxmap = make(map[uint]*Context)
}

func newContext() *Context {
	return &Context{
		ctx: &C.secp256k1_context{},
	}
}

func cBuf(goSlice []byte) *C.uchar {
	if goSlice == nil {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}

func u64Arr(a []uint64) *C.uint64_t {
	if a == nil {
		return nil
	}
	return (*C.uint64_t)(unsafe.Pointer(&a[0]))
}

func goBytes(cSlice []C.uchar, size C.int) []byte {
	return C.GoBytes(unsafe.Pointer(&cSlice[0]), size)
}

// ContextCreate produces a new *Context, initialized with a bitmask of flags
// depending on it's intended usage. The supported flags are currently
// ContextSign and ContextVerify. Although expressed in the return type
// signature, the function does not currently return an error.
func ContextCreate(flags uint) (*Context, error) {
	context := newContext()
	context.ctx = C.secp256k1_context_create(C.uint(flags))
	return context, nil
}

// ContextClone makes a copy of the provided *Context. The provided context
// must not be NULL.
func ContextClone(ctx *Context) (*Context, error) {
	other := newContext()
	other.ctx = C.secp256k1_context_clone(ctx.ctx)
	return other, nil
}

// ContextDestroy destroys the context. The provided context must not be NULL.
func ContextDestroy(ctx *Context) {
	C.secp256k1_context_destroy(ctx.ctx)
}

// ContextRandomize accepts a [32]byte seed in order to update the context
// randomization. NULL may be passed to reset to initial state. The context
// pointer must not be null.
func ContextRandomize(ctx *Context, seed32 [32]byte) int {
	return int(C.secp256k1_context_randomize(ctx.ctx, cBuf(seed32[:])))
}

// SharedContext returns a managed context
func SharedContext(flags uint) (context *Context) {
	flags = flags & ContextBoth
	context, exists := ctxmap[flags]
	if !exists {
		var err error
		context, err = ContextCreate(flags)
		if err != nil {
			panic(fmt.Sprintf("error creating default context object (flags: %d, error: %s)", flags, err))
		}
		ctxmap[flags] = context
	}

	return
}
