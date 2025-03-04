# internal packages

## cryptodata

The cryptodata package holds one utility data type that allows for better
and more strict type checking of inputs and outputs of KEMs, the CryptoData.

## cryptofactory

The cryptofactory package collects implementations and constructions for
KEMs and OKEMs. Built mainly to avoid a cyclic dependency and to provide
NewKem/NewOkem functions. This package also holds all encodings,
constructions and wrapper code used to make KEM implementations available.


## kems

The kem package provides various KEMs in a unified interface.
TODO: Optional - Also implement X-Wing to have a hybrid KEM for use in Drivel

Except for x25519, these KEMs are direct wrappers around
open-quantum-safe implementations. The point is simply to capture all KEMs
using a single interface and abstract away from their internal construction.

## okems

The okems package provides a Go wrapper and unified interface around the
implementation of obfuscated KEMs as e.g. constructed in
https://eprint.iacr.org/2024/1086.
TODO: Also implement encoders for more OKEMs from other OQS KEMs
TODO: Optional - Also implement the generic OEINC combiner (statistical OKEM + OKEM = hybrid)

Except for x25519ell2, these obufscated KEMs are wrappers around
open-quantum-safe implementations. An encoding defined here takes care
of mapping between obfuscated public keys and ciphertexts and the
corresponding values used for the underlying KEM operations.

Consumers such as the drivel transport should only interface with OKEMs.

## x25519ell2

The x25519ell2 package provides X25519 obfuscated with Elligator 2, with
special care taken to handle cofactor related issues, and fixes for the
bugs in agl's original Elligator2 implementation.

All existing versions prior to the migration to the new code (anything
that uses agl's code) are fatally broken, and trivial to distinguish via
some simple math.  For more details see Loup Vaillant's writings on the
subject.  Any bugs in the implementation are mine, and not his.

Representatives created by this implementation will correctly be decoded
by existing implementations.  Public keys created by this implementation
be it via the modified scalar basepoint multiply or via decoding a
representative will be somewhat non-standard, but will interoperate with
a standard X25519 scalar-multiply.

As the representative to public key transform should be identical,
this change is fully-backward compatible (though the non-upgraded side
of the connection will still be trivially distinguishable from random).
