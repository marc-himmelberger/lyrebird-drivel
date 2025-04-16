# internal packages

## cryptodata

The cryptodata package holds one utility data type that allows for better
and more strict type checking of inputs and outputs of KEMs, the CryptoData.
Internally, this is simply a byte slice.

## kems, okems

An OKEM is an obfuscated KEM as defined in https://eprint.iacr.org/2024/1086

The kems and okems packages define unified interfaces for KEMs/OKEMs that
are implemented by constructions and/or wrappers. They also defines data types
used for the inputs and outputs of KEM/OKEM operations.
These packages do not implement any KEM or OKEM themselves.

## cryptofactory

The cryptofactory package collects implementations and constructions for
KEMs and OKEMs using the functions NewKem/NewOkem. This package also holds
all encodings and constructions which implement the KEM/OKEM interfaces.

Except for x25519, all KEMs are direct wrappers around open-quantum-safe
implementations and implement the unified interface from the kems package.

Except for x25519ell2, all OKEMs are wrappers around open-quantum-safe
implementations. An encoding defined here takes care of mapping between
obfuscated ciphertexts and the unobfuscated values used for the underlying
KEM operations.

Possible future additons:
* Implementing X-Wing to have a hybrid KEM for use in Drivel
* Implementing the generic OEINC combiner (statistical OKEM + OKEM = hybrid)

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
