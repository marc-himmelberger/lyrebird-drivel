The kem package provides various KEMs in a unified interface.
TODO: Optional - Also implement X-Wing to have a hybrid KEM for use in Drivel

Except for x25519, these KEMs are direct wrappers around
open-quantum-safe implementations. The point is simply to capture all KEMs
using a single interface and abstract away from their internal construction.
