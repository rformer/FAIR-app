package oscal

import (
	"crypto/sha1" // #nosec G505 -- UUIDv5 name hashing only (see UUIDv5)
	"fmt"
)

// UUIDv5 is a deterministic RFC 9562 version-5 UUID of name in the URL
// namespace, so generated documents are reproducible. OSCAL's UUID datatype
// accepts only versions 4 and 5; version 5 is defined with SHA-1, used here
// only as the name hash, which FIPS mode (fips140=on) permits.
func UUIDv5(name string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8} // URL namespace
	h := sha1.New()                                                                                              // #nosec G401 -- RFC 9562 UUIDv5 name hashing, not a security function
	h.Write(ns)
	h.Write([]byte(name))
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
