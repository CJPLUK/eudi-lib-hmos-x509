/**
 * x509_coverage_test.cj — coverage top-up for previously-untested public symbols.
 *
 * Targets:
 *   - Cert.notBefore        (validity start DateTime)
 *   - Cert.publicKeyDer     (raw SubjectPublicKeyInfo DER bytes)
 *   - RevokedEntry.serialBytes / RevokedEntry.revocationDate (CRL entry fields)
 *   - x509ModuleAnchor()    (module-load marker, smoke only)
 *
 * Test vectors reuse the openssl-generated fixtures already documented in
 * x509_facade_test.cj and x509_crl_test.cj (macOS LibreSSL, 2026-06-12).
 *
 * Leaf cert validity (openssl x509 -noout -dates):
 *   notBefore = Jun 12 17:10:45 2026 GMT   (DER UTCTIME "260612171045Z")
 *   notAfter  = Jun 12 17:10:45 2027 GMT
 *
 * Leaf SubjectPublicKeyInfo is an EC P-256 SPKI whose BIT STRING content is the
 * 65-byte uncompressed X9.63 point (0x04 || X(32) || Y(32)) = COV_LEAF_X963.
 * Because the BIT STRING is the final field of the SPKI SEQUENCE and carries a
 * single 0x00 "unused bits" prefix byte, the SPKI DER must END with that exact
 * 65-byte point.
 *
 * CRL revoked entry (openssl crl -text):
 *   serial          = C97C60296C3026C1  (DER INTEGER, positive, 0x00-padded -> 9 bytes)
 *   revocationDate  = Jun 12 17:51:30 2026 GMT  (UTCTIME "260612175130Z")
 */
package ohos_app_cangjie_eudi_cjx509_local_test

import ohos_app_cangjie_eudi_cjx509.x509ModuleAnchor
import ohos_app_cangjie_eudi_cjx509.x509.core.{Cert}
import ohos_app_cangjie_eudi_cjx509.x509.crl.{Crl}
import std.time.DateTime
import std.unittest.*
import std.unittest.testmacro.*

// ---------------------------------------------------------------------------
// Fixtures (re-declared locally; same vectors as the sibling test files)
// ---------------------------------------------------------------------------

/** Leaf certificate (EC P-256). notBefore = 260612171045Z. */
let COV_LEAF_PEM: String = """
-----BEGIN CERTIFICATE-----
MIIBYTCCAQgCCQDgG1MIt04++TAJBgcqhkjOPQQBMD8xHTAbBgNVBAMMFFRlc3Qg
SW50ZXJtZWRpYXRlIENBMREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCREUw
HhcNMjYwNjEyMTcxMDQ1WhcNMjcwNjEyMTcxMDQ1WjA0MRIwEAYDVQQDDAlUZXN0
IExlYWYxETAPBgNVBAoMCFRlc3QgT3JnMQswCQYDVQQGEwJERTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABHvaTf9Vr6/Idyxa3W1QrCE8B/pHr3A7myRmCEotevc1
qvG+xuyny7JFWqyIU3LUZNcfJpO5ZNdxIii2WoKJu2MwCQYHKoZIzj0EAQNIADBF
AiEA9fr6BJZEWaitvwkRggxAmVnU44iPKKt11x2kKBRnGfgCIEdqQauDYtXSqbjE
/tjmfOW+UziM2VXyQ/s+WtRuQq/Y
-----END CERTIFICATE-----
"""

/** Leaf uncompressed X9.63 EC point (0x04 || X(32) || Y(32)) = tail of SPKI. */
let COV_LEAF_X963: Array<Byte> = [
    0x04u8,
    0x7bu8, 0xdau8, 0x4du8, 0xffu8, 0x55u8, 0xafu8, 0xafu8, 0xc8u8,
    0x77u8, 0x2cu8, 0x5au8, 0xddu8, 0x6du8, 0x50u8, 0xacu8, 0x21u8,
    0x3cu8, 0x07u8, 0xfau8, 0x47u8, 0xafu8, 0x70u8, 0x3bu8, 0x9bu8,
    0x24u8, 0x66u8, 0x08u8, 0x4au8, 0x2du8, 0x7au8, 0xf7u8, 0x35u8,
    0xaau8, 0xf1u8, 0xbeu8, 0xc6u8, 0xecu8, 0xa7u8, 0xcbu8, 0xb2u8,
    0x45u8, 0x5au8, 0xacu8, 0x88u8, 0x53u8, 0x72u8, 0xd4u8, 0x64u8,
    0xd7u8, 0x1fu8, 0x26u8, 0x93u8, 0xb9u8, 0x64u8, 0xd7u8, 0x71u8,
    0x22u8, 0x28u8, 0xb6u8, 0x5au8, 0x82u8, 0x89u8, 0xbbu8, 0x63u8
]

/** PEM-encoded CRL (v1) revoking serial C97C60296C3026C1, revDate 260612175130Z. */
let COV_CRL_PEM: String = """
-----BEGIN X509 CRL-----
MIHaMIGBMAoGCCqGSM49BAMCMDcxFDASBgNVBAMMC0NSTCBUZXN0IENBMRIwEAYD
VQQKDAlFVURJIFRlc3QxCzAJBgNVBAYTAkRFFw0yNjA2MTIxNzUxMzVaFw0yNjA3
MTIxNzUxMzVaMBwwGgIJAMl8YClsMCbBFw0yNjA2MTIxNzUxMzBaMAoGCCqGSM49
BAMCA0gAMEUCIQD6r0nrWv7L5dUXHYLkDFhkOckktqJ1XgMM1m0j2Y/GMQIgP9Rd
ai9rBMCaL4pphZa2hqMesNawfoIV6Ybq+ZQsr1Q=
-----END X509 CRL-----
"""

/** Expected DER INTEGER value bytes of the revoked serial: 0x00 pad + C97C60296C3026C1. */
let COV_REVOKED_SERIAL_BYTES: Array<Byte> = [
    0x00u8, 0xc9u8, 0x7cu8, 0x60u8, 0x29u8, 0x6cu8, 0x30u8, 0x26u8, 0xc1u8
]

// ---------------------------------------------------------------------------
// Cert.notBefore
// ---------------------------------------------------------------------------

@Test
class X509NotBeforeUT {
    /** notBefore equals the known UTC instant 2026-06-12T17:10:45Z. */
    @TestCase
    func testNotBeforeEqualsKnownInstant() {
        let leaf = Cert.fromPem(COV_LEAF_PEM)[0]
        let expected = DateTime.ofUTC(
            year: 2026, month: 6, dayOfMonth: 12, hour: 17, minute: 10, second: 45)
        // DateTime == compares the underlying instant, independent of zone.
        @Expect(leaf.notBefore == expected, true)
    }

    /** notBefore UTC components match the cert UTCTIME field "260612171045Z". */
    @TestCase
    func testNotBeforeUtcComponents() {
        let leaf = Cert.fromPem(COV_LEAF_PEM)[0]
        let nb = leaf.notBefore.inUTC()
        @Expect(nb.year, 2026)
        @Expect(nb.dayOfMonth, 12)
        @Expect(nb.hour, 17)
        @Expect(nb.minute, 10)
        @Expect(nb.second, 45)
    }

    /** notBefore must be strictly before notAfter (1-year validity window). */
    @TestCase
    func testNotBeforeOrdersBeforeNotAfter() {
        let leaf = Cert.fromPem(COV_LEAF_PEM)[0]
        @Expect(leaf.notBefore < leaf.notAfter, true)
    }
}

// ---------------------------------------------------------------------------
// Cert.publicKeyDer
// ---------------------------------------------------------------------------

@Test
class X509PublicKeyDerUT {
    /** publicKeyDer is a DER SEQUENCE (SPKI) and longer than the bare EC point. */
    @TestCase
    func testPublicKeyDerIsSpkiSequence() {
        let leaf = Cert.fromPem(COV_LEAF_PEM)[0]
        let spki = leaf.publicKeyDer
        // SubjectPublicKeyInfo is wrapped in a SEQUENCE (tag 0x30).
        @Expect(spki[0], 0x30u8)
        // SPKI must be larger than the 65-byte EC point it contains.
        @Expect(spki.size > 65, true)
    }

    /** The SPKI DER ends with the exact 65-byte uncompressed X9.63 EC point. */
    @TestCase
    func testPublicKeyDerEndsWithEcPoint() {
        let leaf = Cert.fromPem(COV_LEAF_PEM)[0]
        let spki = leaf.publicKeyDer
        let n = spki.size
        let tail = spki[n - 65..n]
        @Expect(tail == COV_LEAF_X963, true)
    }

    /** publicKeyDer is deterministic across repeated parses of the same cert. */
    @TestCase
    func testPublicKeyDerStableAcrossParses() {
        let a = Cert.fromPem(COV_LEAF_PEM)[0].publicKeyDer
        let b = Cert.fromPem(COV_LEAF_PEM)[0].publicKeyDer
        @Expect(a == b, true)
    }
}

// ---------------------------------------------------------------------------
// RevokedEntry fields (serialBytes / revocationDate)
// ---------------------------------------------------------------------------

@Test
class X509RevokedEntryUT {
    /** serialBytes are the raw DER INTEGER value (0x00-padded, 9 bytes). */
    @TestCase
    func testRevokedEntrySerialBytes() {
        let crl = Crl.fromPem(COV_CRL_PEM)
        @Expect(crl.revokedEntries.size, 1i64)
        let entry = crl.revokedEntries[0]
        let sb = entry.serialBytes
        // Positive DER INTEGER for C97C... has a leading 0x00 padding byte.
        @Expect(sb.size, 9i64)
        @Expect(sb[0], 0x00u8)
        @Expect(sb == COV_REVOKED_SERIAL_BYTES, true)
    }

    /** serialHex (derived from serialBytes) strips the 0x00 pad to canonical hex. */
    @TestCase
    func testRevokedEntrySerialHexMatchesBytes() {
        let crl = Crl.fromPem(COV_CRL_PEM)
        let entry = crl.revokedEntries[0]
        @Expect(entry.serialHex, "C97C60296C3026C1")
    }

    /** revocationDate is the raw UTCTIME string from the CRL entry. */
    @TestCase
    func testRevokedEntryRevocationDate() {
        let crl = Crl.fromPem(COV_CRL_PEM)
        let entry = crl.revokedEntries[0]
        // openssl crl -text: revocation date Jun 12 17:51:30 2026 GMT
        @Expect(entry.revocationDate, "260612175130Z")
    }
}

// ---------------------------------------------------------------------------
// x509ModuleAnchor — module-load marker (smoke)
// ---------------------------------------------------------------------------

@Test
class X509ModuleAnchorUT {
    /**
     * x509ModuleAnchor() is a Unit-returning module-load marker (emits a Hilog
     * line). It takes no args and has no return value to assert on; the test
     * confirms it is callable and completes without throwing.
     */
    @TestCase
    func testModuleAnchorCallable() {
        var ran = false
        x509ModuleAnchor()
        ran = true
        @Expect(ran, true)
    }
}
