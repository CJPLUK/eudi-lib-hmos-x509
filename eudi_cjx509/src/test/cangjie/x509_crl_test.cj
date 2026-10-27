/**
 * x509_crl_test.cj — unit tests for the x509_crl package.
 *
 * Test vectors generated with openssl on 2026-06-12 (macOS LibreSSL 3.3.6):
 *
 *   # CA key + self-signed cert
 *   openssl ecparam -name prime256v1 -genkey -noout -out ca_key.pem
 *   openssl req -new -x509 -key ca_key.pem -out ca_cert.pem -days 3650 \
 *           -subj "/CN=CRL Test CA/O=EUDI Test/C=DE"
 *
 *   # Leaf cert to revoke
 *   openssl ecparam -name prime256v1 -genkey -noout -out leaf_key.pem
 *   openssl req -new -key leaf_key.pem -out leaf_csr.pem \
 *           -subj "/CN=EUDI Test Leaf/O=EUDI Test/C=DE"
 *   openssl x509 -req -in leaf_csr.pem -CA ca_cert.pem -CAkey ca_key.pem \
 *           -CAcreateserial -out leaf_cert.pem -days 365
 *
 *   # CA database setup
 *   touch index.txt && echo "01" > serial.txt
 *   cat > openssl.cnf << 'EOF'
 *   [ca]
 *   default_ca = CA_default
 *   [CA_default]
 *   database = index.txt
 *   serial = serial.txt
 *   default_md = sha256
 *   default_days = 365
 *   default_crl_days = 30
 *   policy = policy_anything
 *   [policy_anything]
 *   countryName = optional
 *   stateOrProvinceName = optional
 *   localityName = optional
 *   organizationName = optional
 *   organizationalUnitName = optional
 *   commonName = supplied
 *   emailAddress = optional
 *   EOF
 *
 *   # Revoke leaf and generate CRL
 *   openssl ca -config openssl.cnf -keyfile ca_key.pem -cert ca_cert.pem -revoke leaf_cert.pem
 *   openssl ca -config openssl.cnf -keyfile ca_key.pem -cert ca_cert.pem -gencrl -out test.crl
 *
 * CRL inspection (openssl crl -in test.crl -text -noout):
 *   Version 1 (0x0)
 *   Signature Algorithm: ecdsa-with-SHA256
 *   Issuer: CN=CRL Test CA, O=EUDI Test, C=DE
 *   thisUpdate: Jun 12 17:51:35 2026 GMT
 *   nextUpdate: Jul 12 17:51:35 2026 GMT
 *   Revoked Serial: C97C60296C3026C1
 *
 * Leaf serial (openssl x509 -noout -serial -in leaf_cert.pem): C97C60296C3026C1
 * CA serial (openssl x509 -noout -serial -in ca_cert.pem):     EA699DCF62F772F2
 */
package ohos_app_cangjie_eudi_cjx509_local_test

import ohos_app_cangjie_eudi_cjx509.x509.crl.{Crl, CrlError, extensionValue, hasDuplicateExtensions}
import ohos_app_cangjie_eudi_cjx509.x509.core.{Cert, CertError}
import std.unittest.*
import std.unittest.testmacro.*

// ---------------------------------------------------------------------------
// Embedded PEM fixtures
// ---------------------------------------------------------------------------

/** CRL Test CA certificate (self-signed EC P-256, issuer of test CRL). */
let CRL_CA_PEM: String = """
-----BEGIN CERTIFICATE-----
MIIBXjCCAQQCCQDqaZ3PYvdy8jAKBggqhkjOPQQDAjA3MRQwEgYDVQQDDAtDUkwg
VGVzdCBDQTESMBAGA1UECgwJRVVESSBUZXN0MQswCQYDVQQGEwJERTAeFw0yNjA2
MTIxNzUxMTBaFw0zNjA2MDkxNzUxMTBaMDcxFDASBgNVBAMMC0NSTCBUZXN0IENB
MRIwEAYDVQQKDAlFVURJIFRlc3QxCzAJBgNVBAYTAkRFMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEtvEdpKBDGzaJwLw6hBmM0laDI5ol1mdbB3JRcNuS951jHqQ3
Ys47IR9X5d+pt06HSbMFfBrY3X3HZfUvMFUIQjAKBggqhkjOPQQDAgNIADBFAiBU
vJW3YXG8YGRfLBAwB1WM7cQEyPBZrE1BZN6FmsPxPAIhAPJkGvhr7XMJSwdfv9kq
XkN4B87Wz2W+zCUBpzXVLdaU
-----END CERTIFICATE-----
"""

/** Leaf certificate, revoked in CRL_PEM. Serial = C97C60296C3026C1. */
let CRL_LEAF_PEM: String = """
-----BEGIN CERTIFICATE-----
MIIBXzCCAQYCCQDJfGApbDAmwTAJBgcqhkjOPQQBMDcxFDASBgNVBAMMC0NSTCBU
ZXN0IENBMRIwEAYDVQQKDAlFVURJIFRlc3QxCzAJBgNVBAYTAkRFMB4XDTI2MDYx
MjE3NTExNVoXDTI3MDYxMjE3NTExNVowOjEXMBUGA1UEAwwORVVESSBUZXN0IExl
YWYxEjAQBgNVBAoMCUVVREkgVGVzdDELMAkGA1UEBhMCREUwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAR+v0GTRtOkJAmDy6SCG4n1fdwy74rWl8kc2WXfBH7Xi1XU
peBALoCMSaCA2Q+0AACseO2x/M2w1AVVIaUY+ggQMAkGByqGSM49BAEDSAAwRQIg
X4sKUKbiPTrTaOjcyVKxk7IOUzmj7n2qt2QCxa8BJ2gCIQDnTspxY1PIkV82xBCh
Cu99rlYBKcCb1dIGtJdZxTDMHg==
-----END CERTIFICATE-----
"""

/** PEM-encoded CRL (v1, issuer = CRL Test CA, revokes C97C60296C3026C1). */
let CRL_PEM: String = """
-----BEGIN X509 CRL-----
MIHaMIGBMAoGCCqGSM49BAMCMDcxFDASBgNVBAMMC0NSTCBUZXN0IENBMRIwEAYD
VQQKDAlFVURJIFRlc3QxCzAJBgNVBAYTAkRFFw0yNjA2MTIxNzUxMzVaFw0yNjA3
MTIxNzUxMzVaMBwwGgIJAMl8YClsMCbBFw0yNjA2MTIxNzUxMzBaMAoGCCqGSM49
BAMCA0gAMEUCIQD6r0nrWv7L5dUXHYLkDFhkOckktqJ1XgMM1m0j2Y/GMQIgP9Rd
ai9rBMCaL4pphZa2hqMesNawfoIV6Ybq+ZQsr1Q=
-----END X509 CRL-----
"""

/**
 * DER bytes of CRL_PEM (hex):
 * 3081da308181300a06082a8648ce3d04030230373114301206035504030c0b43524c205465737420434131123010060355040a
 * 0c09455544492054657374310b3009060355040613024445170d3236303631323137353133355a170d323630373132313735
 * 3133355a301c301a020900c97c60296c3026c1170d3236303631323137353133305a300a06082a8648ce3d040302034800
 * 3045022100faaf49eb5afecbe5d5171d82e40c586439c924b6a2755e030cd66d23d98fc63102203fd45d6a2f6b04c09a2f
 * 8a698596b686a31eb0d6b07e8215e986eaf9942caf54
 */
let CRL_DER_HEX: String = "3081da308181300a06082a8648ce3d04030230373114301206035504030c0b43524c205465737420434131123010060355040a0c09455544492054657374310b3009060355040613024445170d3236303631323137353133355a170d3236303731323137353133355a301c301a020900c97c60296c3026c1170d3236303631323137353133305a300a06082a8648ce3d0403020348003045022100faaf49eb5afecbe5d5171d82e40c586439c924b6a2755e030cd66d23d98fc63102203fd45d6a2f6b04c09a2f8a698596b686a31eb0d6b07e8215e986eaf9942caf54"

/** Serial of the revoked leaf cert (uppercase hex). */
let REVOKED_SERIAL: String = "C97C60296C3026C1"

/** Serial of the CA cert (not revoked). */
let CA_SERIAL: String = "EA699DCF62F772F2"

/** Expected OID for ecdsa-with-SHA256. */
let OID_ECDSA_SHA256: String = "1.2.840.10045.4.3.2"

// ---------------------------------------------------------------------------
// Helper: decode hex string to byte array
// ---------------------------------------------------------------------------

func hexToBytes(hex: String): Array<Byte> {
    let s = hex.toAsciiUpper()
    let arr = s.toArray()
    if (arr.size % 2 != 0) {
        throw Exception("hexToBytes: odd-length hex string")
    }
    let out = Array<Byte>(arr.size / 2) { _ => 0u8 }
    var i: Int64 = 0
    while (i < arr.size) {
        let hi = hexNibbleVal(arr[i])
        let lo = hexNibbleVal(arr[i + 1])
        out[i / 2] = UInt8((hi << 4) | lo)
        i += 2
    }
    out
}

func hexNibbleVal(b: Byte): Int64 {
    if (b >= 0x30u8 && b <= 0x39u8) { return Int64(b - 0x30u8) }  // '0'-'9'
    if (b >= 0x41u8 && b <= 0x46u8) { return Int64(b - 0x41u8) + 10 }  // 'A'-'F'
    throw Exception("hexNibbleVal: invalid hex byte 0x${b}")
}

// ---------------------------------------------------------------------------
// Test group: Crl.fromPem field parsing
// ---------------------------------------------------------------------------

@Test
class X509CrlUT {
    // Test group: Crl.fromPem field parsing
    @TestCase
    func testCrlFromPemVersion() {
        let crl = Crl.fromPem(CRL_PEM)
        // Version 1 (v1 CRL has no version field in TBSCertList)
        @Expect(crl.version, 1i64)
    }

    @TestCase
    func testCrlFromPemIssuer() {
        let crl = Crl.fromPem(CRL_PEM)
        // Issuer should contain "CRL Test CA"
        @Expect(crl.issuer.contains("CRL Test CA"), true)
    }

    @TestCase
    func testCrlFromPemSignatureAlgorithmOID() {
        let crl = Crl.fromPem(CRL_PEM)
        // ecdsa-with-SHA256
        @Expect(crl.signatureAlgorithmOID, OID_ECDSA_SHA256)
    }

    @TestCase
    func testCrlFromPemThisUpdate() {
        let crl = Crl.fromPem(CRL_PEM)
        // thisUpdate = "260612175135Z"
        @Expect(crl.thisUpdate.contains("260612"), true)
    }

    @TestCase
    func testCrlFromPemNextUpdate() {
        let crl = Crl.fromPem(CRL_PEM)
        // nextUpdate = "260712175135Z"
        @Expect(crl.nextUpdate.contains("260712"), true)
    }

    @TestCase
    func testCrlFromPemRevokedCount() {
        let crl = Crl.fromPem(CRL_PEM)
        @Expect(crl.revokedEntries.size, 1i64)
    }

    @TestCase
    func testCrlFromPemRevokedSerial() {
        let crl = Crl.fromPem(CRL_PEM)
        @Expect(crl.revokedEntries.size, 1i64)
        let entry = crl.revokedEntries[0]
        // Serial C97C60296C3026C1 (DER has leading 0x00 padding -> 9 bytes; serialHex strips it)
        @Expect(entry.serialHex, REVOKED_SERIAL)
    }

    // Test group: Crl.fromDer (same vector as PEM, via DER bytes)
    @TestCase
    func testCrlFromDerFields() {
        let der = hexToBytes(CRL_DER_HEX)
        let crl = Crl.fromDer(der)
        @Expect(crl.version, 1i64)
        @Expect(crl.issuer.contains("CRL Test CA"), true)
        @Expect(crl.signatureAlgorithmOID, OID_ECDSA_SHA256)
        @Expect(crl.revokedEntries.size, 1i64)
        @Expect(crl.revokedEntries[0].serialHex, REVOKED_SERIAL)
    }

    @TestCase
    func testCrlFromDerNextUpdatePresent() {
        let der = hexToBytes(CRL_DER_HEX)
        let crl = Crl.fromDer(der)
        @Expect(crl.nextUpdate.isEmpty(), false)
    }

    // Test group: isRevoked
    @TestCase
    func testIsRevokedHit() {
        let crl = Crl.fromPem(CRL_PEM)
        @Expect(crl.isRevoked(REVOKED_SERIAL), true)
    }

    @TestCase
    func testIsRevokedMiss() {
        let crl = Crl.fromPem(CRL_PEM)
        // CA cert serial is NOT revoked
        @Expect(crl.isRevoked(CA_SERIAL), false)
    }

    @TestCase
    func testIsRevokedCaseInsensitive() {
        let crl = Crl.fromPem(CRL_PEM)
        // lower-case serial should also match
        @Expect(crl.isRevoked(REVOKED_SERIAL.toAsciiLower()), true)
    }

    @TestCase
    func testIsRevokedUnknownSerial() {
        let crl = Crl.fromPem(CRL_PEM)
        @Expect(crl.isRevoked("DEADBEEFDEADBEEF"), false)
    }

    // Test group: extensionValue (certificate extension extraction)
    @TestCase
    func testExtensionValueAbsent() {
        // The leaf cert in this test set has no extensions (minimal cert)
        let leaf = Cert.fromPem(CRL_LEAF_PEM)[0]
        // OID 2.5.29.46 = freshestCRL — not present in this cert
        let v = extensionValue(leaf, "2.5.29.46")
        match (v) {
            case None => ()      // expected: extension not present
            case Some(_) => @Fail("Expected None but got Some")
        }
    }

    @TestCase
    func testExtensionValueAbsentArbitraryOID() {
        let ca = Cert.fromPem(CRL_CA_PEM)[0]
        // Arbitrary OID not in this minimal CA cert
        let v = extensionValue(ca, "1.2.3.4.5")
        match (v) {
            case None => ()
            case Some(_) => @Fail("Expected None but got Some")
        }
    }

    // Test group: hasDuplicateExtensions
    @TestCase
    func testHasDuplicateExtensionsNoExtensions() {
        // Leaf cert has no extensions — cannot have duplicates
        let leaf = Cert.fromPem(CRL_LEAF_PEM)[0]
        @Expect(hasDuplicateExtensions(leaf), false)
    }

    @TestCase
    func testHasDuplicateExtensionsCANoDuplicates() {
        // CA cert has no extensions in this minimal test cert
        let ca = Cert.fromPem(CRL_CA_PEM)[0]
        @Expect(hasDuplicateExtensions(ca), false)
    }

    // Test group: error handling
    @TestCase
    func testFromDerMalformed() {
        var threw = false
        try {
            let _ = Crl.fromDer([0x01u8, 0x02u8, 0x03u8])
            threw = false
        } catch (e: CrlError) {
            threw = true
        } catch (e: Exception) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testFromPemWrongLabel() {
        var threw = false
        try {
            // Using a certificate PEM (label "CERTIFICATE") instead of "X509 CRL"
            let _ = Crl.fromPem(CRL_CA_PEM)
            threw = false
        } catch (e: CrlError) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testFromDerEmptyBytes() {
        var threw = false
        try {
            let _ = Crl.fromDer([])
            threw = false
        } catch (e: CrlError) {
            threw = true
        }
        @Expect(threw, true)
    }
}
