/*
 * x509_p0d_regression_suite.cj — regression tests for the P0-D security fix:
 *   A) CRL signature verification + fail-closed checkRevocation (RFC 5280 §5)
 *   B) certificate extension accessors (EKU / keyUsage / critical) for mdoc
 *      reader-auth (ISO 18013-5).
 *
 * Test data:
 *   - CRL_CA_PEM / CRL_PEM / CRL_DER_HEX are reused from x509_crl_suite.cj
 *     (same package). The CRL was signed by CRL_CA_PEM (verified with
 *     `openssl crl -CAfile` => "verify OK"), so positive verifySignature is
 *     possible.
 *   - READER_CERT_PEM is an EC P-256 self-signed cert generated for this suite
 *     with critical keyUsage(digitalSignature) + critical extendedKeyUsage
 *     (mdoc reader-auth OID 1.0.18013.5.1.6). It exercises the positive paths of
 *     the extension accessors (no pre-existing fixture had these extensions).
 */
package ohos_app_cangjie_entry

import ohos_app_cangjie_eudi_cjx509.x509.crl.{Crl, RevocationStatus}
import ohos_app_cangjie_eudi_cjx509.x509.core.{
    Cert,
    extendedKeyUsageOids,
    hasExtendedKeyUsage,
    hasKeyUsageDigitalSignature,
    criticalExtensionOids
}
import std.time.DateTime
import std.unittest.*
import std.unittest.testmacro.*

// ---------------------------------------------------------------------------
// Reader cert with critical keyUsage(digitalSignature) + EKU mdocReaderAuth.
// ---------------------------------------------------------------------------
let READER_CERT_PEM: String = """
-----BEGIN CERTIFICATE-----
MIIBlzCCAT6gAwIBAgIJAM6RUUV7ja8AMAoGCCqGSM49BAMCMDwxGTAXBgNVBAMM
EEVVREkgVGVzdCBSZWFkZXIxEjAQBgNVBAoMCUVVREkgVGVzdDELMAkGA1UEBhMC
REUwHhcNMjYwNjE5MTYwNTExWhcNMzYwNjE2MTYwNTExWjA8MRkwFwYDVQQDDBBF
VURJIFRlc3QgUmVhZGVyMRIwEAYDVQQKDAlFVURJIFRlc3QxCzAJBgNVBAYTAkRF
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVjVrHdqON8E4cqJQTxrmNgUBwoJ4
fa7Dp3qWCi1wdgbBfkzp7SUax4ZhsvZ63bdZyc+IMpOwLabDDAJ1CkVoj6MpMCcw
DgYDVR0PAQH/BAQDAgeAMBUGA1UdJQEB/wQLMAkGByiBjF0FAQYwCgYIKoZIzj0E
AwIDRwAwRAIgJzawzlz4XiTTpsEUWpeGQDYDl3GsW1bvW0yJP7iuTroCIFm8a8ZH
29NfNGTpJ1gQsA/wom5FVhPrY3oKHj816yOy
-----END CERTIFICATE-----
"""

/** mdoc reader-auth EKU KeyPurposeId. */
let OID_MDOC_READER_AUTH: String = "1.0.18013.5.1.6"

// Build a fixed UTC DateTime for deterministic validity-window tests.
func utc(year: Int64, month: Int64, day: Int64, hour: Int64, minute: Int64, second: Int64): DateTime {
    DateTime.ofUTC(year: year, month: month, dayOfMonth: day, hour: hour, minute: minute, second: second)
}

@Test
class X509P0DRegressionTest {
    // -----------------------------------------------------------------------
    // A) CRL signature: parsed fields preserved
    // -----------------------------------------------------------------------
    @TestCase
    func testCrlPreservesTbsAndSignature() {
        let crl = Crl.fromPem(CRL_PEM)
        @Expect(crl.tbsRaw.size > 0, true)
        @Expect(crl.signatureValue.size > 0, true)
        // tbsRaw is a SEQUENCE element -> starts with tag 0x30.
        @Expect(crl.tbsRaw[0], 0x30u8)
        // outer signatureAlgorithm OID must match the TBS copy (RFC 5280 §5.1.1.2).
        @Expect(crl.outerSignatureAlgorithmOID, crl.signatureAlgorithmOID)
        @Expect(crl.outerSignatureAlgorithmOID, "1.2.840.10045.4.3.2")
    }

    // A) positive: CRL signature verifies against its true issuer CA.
    @TestCase
    func testVerifySignaturePositive() {
        let crl = Crl.fromPem(CRL_PEM)
        let ca = Cert.fromPem(CRL_CA_PEM)[0]
        @Expect(crl.verifySignature(ca), true)
    }

    // A) negative: a different (wrong) certificate must NOT verify.
    @TestCase
    func testVerifySignatureWrongIssuer() {
        let crl = Crl.fromPem(CRL_PEM)
        // The revoked leaf cert is not the CRL signer.
        let wrong = Cert.fromPem(CRL_LEAF_PEM)[0]
        @Expect(crl.verifySignature(wrong), false)
    }

    // A) negative: tampering one byte of the signed TBS region breaks the sig.
    @TestCase
    func testVerifySignatureTamperedTbs() {
        let der = hexToBytes(CRL_DER_HEX)
        // Flip a byte inside the TBSCertList content (offset ~20 is within issuer DN).
        der[20] = der[20] ^ 0xffu8
        let ca = Cert.fromPem(CRL_CA_PEM)[0]
        var ok = true
        try {
            let crl = Crl.fromDer(der)
            ok = crl.verifySignature(ca)
        } catch (_: Exception) {
            // A structural break is also an acceptable "not verified" outcome.
            ok = false
        }
        @Expect(ok, false)
    }

    // -----------------------------------------------------------------------
    // A) checkRevocation — fail-closed
    // -----------------------------------------------------------------------

    // Within window, correct CA, revoked serial -> Revoked.
    @TestCase
    func testCheckRevocationRevoked() {
        let crl = Crl.fromPem(CRL_PEM)
        let ca = Cert.fromPem(CRL_CA_PEM)[0]
        // CRL window: thisUpdate 2026-06-12, nextUpdate 2026-07-12. Pick mid-window.
        let now = utc(2026, 6, 20, 0, 0, 0)
        match (crl.checkRevocation(REVOKED_SERIAL, ca, now)) {
            case Revoked => ()
            case Valid => @Fail("expected Revoked, got Valid")
            case Unverified(why) => @Fail("expected Revoked, got Unverified(${why})")
        }
    }

    // Within window, correct CA, clean serial -> Valid.
    @TestCase
    func testCheckRevocationValid() {
        let crl = Crl.fromPem(CRL_PEM)
        let ca = Cert.fromPem(CRL_CA_PEM)[0]
        let now = utc(2026, 6, 20, 0, 0, 0)
        match (crl.checkRevocation(CA_SERIAL, ca, now)) {
            case Valid => ()
            case Revoked => @Fail("expected Valid, got Revoked")
            case Unverified(why) => @Fail("expected Valid, got Unverified(${why})")
        }
    }

    // Past nextUpdate -> Unverified (expired).
    @TestCase
    func testCheckRevocationExpired() {
        let crl = Crl.fromPem(CRL_PEM)
        let ca = Cert.fromPem(CRL_CA_PEM)[0]
        // Far past nextUpdate (2026-07-12).
        let now = utc(2027, 1, 1, 0, 0, 0)
        match (crl.checkRevocation(REVOKED_SERIAL, ca, now)) {
            case Unverified(_) => ()
            case Revoked => @Fail("expected Unverified (expired), got Revoked")
            case Valid => @Fail("expected Unverified (expired), got Valid")
        }
    }

    // Before thisUpdate -> Unverified (not yet valid).
    @TestCase
    func testCheckRevocationNotYetValid() {
        let crl = Crl.fromPem(CRL_PEM)
        let ca = Cert.fromPem(CRL_CA_PEM)[0]
        let now = utc(2020, 1, 1, 0, 0, 0)
        match (crl.checkRevocation(REVOKED_SERIAL, ca, now)) {
            case Unverified(_) => ()
            case _ => @Fail("expected Unverified (not yet valid)")
        }
    }

    // Wrong signer -> Unverified (signature gate, fail-closed). Even though the
    // serial IS revoked, an unverifiable CRL must NOT report Revoked/Valid.
    @TestCase
    func testCheckRevocationWrongIssuerFailsClosed() {
        let crl = Crl.fromPem(CRL_PEM)
        let wrong = Cert.fromPem(CRL_LEAF_PEM)[0]
        let now = utc(2026, 6, 20, 0, 0, 0)
        match (crl.checkRevocation(REVOKED_SERIAL, wrong, now)) {
            case Unverified(why) => @Expect(why, "CRL signature")
            case _ => @Fail("expected Unverified(CRL signature) — fail closed")
        }
    }

    // -----------------------------------------------------------------------
    // B) extension accessors
    // -----------------------------------------------------------------------
    @TestCase
    func testExtendedKeyUsageOids() {
        let reader = Cert.fromPem(READER_CERT_PEM)[0]
        let ekus = extendedKeyUsageOids(reader)
        @Expect(ekus.size, 1i64)
        @Expect(ekus[0], OID_MDOC_READER_AUTH)
    }

    @TestCase
    func testHasExtendedKeyUsage() {
        let reader = Cert.fromPem(READER_CERT_PEM)[0]
        @Expect(hasExtendedKeyUsage(reader, OID_MDOC_READER_AUTH), true)
        @Expect(hasExtendedKeyUsage(reader, "1.2.3.4.5"), false)
    }

    @TestCase
    func testExtendedKeyUsageAbsent() {
        // CRL leaf cert has no extensions -> empty EKU list.
        let leaf = Cert.fromPem(CRL_LEAF_PEM)[0]
        @Expect(extendedKeyUsageOids(leaf).size, 0i64)
        @Expect(hasExtendedKeyUsage(leaf, OID_MDOC_READER_AUTH), false)
    }

    @TestCase
    func testHasKeyUsageDigitalSignature() {
        let reader = Cert.fromPem(READER_CERT_PEM)[0]
        @Expect(hasKeyUsageDigitalSignature(reader), true)
    }

    @TestCase
    func testHasKeyUsageDigitalSignatureAbsent() {
        // No keyUsage extension -> false.
        let leaf = Cert.fromPem(CRL_LEAF_PEM)[0]
        @Expect(hasKeyUsageDigitalSignature(leaf), false)
    }

    @TestCase
    func testCriticalExtensionOids() {
        let reader = Cert.fromPem(READER_CERT_PEM)[0]
        let crit = criticalExtensionOids(reader)
        // Both keyUsage (2.5.29.15) and EKU (2.5.29.37) are marked critical.
        @Expect(crit.contains("2.5.29.15"), true)
        @Expect(crit.contains("2.5.29.37"), true)
    }

    @TestCase
    func testCriticalExtensionOidsNone() {
        // Leaf cert has no extensions -> no critical OIDs.
        let leaf = Cert.fromPem(CRL_LEAF_PEM)[0]
        @Expect(criticalExtensionOids(leaf).size, 0i64)
    }
}
