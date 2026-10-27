package ohos_app_cangjie_eudi_cjx509

import kit.PerformanceAnalysisKit.Hilog
import ohos_app_cangjie_eudi_cjx509.x509.core.{Cert, verifyChain}
import ohos_app_cangjie_eudi_cjx509.x509.crl.{Crl}

public func x509ModuleAnchor(): Unit {
    Hilog.info(0, "Cangjie", "eudi_cjx509 module loaded")
}

// ---------------------------------------------------------------------------
// Embedded PEM fixtures (copied from x509_facade_test / x509_crl_test)
// ---------------------------------------------------------------------------

let _DEMO_ROOT_CA_PEM: String = """
-----BEGIN CERTIFICATE-----
MIIBXzCCAQQCCQDf8najtcVHajAKBggqhkjOPQQDAjA3MRUwEwYDVQQDDAxUZXN0
IFJvb3QgQ0ExETAPBgNVBAoMCFRlc3QgT3JnMQswCQYDVQQGEwJERTAeFw0yNjA2
MTIxNzEwMTRaFw0zNjA2MDkxNzEwMTRaMDcxFTATBgNVBAMMDFRlc3QgUm9vdCBD
QTERMA8GA1UECgwIVGVzdCBPcmcxCzAJBgNVBAYTAkRFMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEL7MTEGbogCdSD66Ka0Bzpd/f++u0rKaRGoemAcDEolGHLwzo
9rXor6C8WhhKclFeQfuczpn2kboNn2Ru1U/+jzAKBggqhkjOPQQDAgNJADBGAiEA
2apXjtSAeBpka0u67J3/DoXw2x/qaih03ajwCJHTN/QCIQDwnL5m39lIkpER6LK3
81vuWQZY/ipamdWaffkb527fZw==
-----END CERTIFICATE-----
"""

let _DEMO_INT_CA_PEM: String = """
-----BEGIN CERTIFICATE-----
MIIBfDCCASKgAwIBAgIJAP0u8k/hL6MGMAkGByqGSM49BAEwNzEVMBMGA1UEAwwM
VGVzdCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCREUwHhcN
MjYwNjEyMTcxMDMyWhcNMzYwNjA5MTcxMDMyWjA/MR0wGwYDVQQDDBRUZXN0IElu
dGVybWVkaWF0ZSBDQTERMA8GA1UECgwIVGVzdCBPcmcxCzAJBgNVBAYTAkRFMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHIRmAVISzJTxygO8L2gz0ASobF3BVT2x
0PDBhWWBJEwXJnKSdXX1KJUf8Dm2C1QVcMX/nmXZcLFk3Y7CKeQEx6MQMA4wDAYD
VR0TBAUwAwEB/zAJBgcqhkjOPQQBA0kAMEYCIQDoByBiZOdbxMkN/vsicOaw8mGK
H+JCW6Xg5rgSuZnahQIhAOLKSG6rl4UaiMrDsPX5YanvnMfUL6slRi92WRtDorHZ
-----END CERTIFICATE-----
"""

let _DEMO_LEAF_PEM: String = """
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

let _DEMO_CRL_PEM: String = """
-----BEGIN X509 CRL-----
MIHaMIGBMAoGCCqGSM49BAMCMDcxFDASBgNVBAMMC0NSTCBUZXN0IENBMRIwEAYD
VQQKDAlFVURJIFRlc3QxCzAJBgNVBAYTAkRFFw0yNjA2MTIxNzUxMzVaFw0yNjA3
MTIxNzUxMzVaMBwwGgIJAMl8YClsMCbBFw0yNjA2MTIxNzUxMzBaMAoGCCqGSM49
BAMCA0gAMEUCIQD6r0nrWv7L5dUXHYLkDFhkOckktqJ1XgMM1m0j2Y/GMQIgP9Rd
ai9rBMCaL4pphZa2hqMesNawfoIV6Ybq+ZQsr1Q=
-----END X509 CRL-----
"""

/** Serial of the revoked leaf cert in the demo CRL. */
let _DEMO_REVOKED_SERIAL: String = "C97C60296C3026C1"

/** Serial of the CA cert — not revoked in the demo CRL. */
let _DEMO_CLEAN_SERIAL: String = "EA699DCF62F772F2"

/**
 * runX509Demo runs a self-contained x509 capability demonstration:
 *   1. Parse a leaf certificate and extract its subject CN.
 *   2. Verify a three-cert chain (leaf <- intermediate <- root) → PASS.
 *   3. Parse a CRL and check a revoked serial → hit.
 *   4. Check a non-revoked serial → miss.
 *
 * Returns a result string of the form:
 *   "OK: cert=<subject>, chain=PASS, revoked_hit=true, clean_miss=false"
 * or on any error:
 *   "ERR: <message>"
 */
public func runX509Demo(): String {
    try {
        // Step 1 — parse leaf cert and extract subject
        let leafCerts = Cert.fromPem(_DEMO_LEAF_PEM)
        if (leafCerts.size < 1) {
            return "ERR: leaf PEM produced no certs"
        }
        let leaf = leafCerts[0]
        let subj = leaf.subject

        // Extract CN from subject string (format: "CN=Test Leaf,O=Test Org,C=DE")
        let cn = extractCN(subj)

        // Step 2 — build chain and verify
        let root = Cert.fromPem(_DEMO_ROOT_CA_PEM)[0]
        let intCa = Cert.fromPem(_DEMO_INT_CA_PEM)[0]
        let chainOk = verifyChain(leaf, [intCa], [root])
        let chainStr = if (chainOk) { "PASS" } else { "FAIL" }

        // Step 3 — CRL: revoked serial must be hit
        let crl = Crl.fromPem(_DEMO_CRL_PEM)
        let revokedHit = crl.isRevoked(_DEMO_REVOKED_SERIAL)

        // Step 4 — CRL: clean serial must be a miss
        let cleanMiss = crl.isRevoked(_DEMO_CLEAN_SERIAL)

        "OK: cert=${cn}, chain=${chainStr}, revoked_hit=${revokedHit}, clean_miss=${cleanMiss}"
    } catch (e: Exception) {
        "ERR: ${e.message}"
    }
}

/**
 * extractCN extracts the CN value from a distinguished name string.
 * Input format: "CN=Test Leaf,O=Test Org,C=DE" (comma-separated RDNs).
 * Returns the CN value, or the full subject string if CN= is not found.
 */
func extractCN(dn: String): String {
    let dnArr = dn.toArray()
    let prefix: Array<Byte> = [0x43u8, 0x4Eu8, 0x3Du8]  // "CN="
    var i: Int64 = 0
    while (i + 3 <= dnArr.size) {
        if (dnArr[i] == prefix[0] && dnArr[i + 1] == prefix[1] && dnArr[i + 2] == prefix[2]) {
            // found "CN=", collect until comma or end
            var j = i + 3
            while (j < dnArr.size && dnArr[j] != 0x2Cu8) {  // ',' == 0x2C
                j++
            }
            return String.fromUtf8(dnArr[i + 3..j])
        }
        i++
    }
    dn
}
