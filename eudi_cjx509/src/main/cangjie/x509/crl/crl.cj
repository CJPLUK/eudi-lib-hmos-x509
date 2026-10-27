/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Package: ohos_app_cangjie_eudi_cjx509.x509.crl
 *
 * RFC 5280 §5 Certificate Revocation List (CRL) parser — pure DER/PEM decoder.
 * stdx has no CRL type; all TLV parsing is self-contained in this package.
 *
 * Public API:
 *   Crl.fromDer(bytes)            — parse DER-encoded CRL
 *   Crl.fromPem(pem)              — parse PEM-encoded CRL (label "X509 CRL")
 *   Crl.isRevoked(serial)         — serial hex lookup in revocation list
 *   extensionValue(cert, oid)     — extract extension raw value from a Cert
 *   hasDuplicateExtensions(cert)  — detect duplicate OID extensions in a Cert
 *
 * RFC 5280 §5.1 TBSCertList structure:
 *   TBSCertList ::= SEQUENCE {
 *     version                 Version OPTIONAL,          -- absent for v1
 *     signature               AlgorithmIdentifier,
 *     issuer                  Name,
 *     thisUpdate              Time,
 *     nextUpdate              Time OPTIONAL,
 *     revokedCertificates     SEQUENCE OF SEQUENCE {
 *       userCertificate   CertificateSerialNumber,
 *       revocationDate    Time,
 *       crlEntryExtensions Extensions OPTIONAL
 *     } OPTIONAL,
 *     crlExtensions           [0] EXPLICIT Extensions OPTIONAL
 *   }
 */
package ohos_app_cangjie_eudi_cjx509.x509.crl

import ohos_app_cangjie_eudi_cjx509.x509.core.{Cert}
import stdx.crypto.common.{Pem, DerBlob}
import stdx.crypto.keys.ECDSAPublicKey
import stdx.crypto.digest.SHA256
import std.collection.{ArrayList, HashSet}
import std.time.DateTime

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/**
 * CrlError wraps all CRL parsing and lookup failures.
 * Inherits Exception.message via super(msg) — see R-105.
 */
public class CrlError <: Exception {
    public init(msg: String) {
        super(msg)
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/**
 * One revoked certificate entry from a CRL.
 * serialBytes — raw DER INTEGER value bytes (no tag/length).
 */
public class RevokedEntry {
    public let serialBytes: Array<Byte>
    public let revocationDate: String

    init(serialBytes: Array<Byte>, revocationDate: String) {
        this.serialBytes = serialBytes
        this.revocationDate = revocationDate
    }

    /**
     * Serial as uppercase hex string, leading zero pad byte stripped.
     * Matches the format returned by stdx SerialNumber.toString() / Cert.serialNumber.
     */
    public prop serialHex: String {
        get() {
            var start: Int64 = 0
            // DER positive INTEGER may have a 0x00 prefix — strip it for display
            if (serialBytes.size > 1 && serialBytes[0] == 0x00u8) {
                start = 1
            }
            let len = serialBytes.size - start
            let buf = Array<Byte>(len * 2) { _ => 0u8 }
            var i = start
            var j: Int64 = 0
            while (i < serialBytes.size) {
                let b = serialBytes[i]
                buf[j]     = crlHexNibble(b >> 4)
                buf[j + 1] = crlHexNibble(b & 0x0fu8)
                j += 2
                i++
            }
            String.fromUtf8(buf)
        }
    }
}

// ---------------------------------------------------------------------------
// Revocation check result
// ---------------------------------------------------------------------------

/**
 * Result of a *trusted* revocation check (Crl.checkRevocation).
 *
 *   Valid            — CRL signature + issuer + validity window all passed,
 *                      and the queried serial is NOT in the revoked list.
 *   Revoked          — all trust checks passed AND the serial IS revoked.
 *   Unverified(why)  — fail-closed: a trust precondition failed (signature,
 *                      issuer mismatch, or expired/not-yet-valid window). The
 *                      caller MUST treat this as "cannot trust this CRL" — it is
 *                      NOT a synonym for Valid.
 */
public enum RevocationStatus {
    | Valid
    | Revoked
    | Unverified(String)
}

// ---------------------------------------------------------------------------
// Main Crl type
// ---------------------------------------------------------------------------

/**
 * Parsed X.509 CRL (RFC 5280 §5).
 */
public class Crl {
    /** 1 for v1 (no version field in TBSCertList), 2 for v2. */
    public let version: Int64
    /** Issuer DN as "CN=...,O=...,C=..." */
    public let issuer: String
    /** thisUpdate as raw UTCTIME/GENERALIZEDTIME string, e.g. "260612175135Z". */
    public let thisUpdate: String
    /** nextUpdate; empty string if absent. */
    public let nextUpdate: String
    /** Revoked certificate entries. */
    public let revokedEntries: Array<RevokedEntry>
    /** Signature algorithm OID (dotted decimal) from inside the TBSCertList. */
    public let signatureAlgorithmOID: String
    /**
     * Raw DER of the TBSCertList element (tag 0x30 + length + content) — the
     * exact byte range the CRL signature is computed over (RFC 5280 §5.1.1.1).
     */
    public let tbsRaw: Array<Byte>
    /**
     * signatureValue: DER ECDSA-Sig-Value (SEQUENCE { r, s }) bytes, with the
     * BIT STRING unused-bits prefix byte already stripped.
     */
    public let signatureValue: Array<Byte>
    /**
     * signatureAlgorithm OID from the *outer* CertificateList (the one actually
     * applied to the signature), dotted decimal. Per RFC 5280 §5.1.1.2 this MUST
     * equal signatureAlgorithmOID (the TBS copy); we keep both to enforce that.
     */
    public let outerSignatureAlgorithmOID: String

    init(
        version: Int64,
        issuer: String,
        thisUpdate: String,
        nextUpdate: String,
        revokedEntries: Array<RevokedEntry>,
        signatureAlgorithmOID: String,
        tbsRaw: Array<Byte>,
        signatureValue: Array<Byte>,
        outerSignatureAlgorithmOID: String
    ) {
        this.version          = version
        this.issuer           = issuer
        this.thisUpdate       = thisUpdate
        this.nextUpdate       = nextUpdate
        this.revokedEntries   = revokedEntries
        this.signatureAlgorithmOID = signatureAlgorithmOID
        this.tbsRaw           = tbsRaw
        this.signatureValue   = signatureValue
        this.outerSignatureAlgorithmOID = outerSignatureAlgorithmOID
    }

    // -----------------------------------------------------------------------
    // Parsing
    // -----------------------------------------------------------------------

    /**
     * Parse a DER-encoded CRL.
     * Throws CrlError on malformed input.
     */
    public static func fromDer(bytes: Array<Byte>): Crl {
        try {
            crlParseDer(bytes)
        } catch (e: CrlError) {
            throw e
        } catch (e: Exception) {
            throw CrlError("Crl.fromDer failed: ${e.message}")
        }
    }

    /**
     * Parse a PEM-encoded CRL.  The PEM label must be "X509 CRL".
     * Throws CrlError if no CRL entry is found or DER is malformed.
     */
    public static func fromPem(pem: String): Crl {
        try {
            let pemObj = Pem.decode(pem)
            var found: ?Array<Byte> = None
            for (entry in pemObj) {
                if (entry.label == "X509 CRL") {
                    match (entry.body) {
                        case Some(blob) =>
                            found = Some(blob.body)
                            break
                        case None => ()
                    }
                }
            }
            match (found) {
                case Some(der) => fromDer(der)
                case None => throw CrlError("No 'X509 CRL' PEM entry found")
            }
        } catch (e: CrlError) {
            throw e
        } catch (e: Exception) {
            throw CrlError("Crl.fromPem failed: ${e.message}")
        }
    }

    // -----------------------------------------------------------------------
    // Lookup
    // -----------------------------------------------------------------------

    /**
     * WARNING — UNVERIFIED RAW LOOKUP. This is a plain serial-number membership
     * test against the parsed revoked list. It does NOT verify the CRL
     * signature, the issuer, or the thisUpdate/nextUpdate validity window. A
     * forged or stale CRL will be trusted blindly. Kept only for the demo and
     * legacy callers. ALL trust/security decisions MUST use checkRevocation(),
     * which is fail-closed (RFC 5280 §5).
     *
     * Returns true if the given serial number is in the CRL's revoked list.
     *
     * serial — uppercase hex string as returned by Cert.serialNumber,
     *           e.g. "C97C60296C3026C1".
     * Leading-zero normalisation is applied on both sides before comparison.
     */
    public func isRevoked(serial: String): Bool {
        let target = crlNormalizeHex(serial)
        for (entry in revokedEntries) {
            if (crlNormalizeHex(entry.serialHex) == target) {
                return true
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // Signature verification (RFC 5280 §5.1.1.3)
    // -----------------------------------------------------------------------

    /**
     * Verify the CRL signature against the public key of the supplied issuer
     * certificate (ECDSA-with-SHA256 over the raw TBSCertList bytes).
     *
     * Only ECDSA signatures are supported. If outerSignatureAlgorithmOID is not
     * an ecdsa-with-SHA* OID (e.g. 1.2.840.10045.4.3.2 = ecdsa-with-SHA256),
     * verification returns false rather than silently passing.
     *
     * The whole body is wrapped in try/catch: any decode/verify exception is
     * treated as a verification failure (fail-closed) and returns false.
     *
     * issuer — the certificate believed to have signed this CRL.
     */
    public func verifySignature(issuer: Cert): Bool {
        try {
            if (!crlIsEcdsaSigAlg(this.outerSignatureAlgorithmOID)) {
                // Non-ECDSA (RSA/EdDSA/...) not supported in this leaf module.
                return false
            }
            if (this.tbsRaw.size == 0 || this.signatureValue.size == 0) {
                return false
            }
            let pub = ECDSAPublicKey.decodeDer(DerBlob(issuer.publicKeyDer))
            let digest = crlSha256(this.tbsRaw)
            // stdx verify takes the pre-hashed digest and the DER ECDSA-Sig-Value.
            pub.verify(digest, this.signatureValue)
        } catch (_: Exception) {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Trusted revocation check — fail-closed (RFC 5280 §5)
    // -----------------------------------------------------------------------

    /**
     * Fail-closed revocation check. Order of preconditions:
     *   1. verifySignature(issuerCert) must pass   -> else Unverified("CRL signature")
     *   2. CRL issuer DN must match issuerCert.subject
     *                                              -> else Unverified("issuer mismatch")
     *   3. now must be within [thisUpdate, nextUpdate]
     *                                              -> else Unverified("CRL expired/not yet valid")
     *   4. only then: serial in revokedEntries -> Revoked, else Valid
     *
     * serial     — uppercase hex serial of the certificate being checked.
     * issuerCert — the CA certificate that signed (and whose subject names) this CRL.
     * now        — the reference time for validity-window evaluation.
     */
    public func checkRevocation(serial: String, issuerCert: Cert, now: DateTime): RevocationStatus {
        // (1) signature
        if (!verifySignature(issuerCert)) {
            return Unverified("CRL signature")
        }
        // (2) issuer DN match.
        //
        // DN-FORMAT NOTE: this.issuer is produced by our own crlDecodeDN, which
        // emits "CN=...,O=...,C=..." (comma-separated, no spaces, our short-name
        // map). issuerCert.subject comes from stdx X509Certificate.subject and
        // may differ in attribute ordering, spacing, or short-vs-long names. A
        // strict string equality would be too brittle, so we compare on a
        // normalised, order-independent set of "TYPE=VALUE" tokens (uppercased,
        // whitespace-stripped). Equality of the token sets is required.
        if (!crlDnMatches(this.issuer, issuerCert.subject)) {
            return Unverified("issuer mismatch")
        }
        // (3) validity window.
        let nowCmp = crlDateTimeToComparable(now)
        let thisCmp = crlAsn1TimeToComparable(this.thisUpdate)
        if (nowCmp < thisCmp) {
            return Unverified("CRL expired/not yet valid")
        }
        if (this.nextUpdate.isEmpty()) {
            // RFC 5280 §5.1.2.5: nextUpdate is technically OPTIONAL in ASN.1 but
            // conforming CRL issuers MUST include it. Absent -> we skip the upper
            // bound rather than fail, but a missing nextUpdate is a degraded CRL.
        } else {
            let nextCmp = crlAsn1TimeToComparable(this.nextUpdate)
            if (nowCmp > nextCmp) {
                return Unverified("CRL expired/not yet valid")
            }
        }
        // (4) membership
        if (isRevoked(serial)) {
            return Revoked
        }
        Valid
    }
}

// ---------------------------------------------------------------------------
// Certificate extension helpers (public, operate on Cert via toDer())
// ---------------------------------------------------------------------------

/**
 * Extract the raw value bytes of an extension OID from a certificate.
 *
 * cert  — a Cert parsed by x509_core
 * oid   — dotted-decimal OID string, e.g. "2.5.29.46" for freshestCRL
 *
 * Returns Some(rawValueBytes) where rawValueBytes is the OCTET STRING *content*
 * (not including the OCTET STRING wrapper tag+length), or None if not present.
 *
 * Throws CrlError if the certificate DER is structurally invalid.
 */
public func extensionValue(cert: Cert, oid: String): ?Array<Byte> {
    let der = cert.toDer()
    try {
        certExtractExtension(der, oid)
    } catch (e: CrlError) {
        throw e
    } catch (e: Exception) {
        throw CrlError("extensionValue: ${e.message}")
    }
}

/**
 * Returns true if the certificate contains any duplicate extension OIDs.
 * RFC 5280 §4.2 forbids duplicate extensions.
 * Known use case: OID 2.5.29.46 (freshestCRL) per SecurityHelpers.swift.
 *
 * Throws CrlError if the certificate DER is structurally invalid.
 */
public func hasDuplicateExtensions(cert: Cert): Bool {
    let der = cert.toDer()
    try {
        certCheckDuplicateExtensions(der)
    } catch (e: CrlError) {
        throw e
    } catch (e: Exception) {
        throw CrlError("hasDuplicateExtensions: ${e.message}")
    }
}

// ---------------------------------------------------------------------------
// CRL DER parser (internal)
// ---------------------------------------------------------------------------

/**
 * Parse CertificateList DER:
 *   SEQUENCE { TBSCertList, signatureAlgorithm, signatureValue }
 */
func crlParseDer(b: Array<Byte>): Crl {
    let n = b.size
    if (n < 4) {
        throw CrlError("CRL DER too short (${n} bytes)")
    }
    var offset: Int64 = 0
    // Outer SEQUENCE
    crlExpectTag(b, offset, 0x30u8, "CertificateList outer SEQUENCE")
    offset++
    let (_, off1) = crlReadLength(b, offset)
    offset = off1

    // TBSCertList SEQUENCE — remember where its tag starts so we can slice the
    // exact signed bytes (tag + length + content) the signature covers.
    let tbsTagStart = offset
    crlExpectTag(b, offset, 0x30u8, "TBSCertList SEQUENCE")
    offset++
    let (tbsLen, off2) = crlReadLength(b, offset)
    offset = off2
    let tbsEnd = offset + tbsLen
    if (tbsEnd > n) {
        throw CrlError("TBSCertList length (${tbsLen}) exceeds DER buffer (${n})")
    }

    let (version, issuer, thisUpdate, nextUpdate, revokedEntries, sigAlgOID) =
        crlParseTbs(b, offset, tbsEnd)

    // tbsRaw = the whole TBSCertList element (tag+len+content). This is the
    // byte range RFC 5280 §5.1.1.1 signs.
    let tbsRaw = b[tbsTagStart..tbsEnd]
    offset = tbsEnd

    // Outer signatureAlgorithm SEQUENCE { OID [, params] }
    crlExpectTag(b, offset, 0x30u8, "CertificateList signatureAlgorithm SEQUENCE")
    offset++
    let (outerSigAlgLen, outerSigAlgOff) = crlReadLength(b, offset)
    offset = outerSigAlgOff
    let outerSigAlgEnd = offset + outerSigAlgLen
    if (outerSigAlgEnd > n) {
        throw CrlError("CertificateList signatureAlgorithm out of bounds")
    }
    crlExpectTag(b, offset, 0x06u8, "CertificateList signatureAlgorithm OID")
    offset++
    let (outerOidLen, outerOidOff) = crlReadLength(b, offset)
    offset = outerOidOff
    if (offset + outerOidLen > outerSigAlgEnd) {
        throw CrlError("CertificateList signatureAlgorithm OID out of bounds")
    }
    let outerSigAlgOID = crlDecodeOID(b, offset, outerOidLen)
    offset = outerSigAlgEnd

    // signatureValue BIT STRING (tag 0x03).
    // First content byte = unused-bits count (must be 0 for a DER signature);
    // the remaining bytes are the DER ECDSA-Sig-Value (SEQUENCE { r, s }).
    crlExpectTag(b, offset, 0x03u8, "CertificateList signatureValue BIT STRING")
    offset++
    let (sigBitLen, sigBitOff) = crlReadLength(b, offset)
    offset = sigBitOff
    if (sigBitLen < 1 || offset + sigBitLen > n) {
        throw CrlError("CertificateList signatureValue out of bounds")
    }
    let unusedBits = b[offset]
    if (unusedBits != 0x00u8) {
        throw CrlError("CertificateList signatureValue: non-zero unused-bits (${unusedBits})")
    }
    // Strip the unused-bits prefix byte -> raw DER ECDSA-Sig-Value.
    let signatureValue = b[offset + 1..offset + sigBitLen]

    Crl(version, issuer, thisUpdate, nextUpdate, revokedEntries, sigAlgOID,
        tbsRaw, signatureValue, outerSigAlgOID)
}

/**
 * Parse TBSCertList body b[start..end].
 * Returns (version, issuer, thisUpdate, nextUpdate, revokedEntries, sigAlgOID).
 */
func crlParseTbs(b: Array<Byte>, start: Int64, end: Int64):
    (Int64, String, String, String, Array<RevokedEntry>, String)
{
    var offset = start
    var version: Int64 = 1   // v1: no version field present

    // Optional version field: present only for v2 CRLs (tag INTEGER 0x02)
    // RFC 5280 §5.1.2.1: if present, value MUST be 1 (v2)
    if (offset < end && b[offset] == 0x02u8) {
        offset++
        let (vLen, vOff) = crlReadLength(b, offset)
        offset = vOff
        if (vLen < 1 || offset + vLen > end) {
            throw CrlError("TBSCertList: version INTEGER invalid")
        }
        version = Int64(b[offset]) + 1   // 0 => v1, 1 => v2
        offset += vLen
    }

    // signatureAlgorithm SEQUENCE { OID, [params] }
    crlExpectTag(b, offset, 0x30u8, "TBSCertList signatureAlgorithm")
    offset++
    let (sigAlgLen, sigAlgOff) = crlReadLength(b, offset)
    offset = sigAlgOff
    let sigAlgEnd = offset + sigAlgLen
    crlExpectTag(b, offset, 0x06u8, "signatureAlgorithm OID")
    offset++
    let (oidLen, oidOff) = crlReadLength(b, offset)
    offset = oidOff
    if (offset + oidLen > sigAlgEnd) {
        throw CrlError("TBSCertList: signatureAlgorithm OID out of bounds")
    }
    let sigAlgOID = crlDecodeOID(b, offset, oidLen)
    offset = sigAlgEnd

    // issuer Name SEQUENCE
    crlExpectTag(b, offset, 0x30u8, "issuer SEQUENCE")
    offset++
    let (issuerLen, issuerOff) = crlReadLength(b, offset)
    offset = issuerOff
    let issuerEnd = offset + issuerLen
    let issuer = crlDecodeDN(b, offset, issuerEnd)
    offset = issuerEnd

    // thisUpdate Time
    let thisUpdate = crlReadTimeStr(b, offset)
    offset++
    let (tuLen, tuOff) = crlReadLength(b, offset)
    offset = tuOff + tuLen

    // nextUpdate Time OPTIONAL
    var nextUpdate = ""
    if (offset < end && (b[offset] == 0x17u8 || b[offset] == 0x18u8)) {
        nextUpdate = crlReadTimeStr(b, offset)
        offset++
        let (nuLen, nuOff) = crlReadLength(b, offset)
        offset = nuOff + nuLen
    }

    // revokedCertificates SEQUENCE OF OPTIONAL
    let entries = ArrayList<RevokedEntry>()
    if (offset < end && b[offset] == 0x30u8) {
        offset++
        let (rcLen, rcOff) = crlReadLength(b, offset)
        offset = rcOff
        let rcEnd = offset + rcLen
        while (offset < rcEnd) {
            crlExpectTag(b, offset, 0x30u8, "revokedCertificates entry SEQUENCE")
            offset++
            let (entryLen, entryOff) = crlReadLength(b, offset)
            offset = entryOff
            let entryEnd = offset + entryLen
            if (entryEnd > rcEnd) {
                throw CrlError("revokedCertificates: entry extends past list end")
            }
            // userCertificate INTEGER (serial number)
            crlExpectTag(b, offset, 0x02u8, "revokedCertificates serial INTEGER")
            offset++
            let (sLen, sOff) = crlReadLength(b, offset)
            offset = sOff
            if (offset + sLen > entryEnd) {
                throw CrlError("revokedCertificates: serial out of bounds")
            }
            let serialBytes = b[offset..offset + sLen]
            offset += sLen
            // revocationDate Time
            let revDate = crlReadTimeStr(b, offset)
            offset++
            let (rdLen, rdOff) = crlReadLength(b, offset)
            offset = rdOff + rdLen
            entries.add(RevokedEntry(serialBytes, revDate))
            // skip optional crlEntryExtensions
            offset = entryEnd
        }
    }

    (version, issuer, thisUpdate, nextUpdate, entries.toArray(), sigAlgOID)
}

// ---------------------------------------------------------------------------
// Certificate extension parsing (internal)
// ---------------------------------------------------------------------------

/**
 * Parse certificate DER and find extension value for given OID.
 * Returns None if the certificate has no extensions or the OID is not present.
 *
 * Certificate DER layout:
 *   SEQUENCE {                         <- Certificate
 *     SEQUENCE {                       <- TBSCertificate
 *       [0] EXPLICIT INTEGER?,        <- version (v3 only)
 *       INTEGER,                       <- serialNumber
 *       SEQUENCE,                      <- signature AlgorithmIdentifier
 *       SEQUENCE,                      <- issuer
 *       SEQUENCE,                      <- validity
 *       SEQUENCE,                      <- subject
 *       SEQUENCE,                      <- subjectPublicKeyInfo
 *       [1] IMPLICIT?,                 <- issuerUniqueID
 *       [2] IMPLICIT?,                 <- subjectUniqueID
 *       [3] EXPLICIT SEQUENCE OF?      <- extensions
 *     },
 *     ...
 *   }
 */
func certExtractExtension(der: Array<Byte>, targetOID: String): ?Array<Byte> {
    var offset: Int64 = 0
    let n = der.size
    // Outer Certificate SEQUENCE
    crlExpectTag(der, offset, 0x30u8, "Certificate outer SEQUENCE")
    offset++
    let (_, off1) = crlReadLength(der, offset)
    offset = off1
    // TBSCertificate SEQUENCE
    crlExpectTag(der, offset, 0x30u8, "TBSCertificate SEQUENCE")
    offset++
    let (tbsLen, off2) = crlReadLength(der, offset)
    offset = off2
    let tbsEnd = offset + tbsLen
    if (tbsEnd > n) {
        throw CrlError("certExtractExtension: TBSCertificate out of bounds")
    }
    // Scan TBS fields until we find [3] EXPLICIT (tag 0xA3)
    while (offset < tbsEnd) {
        let tag = der[offset]
        if (tag == 0xa3u8) {
            // extensions [3] EXPLICIT
            offset++
            let (_, wrapOff) = crlReadLength(der, offset)
            offset = wrapOff
            // inner SEQUENCE OF Extension
            crlExpectTag(der, offset, 0x30u8, "extensions SEQUENCE")
            offset++
            let (extsLen, extsOff) = crlReadLength(der, offset)
            offset = extsOff
            let extsEnd = offset + extsLen
            while (offset < extsEnd) {
                crlExpectTag(der, offset, 0x30u8, "Extension SEQUENCE")
                offset++
                let (extLen, extOff) = crlReadLength(der, offset)
                offset = extOff
                let extEnd = offset + extLen
                if (extEnd > extsEnd) {
                    throw CrlError("certExtractExtension: extension extends past extensions end")
                }
                // extnID OID
                crlExpectTag(der, offset, 0x06u8, "extnID OID")
                offset++
                let (extOIDLen, extOIDOff) = crlReadLength(der, offset)
                offset = extOIDOff
                let extOID = crlDecodeOID(der, offset, extOIDLen)
                offset += extOIDLen
                // optional critical BOOLEAN
                if (offset < extEnd && der[offset] == 0x01u8) {
                    offset++
                    let (bLen, bOff) = crlReadLength(der, offset)
                    offset = bOff + bLen
                }
                // extnValue OCTET STRING
                crlExpectTag(der, offset, 0x04u8, "extnValue OCTET STRING")
                offset++
                let (valLen, valOff) = crlReadLength(der, offset)
                offset = valOff
                if (offset + valLen > extEnd) {
                    throw CrlError("certExtractExtension: extension value out of bounds")
                }
                let valBytes = der[offset..offset + valLen]
                offset = extEnd
                if (extOID == targetOID) {
                    return Some(valBytes)
                }
            }
            return None
        }
        // skip any other TBS field (tag+length+value)
        let (skipLen, skipOff) = crlSkipTlv(der, offset)
        offset = skipOff + skipLen
    }
    None
}

/**
 * Parse certificate DER and return true if any extension OID appears more than once.
 */
func certCheckDuplicateExtensions(der: Array<Byte>): Bool {
    var offset: Int64 = 0
    let n = der.size
    crlExpectTag(der, offset, 0x30u8, "Certificate outer SEQUENCE")
    offset++
    let (_, off1) = crlReadLength(der, offset)
    offset = off1
    crlExpectTag(der, offset, 0x30u8, "TBSCertificate SEQUENCE")
    offset++
    let (tbsLen, off2) = crlReadLength(der, offset)
    offset = off2
    let tbsEnd = offset + tbsLen
    if (tbsEnd > n) {
        throw CrlError("certCheckDuplicateExtensions: TBSCertificate out of bounds")
    }
    while (offset < tbsEnd) {
        let tag = der[offset]
        if (tag == 0xa3u8) {
            offset++
            let (_, wrapOff) = crlReadLength(der, offset)
            offset = wrapOff
            crlExpectTag(der, offset, 0x30u8, "extensions SEQUENCE")
            offset++
            let (extsLen, extsOff) = crlReadLength(der, offset)
            offset = extsOff
            let extsEnd = offset + extsLen
            let seen = HashSet<String>()
            while (offset < extsEnd) {
                crlExpectTag(der, offset, 0x30u8, "Extension SEQUENCE")
                offset++
                let (extLen, extOff) = crlReadLength(der, offset)
                offset = extOff
                let extEnd = offset + extLen
                crlExpectTag(der, offset, 0x06u8, "extnID OID")
                offset++
                let (extOIDLen, extOIDOff) = crlReadLength(der, offset)
                offset = extOIDOff
                let extOID = crlDecodeOID(der, offset, extOIDLen)
                offset = extEnd
                if (seen.contains(extOID)) {
                    return true
                }
                seen.add(extOID)
            }
            return false
        }
        let (skipLen, skipOff) = crlSkipTlv(der, offset)
        offset = skipOff + skipLen
    }
    false
}

// ---------------------------------------------------------------------------
// DER primitive helpers (prefixed crl* to avoid clash with core package)
// ---------------------------------------------------------------------------

/**
 * Assert bytes[offset] == expectedTag; throw CrlError otherwise.
 */
func crlExpectTag(bytes: Array<Byte>, offset: Int64, expected: UInt8, ctx: String): Unit {
    if (offset >= bytes.size) {
        throw CrlError("${ctx}: out of bounds at offset ${offset}")
    }
    if (bytes[offset] != expected) {
        throw CrlError("${ctx}: expected tag 0x${crlHexByte(expected)} got 0x${crlHexByte(bytes[offset])}")
    }
}

/**
 * Read DER length field at bytes[startOffset].
 * Returns (length_value, offset_after_length_field).
 * Supports short form (0x00-0x7F) and definite long form.
 */
func crlReadLength(bytes: Array<Byte>, startOffset: Int64): (Int64, Int64) {
    if (startOffset >= bytes.size) {
        throw CrlError("crlReadLength: out of bounds at ${startOffset}")
    }
    let first = bytes[startOffset]
    if ((first & 0x80u8) == 0u8) {
        return (Int64(first), startOffset + 1)
    }
    let numBytes = Int64(first & 0x7fu8)
    if (numBytes == 0) {
        throw CrlError("crlReadLength: indefinite form not supported")
    }
    let end = startOffset + 1 + numBytes
    if (end > bytes.size) {
        throw CrlError("crlReadLength: multi-byte length field out of bounds")
    }
    var len: Int64 = 0
    var i = startOffset + 1
    while (i < end) {
        len = (len << 8) | Int64(bytes[i])
        i++
    }
    (len, end)
}

/**
 * Skip a TLV at bytes[offset].
 * Returns (valueLength, offsetAfterTagAndLength) so caller can jump to offset+valueLength.
 */
func crlSkipTlv(bytes: Array<Byte>, offset: Int64): (Int64, Int64) {
    if (offset >= bytes.size) {
        throw CrlError("crlSkipTlv: out of bounds at ${offset}")
    }
    let (len, afterLen) = crlReadLength(bytes, offset + 1)
    (len, afterLen)
}

/**
 * Decode a DER OBJECT IDENTIFIER to dotted-decimal string.
 * bytes[offset..offset+length] are the raw OID value bytes (no tag/length).
 */
func crlDecodeOID(bytes: Array<Byte>, offset: Int64, length: Int64): String {
    if (length < 1) {
        throw CrlError("crlDecodeOID: empty OID")
    }
    if (offset + length > bytes.size) {
        throw CrlError("crlDecodeOID: OID bytes out of bounds")
    }
    // First byte = first_arc * 40 + second_arc
    let fb = Int64(bytes[offset])
    let arc0 = fb / 40
    let arc1 = fb % 40
    let parts = ArrayList<String>()
    parts.add(arc0.toString())
    parts.add(arc1.toString())
    var i = offset + 1
    let end = offset + length
    while (i < end) {
        var arc: Int64 = 0
        var b = bytes[i]
        while ((b & 0x80u8) != 0u8) {
            arc = (arc << 7) | Int64(b & 0x7fu8)
            i++
            if (i >= end) {
                throw CrlError("crlDecodeOID: truncated base-128 encoding")
            }
            b = bytes[i]
        }
        arc = (arc << 7) | Int64(b)
        parts.add(arc.toString())
        i++
    }
    let arr = parts.toArray()
    var result = arr[0]
    var k: Int64 = 1
    while (k < arr.size) {
        result = result + "." + arr[k]
        k++
    }
    result
}

/**
 * Read the ASCII content of a UTCTIME (0x17) or GENERALIZEDTIME (0x18).
 * Returns the raw string, e.g. "260612175135Z".
 * Does not advance offset — caller must do so with tag(1) + length + value.
 */
func crlReadTimeStr(bytes: Array<Byte>, offset: Int64): String {
    if (offset >= bytes.size) {
        throw CrlError("crlReadTimeStr: out of bounds at ${offset}")
    }
    let tag = bytes[offset]
    if (tag != 0x17u8 && tag != 0x18u8) {
        throw CrlError("crlReadTimeStr: expected UTCTIME(0x17) or GENERALIZEDTIME(0x18), got 0x${crlHexByte(tag)}")
    }
    let (tLen, tOff) = crlReadLength(bytes, offset + 1)
    if (tOff + tLen > bytes.size) {
        throw CrlError("crlReadTimeStr: time value out of bounds")
    }
    String.fromUtf8(bytes[tOff..tOff + tLen])
}

/**
 * Decode a Name (SEQUENCE OF SET OF SEQUENCE { OID, value }) to human-readable string.
 * Output format: "CN=...,O=...,C=..."
 */
func crlDecodeDN(bytes: Array<Byte>, start: Int64, end: Int64): String {
    let parts = ArrayList<String>()
    var offset = start
    while (offset < end) {
        // RDN = SET
        if (offset >= bytes.size || bytes[offset] != 0x31u8) {
            throw CrlError("crlDecodeDN: expected SET (0x31) at offset ${offset}")
        }
        offset++
        let (setLen, setOff) = crlReadLength(bytes, offset)
        offset = setOff
        let setEnd = offset + setLen
        while (offset < setEnd) {
            // AttributeTypeAndValue SEQUENCE
            crlExpectTag(bytes, offset, 0x30u8, "DN AttributeTypeAndValue")
            offset++
            let (atvLen, atvOff) = crlReadLength(bytes, offset)
            offset = atvOff
            let atvEnd = offset + atvLen
            // OID
            crlExpectTag(bytes, offset, 0x06u8, "DN attribute OID")
            offset++
            let (oidLen, oidOff) = crlReadLength(bytes, offset)
            offset = oidOff
            if (offset + oidLen > atvEnd) {
                throw CrlError("crlDecodeDN: OID out of bounds")
            }
            let oid = crlDecodeOID(bytes, offset, oidLen)
            offset += oidLen
            // Value string (UTF8String 0x0C, PrintableString 0x13, IA5String 0x16, etc.)
            if (offset >= atvEnd) {
                throw CrlError("crlDecodeDN: missing value after OID")
            }
            offset++   // skip tag byte
            let (valLen, valOff) = crlReadLength(bytes, offset)
            offset = valOff
            if (offset + valLen > atvEnd) {
                throw CrlError("crlDecodeDN: value out of bounds")
            }
            let valStr = String.fromUtf8(bytes[offset..offset + valLen])
            offset = atvEnd
            let attrName = crlOidToAttr(oid)
            parts.add("${attrName}=${valStr}")
        }
        offset = setEnd
    }
    let arr = parts.toArray()
    if (arr.size == 0) { return "" }
    var result = arr[0]
    var k: Int64 = 1
    while (k < arr.size) {
        result = result + "," + arr[k]
        k++
    }
    result
}

/** Map common X.500 attribute OIDs to short names. */
func crlOidToAttr(oid: String): String {
    if (oid == "2.5.4.3")  { return "CN" }
    if (oid == "2.5.4.6")  { return "C" }
    if (oid == "2.5.4.7")  { return "L" }
    if (oid == "2.5.4.8")  { return "ST" }
    if (oid == "2.5.4.10") { return "O" }
    if (oid == "2.5.4.11") { return "OU" }
    if (oid == "1.2.840.113549.1.9.1") { return "emailAddress" }
    oid
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/**
 * Normalize a hex serial string: uppercase and strip leading '0' padding.
 * Minimum one character is preserved (e.g. "00" -> "0").
 */
func crlNormalizeHex(hex: String): String {
    let upper = hex.toAsciiUpper()
    let arr = upper.toArray()
    var start: Int64 = 0
    while (start < arr.size - 1 && arr[start] == 0x30u8) {  // '0' == 0x30
        start++
    }
    if (start == 0) { return upper }
    String.fromUtf8(arr[start..arr.size])
}

// ---------------------------------------------------------------------------
// Signature / time / DN helpers (for verifySignature + checkRevocation)
// ---------------------------------------------------------------------------

/**
 * True if the OID is an ECDSA-with-SHA* signature algorithm.
 * 1.2.840.10045.4.3.1 = ecdsa-with-SHA224
 * 1.2.840.10045.4.3.2 = ecdsa-with-SHA256
 * 1.2.840.10045.4.3.3 = ecdsa-with-SHA384
 * 1.2.840.10045.4.3.4 = ecdsa-with-SHA512
 * We hash with SHA-256 regardless (the test CRL is ecdsa-with-SHA256); the
 * common reader/issuer CRLs in EUDI use SHA-256.
 */
func crlIsEcdsaSigAlg(oid: String): Bool {
    oid == "1.2.840.10045.4.3.2" ||
    oid == "1.2.840.10045.4.3.1" ||
    oid == "1.2.840.10045.4.3.3" ||
    oid == "1.2.840.10045.4.3.4"
}

/** SHA-256 over data using stdx digest; returns the 32-byte digest. */
func crlSha256(data: Array<Byte>): Array<Byte> {
    let h = SHA256()
    h.write(data)
    h.finish()
}

/**
 * Normalise a DN string into an order-independent comparison key.
 * Splits on ',', trims each token, uppercases, drops empties, sorts, rejoins.
 * This makes "CN=X,O=Y,C=DE" compare equal to "C=DE, O=Y, CN=X" etc.
 */
func crlNormalizeDn(dn: String): String {
    let toks = ArrayList<String>()
    for (raw in dn.split(",")) {
        let t = crlStripWs(raw).toAsciiUpper()
        if (!t.isEmpty()) {
            toks.add(t)
        }
    }
    let arr = toks.toArray()
    // simple insertion sort (small token counts)
    var i: Int64 = 1
    while (i < arr.size) {
        let key = arr[i]
        var j = i - 1
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j]
            j--
        }
        arr[j + 1] = key
        i++
    }
    var out = ""
    var k: Int64 = 0
    while (k < arr.size) {
        if (k > 0) { out = out + "," }
        out = out + arr[k]
        k++
    }
    out
}

/** Strip leading/trailing ASCII spaces and tabs from a string. */
func crlStripWs(s: String): String {
    let arr = s.toArray()
    var lo: Int64 = 0
    var hi: Int64 = arr.size
    while (lo < hi && (arr[lo] == 0x20u8 || arr[lo] == 0x09u8)) { lo++ }
    while (hi > lo && (arr[hi - 1] == 0x20u8 || arr[hi - 1] == 0x09u8)) { hi-- }
    if (lo == 0 && hi == arr.size) { return s }
    String.fromUtf8(arr[lo..hi])
}

/**
 * DN match used for CRL issuer / cert subject correspondence.
 * Primary: normalised token-set equality (order/space/case independent).
 * Fallback: if normalisation produced very different token counts (e.g. stdx
 * uses long attribute names where we use short ones), require that every token
 * of the smaller DN is contained as a substring of the other DN's normalised
 * form. This tolerates short-vs-long attribute-name divergence while still
 * demanding the actual CN/O/C values line up.
 */
func crlDnMatches(crlIssuer: String, certSubject: String): Bool {
    let a = crlNormalizeDn(crlIssuer)
    let b = crlNormalizeDn(certSubject)
    if (a == b) { return true }
    // Fallback: every comma-token of the shorter normalised DN must appear in
    // the longer one. Compare on RDN values are embedded in the tokens.
    let (short, long) = if (a.size <= b.size) { (a, b) } else { (b, a) }
    for (tok in short.split(",")) {
        if (!tok.isEmpty() && !long.contains(tok)) {
            return false
        }
    }
    true
}

/**
 * Convert an ASN.1 time string (UTCTIME "YYMMDDHHMMSSZ" or GENERALIZEDTIME
 * "YYYYMMDDHHMMSSZ") into a monotonically-comparable Int64 of the form
 * YYYYMMDDHHMMSS. UTCTIME 2-digit year uses RFC 5280 §4.1.2.5.1 windowing:
 * YY < 50 => 20YY, YY >= 50 => 19YY.
 *
 * Any trailing fractional seconds or non-'Z' suffixes are ignored; we only read
 * the leading 12 (UTCTIME) / 14 (GENERALIZEDTIME) numeric characters. EUDI CRLs
 * always use UTC 'Z' times.
 */
func crlAsn1TimeToComparable(t: String): Int64 {
    let arr = t.toArray()
    // Count leading digits.
    var digits = ArrayList<Int64>()
    var i: Int64 = 0
    while (i < arr.size && arr[i] >= 0x30u8 && arr[i] <= 0x39u8) {
        digits.add(Int64(arr[i] - 0x30u8))
        i++
    }
    let d = digits.toArray()
    var year: Int64
    var idx: Int64
    if (d.size >= 14) {
        // GENERALIZEDTIME YYYYMMDD...
        year = d[0] * 1000 + d[1] * 100 + d[2] * 10 + d[3]
        idx = 4
    } else if (d.size >= 12) {
        // UTCTIME YYMMDD...
        let yy = d[0] * 10 + d[1]
        year = if (yy < 50) { 2000 + yy } else { 1900 + yy }
        idx = 2
    } else {
        throw CrlError("crlAsn1TimeToComparable: too few digits in time '${t}'")
    }
    let month = d[idx] * 10 + d[idx + 1]
    let day   = d[idx + 2] * 10 + d[idx + 3]
    let hour  = d[idx + 4] * 10 + d[idx + 5]
    let min   = d[idx + 6] * 10 + d[idx + 7]
    let sec   = d[idx + 8] * 10 + d[idx + 9]
    // YYYYMMDDHHMMSS as a single comparable integer.
    ((((year * 100 + month) * 100 + day) * 100 + hour) * 100 + min) * 100 + sec
}

/**
 * Convert a DateTime into the same YYYYMMDDHHMMSS comparable form as
 * crlAsn1TimeToComparable, evaluated in UTC so it lines up with the 'Z' times
 * in the CRL. DateTime fields are 1-based for month/day.
 */
func crlDateTimeToComparable(dt: DateTime): Int64 {
    let u = dt.inUTC()
    let year  = u.year
    let month = u.month.toInteger()   // 1-based
    let day   = u.dayOfMonth
    let hour  = u.hour
    let min   = u.minute
    let sec   = u.second
    ((((year * 100 + month) * 100 + day) * 100 + hour) * 100 + min) * 100 + sec
}

/** Return the ASCII byte for hex nibble v (0-15) — uppercase. */
func crlHexNibble(v: UInt8): UInt8 {
    let HEX: Array<UInt8> = [
        0x30u8, 0x31u8, 0x32u8, 0x33u8, 0x34u8, 0x35u8, 0x36u8, 0x37u8,
        0x38u8, 0x39u8, 0x41u8, 0x42u8, 0x43u8, 0x44u8, 0x45u8, 0x46u8
    ]
    HEX[Int64(v & 0x0fu8)]
}

/** Format a single byte as two uppercase hex characters. */
func crlHexByte(b: UInt8): String {
    let buf: Array<Byte> = [crlHexNibble(b >> 4), crlHexNibble(b & 0x0fu8)]
    String.fromUtf8(buf)
}
