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
 * Package: ohos_app_cangjie_eudi_cjx509.x509.core
 *
 * Certificate extension accessors needed for mdoc reader-auth (ISO 18013-5)
 * and RFC 5280 §4.2 trust decisions. All parsing is self-contained minimal DER
 * (the x509 module stays a stdx-only leaf — no core-crypto).
 *
 * Public API:
 *   extendedKeyUsageOids(cert)         — OIDs in the EKU extension (2.5.29.37)
 *   hasExtendedKeyUsage(cert, oid)     — membership test on the above
 *   hasKeyUsageDigitalSignature(cert)  — keyUsage (2.5.29.15) digitalSignature bit
 *   criticalExtensionOids(cert)        — OIDs of extensions marked critical
 *
 * Extension raw-value extraction is implemented locally here (extExtensionValue)
 * rather than importing the sibling x509.crl package's extensionValue(): the crl
 * package already depends on this core package (for Cert), so importing back
 * would create a package import cycle. The DER walk is the same minimal logic.
 */
package ohos_app_cangjie_eudi_cjx509.x509.core

import std.collection.{ArrayList}

// ---------------------------------------------------------------------------
// Extended Key Usage (RFC 5280 §4.2.1.12, OID 2.5.29.37)
// ---------------------------------------------------------------------------

/** OID of the ExtendedKeyUsage extension. */
let EXT_EKU_OID: String = "2.5.29.37"
/** OID of the KeyUsage extension. */
let EXT_KEY_USAGE_OID: String = "2.5.29.15"

/**
 * Return the list of KeyPurposeId OIDs (dotted decimal) in the certificate's
 * ExtendedKeyUsage extension. Empty array if the extension is absent.
 *
 * The EKU extnValue is DER:  SEQUENCE OF OBJECT IDENTIFIER.
 * (mdoc reader-auth KeyPurposeId = 1.0.18013.5.1.6)
 */
public func extendedKeyUsageOids(cert: Cert): Array<String> {
    let raw = match (extExtensionValue(cert, EXT_EKU_OID)) {
        case Some(v) => v
        case None => return Array<String>()
    }
    let out = ArrayList<String>()
    var offset: Int64 = 0
    let n = raw.size
    // Outer SEQUENCE
    if (n == 0 || raw[offset] != 0x30u8) {
        // Not a well-formed SEQUENCE OF — treat as no usable EKU entries.
        return Array<String>()
    }
    offset++
    let (seqLen, seqOff) = extReadLength(raw, offset)
    offset = seqOff
    let seqEnd = offset + seqLen
    if (seqEnd > n) {
        throw CertError("extendedKeyUsageOids: SEQUENCE length out of bounds")
    }
    while (offset < seqEnd) {
        // OBJECT IDENTIFIER (tag 0x06)
        if (raw[offset] != 0x06u8) {
            throw CertError("extendedKeyUsageOids: expected OID tag 0x06 at ${offset}")
        }
        offset++
        let (oidLen, oidOff) = extReadLength(raw, offset)
        offset = oidOff
        if (offset + oidLen > seqEnd) {
            throw CertError("extendedKeyUsageOids: OID out of bounds")
        }
        out.add(extDecodeOID(raw, offset, oidLen))
        offset += oidLen
    }
    out.toArray()
}

/**
 * True if the certificate's ExtendedKeyUsage extension contains the given OID.
 * (mdoc reader-auth EKU = "1.0.18013.5.1.6")
 */
public func hasExtendedKeyUsage(cert: Cert, oid: String): Bool {
    for (o in extendedKeyUsageOids(cert)) {
        if (o == oid) { return true }
    }
    false
}

// ---------------------------------------------------------------------------
// Key Usage (RFC 5280 §4.2.1.3, OID 2.5.29.15)
// ---------------------------------------------------------------------------

/**
 * True if the certificate's KeyUsage extension asserts the digitalSignature bit.
 * Returns false if the KeyUsage extension is absent.
 *
 * KeyUsage extnValue DER:  BIT STRING.
 *   byte[0] = number of unused bits in the final byte
 *   byte[1] = first content byte; bit 0 (digitalSignature) is the MOST
 *             significant bit of that byte (mask 0x80) per RFC 5280 §4.2.1.3.
 */
public func hasKeyUsageDigitalSignature(cert: Cert): Bool {
    let raw = match (extExtensionValue(cert, EXT_KEY_USAGE_OID)) {
        case Some(v) => v
        case None => return false
    }
    var offset: Int64 = 0
    let n = raw.size
    if (n == 0 || raw[offset] != 0x03u8) {
        // Not a BIT STRING — cannot assert digitalSignature.
        return false
    }
    offset++
    let (bitLen, bitOff) = extReadLength(raw, offset)
    offset = bitOff
    if (bitLen < 2 || offset + bitLen > n) {
        // Need at least unused-bits byte + 1 content byte.
        return false
    }
    // offset -> unused-bits byte; offset+1 -> first content byte.
    let firstContent = raw[offset + 1]
    (firstContent & 0x80u8) != 0u8
}

// ---------------------------------------------------------------------------
// Critical extension OIDs (RFC 5280 §4.2)
// ---------------------------------------------------------------------------

/**
 * Return the OIDs (dotted decimal) of all extensions marked critical (the
 * critical BOOLEAN present and TRUE). Empty array if the certificate has no
 * extensions or none are critical.
 *
 * Walks the TBSCertificate to the [3] EXPLICIT extensions wrapper, then each
 * Extension SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue }.
 * A critical BOOLEAN is encoded as 0x01 0x01 0xFF; absent => DEFAULT FALSE.
 */
public func criticalExtensionOids(cert: Cert): Array<String> {
    let der = cert.toDer()
    try {
        certCriticalExtensionOids(der)
    } catch (e: CertError) {
        throw e
    } catch (e: Exception) {
        throw CertError("criticalExtensionOids: ${e.message}")
    }
}

/**
 * Return the first subject distinguished-name value for `targetOID`.
 *
 * `X509Certificate.subject.toString()` omits attributes it does not know how
 * to render (notably organizationIdentifier, OID 2.5.4.97).  Consumers that
 * make security decisions must therefore inspect the encoded Name instead of
 * parsing that lossy display string.
 */
public func subjectAttributeValue(cert: Cert, targetOID: String): ?String {
    try {
        return certSubjectAttributeValue(cert.toDer(), targetOID)
    } catch (e: CertError) {
        throw e
    } catch (e: Exception) {
        throw CertError("subjectAttributeValue: ${e.message}")
    }
}

func certSubjectAttributeValue(der: Array<Byte>, targetOID: String): ?String {
    var offset: Int64 = 0
    let n = der.size
    if (n == 0 || der[offset] != 0x30u8) {
        throw CertError("subjectAttributeValue: expected Certificate SEQUENCE")
    }
    offset++
    let (_, outerOff) = extReadLength(der, offset)
    offset = outerOff
    if (offset >= n || der[offset] != 0x30u8) {
        throw CertError("subjectAttributeValue: expected TBSCertificate SEQUENCE")
    }
    offset++
    let (tbsLen, tbsOff) = extReadLength(der, offset)
    offset = tbsOff
    let tbsEnd = offset + tbsLen
    if (tbsEnd > n) {
        throw CertError("subjectAttributeValue: TBSCertificate out of bounds")
    }

    // version [0] EXPLICIT is optional. Then skip serialNumber, signature,
    // issuer and validity to reach subject.
    if (offset < tbsEnd && der[offset] == 0xa0u8) {
        let (len, valueOff) = extSkipTlv(der, offset)
        offset = valueOff + len
    }
    var fieldsToSkip: Int64 = 4
    while (fieldsToSkip > 0) {
        let (len, valueOff) = extSkipTlv(der, offset)
        offset = valueOff + len
        fieldsToSkip--
    }

    if (offset >= tbsEnd || der[offset] != 0x30u8) {
        throw CertError("subjectAttributeValue: expected subject Name SEQUENCE")
    }
    offset++
    let (subjectLen, subjectOff) = extReadLength(der, offset)
    offset = subjectOff
    let subjectEnd = offset + subjectLen
    if (subjectEnd > tbsEnd) {
        throw CertError("subjectAttributeValue: subject out of bounds")
    }

    while (offset < subjectEnd) {
        if (der[offset] != 0x31u8) {
            throw CertError("subjectAttributeValue: expected RDN SET")
        }
        offset++
        let (setLen, setOff) = extReadLength(der, offset)
        offset = setOff
        let setEnd = offset + setLen
        if (setEnd > subjectEnd) {
            throw CertError("subjectAttributeValue: RDN SET out of bounds")
        }
        while (offset < setEnd) {
            if (der[offset] != 0x30u8) {
                throw CertError("subjectAttributeValue: expected AttributeTypeAndValue SEQUENCE")
            }
            offset++
            let (atvLen, atvOff) = extReadLength(der, offset)
            offset = atvOff
            let atvEnd = offset + atvLen
            if (atvEnd > setEnd || offset >= atvEnd || der[offset] != 0x06u8) {
                throw CertError("subjectAttributeValue: malformed subject attribute")
            }
            offset++
            let (oidLen, oidOff) = extReadLength(der, offset)
            offset = oidOff
            let oid = extDecodeOID(der, offset, oidLen)
            offset += oidLen
            if (offset >= atvEnd) {
                throw CertError("subjectAttributeValue: missing subject attribute value")
            }
            offset++ // DirectoryString tag
            let (valueLen, valueOff) = extReadLength(der, offset)
            if (valueOff + valueLen > atvEnd) {
                throw CertError("subjectAttributeValue: attribute value out of bounds")
            }
            if (oid == targetOID) {
                return Some(String.fromUtf8(der[valueOff..valueOff + valueLen]))
            }
            offset = atvEnd
        }
        offset = setEnd
    }
    None
}

func certCriticalExtensionOids(der: Array<Byte>): Array<String> {
    let out = ArrayList<String>()
    var offset: Int64 = 0
    let n = der.size
    // Outer Certificate SEQUENCE
    if (n == 0 || der[offset] != 0x30u8) {
        throw CertError("certCriticalExtensionOids: expected Certificate SEQUENCE")
    }
    offset++
    let (_, off1) = extReadLength(der, offset)
    offset = off1
    // TBSCertificate SEQUENCE
    if (offset >= n || der[offset] != 0x30u8) {
        throw CertError("certCriticalExtensionOids: expected TBSCertificate SEQUENCE")
    }
    offset++
    let (tbsLen, off2) = extReadLength(der, offset)
    offset = off2
    let tbsEnd = offset + tbsLen
    if (tbsEnd > n) {
        throw CertError("certCriticalExtensionOids: TBSCertificate out of bounds")
    }
    while (offset < tbsEnd) {
        let tag = der[offset]
        if (tag == 0xa3u8) {
            // extensions [3] EXPLICIT
            offset++
            let (_, wrapOff) = extReadLength(der, offset)
            offset = wrapOff
            if (offset >= tbsEnd || der[offset] != 0x30u8) {
                throw CertError("certCriticalExtensionOids: expected extensions SEQUENCE")
            }
            offset++
            let (extsLen, extsOff) = extReadLength(der, offset)
            offset = extsOff
            let extsEnd = offset + extsLen
            while (offset < extsEnd) {
                if (der[offset] != 0x30u8) {
                    throw CertError("certCriticalExtensionOids: expected Extension SEQUENCE")
                }
                offset++
                let (extLen, extOff) = extReadLength(der, offset)
                offset = extOff
                let extEnd = offset + extLen
                if (extEnd > extsEnd) {
                    throw CertError("certCriticalExtensionOids: extension out of bounds")
                }
                // extnID OID
                if (der[offset] != 0x06u8) {
                    throw CertError("certCriticalExtensionOids: expected extnID OID")
                }
                offset++
                let (oidLen, oidOff) = extReadLength(der, offset)
                offset = oidOff
                let extOID = extDecodeOID(der, offset, oidLen)
                offset += oidLen
                // optional critical BOOLEAN (tag 0x01). DEFAULT FALSE if absent.
                var isCritical = false
                if (offset < extEnd && der[offset] == 0x01u8) {
                    offset++
                    let (bLen, bOff) = extReadLength(der, offset)
                    if (bLen == 1 && bOff < extEnd && der[bOff] != 0x00u8) {
                        isCritical = true
                    }
                    offset = bOff + bLen
                }
                if (isCritical) {
                    out.add(extOID)
                }
                offset = extEnd
            }
            return out.toArray()
        }
        // skip this TBS field
        let (skipLen, skipOff) = extSkipTlv(der, offset)
        offset = skipOff + skipLen
    }
    out.toArray()
}

// ---------------------------------------------------------------------------
// Local extension raw-value extractor (mirrors crl.certExtractExtension; kept
// here to avoid a core<->crl package import cycle)
// ---------------------------------------------------------------------------

/**
 * Return the extnValue OCTET STRING *content* bytes for the given extension OID,
 * or None if the certificate has no extensions or the OID is absent.
 */
func extExtensionValue(cert: Cert, targetOID: String): ?Array<Byte> {
    let der = cert.toDer()
    var offset: Int64 = 0
    let n = der.size
    if (n == 0 || der[offset] != 0x30u8) {
        throw CertError("extExtensionValue: expected Certificate SEQUENCE")
    }
    offset++
    let (_, off1) = extReadLength(der, offset)
    offset = off1
    if (offset >= n || der[offset] != 0x30u8) {
        throw CertError("extExtensionValue: expected TBSCertificate SEQUENCE")
    }
    offset++
    let (tbsLen, off2) = extReadLength(der, offset)
    offset = off2
    let tbsEnd = offset + tbsLen
    if (tbsEnd > n) {
        throw CertError("extExtensionValue: TBSCertificate out of bounds")
    }
    while (offset < tbsEnd) {
        let tag = der[offset]
        if (tag == 0xa3u8) {
            offset++
            let (_, wrapOff) = extReadLength(der, offset)
            offset = wrapOff
            if (offset >= tbsEnd || der[offset] != 0x30u8) {
                throw CertError("extExtensionValue: expected extensions SEQUENCE")
            }
            offset++
            let (extsLen, extsOff) = extReadLength(der, offset)
            offset = extsOff
            let extsEnd = offset + extsLen
            while (offset < extsEnd) {
                if (der[offset] != 0x30u8) {
                    throw CertError("extExtensionValue: expected Extension SEQUENCE")
                }
                offset++
                let (extLen, extOff) = extReadLength(der, offset)
                offset = extOff
                let extEnd = offset + extLen
                if (extEnd > extsEnd) {
                    throw CertError("extExtensionValue: extension out of bounds")
                }
                if (der[offset] != 0x06u8) {
                    throw CertError("extExtensionValue: expected extnID OID")
                }
                offset++
                let (oidLen, oidOff) = extReadLength(der, offset)
                offset = oidOff
                let extOID = extDecodeOID(der, offset, oidLen)
                offset += oidLen
                // optional critical BOOLEAN
                if (offset < extEnd && der[offset] == 0x01u8) {
                    offset++
                    let (bLen, bOff) = extReadLength(der, offset)
                    offset = bOff + bLen
                }
                // extnValue OCTET STRING
                if (der[offset] != 0x04u8) {
                    throw CertError("extExtensionValue: expected extnValue OCTET STRING")
                }
                offset++
                let (valLen, valOff) = extReadLength(der, offset)
                offset = valOff
                if (offset + valLen > extEnd) {
                    throw CertError("extExtensionValue: extension value out of bounds")
                }
                let valBytes = der[offset..offset + valLen]
                offset = extEnd
                if (extOID == targetOID) {
                    return Some(valBytes)
                }
            }
            return None
        }
        let (skipLen, skipOff) = extSkipTlv(der, offset)
        offset = skipOff + skipLen
    }
    None
}

// ---------------------------------------------------------------------------
// Minimal DER helpers (prefixed ext* — local to this file/package)
// ---------------------------------------------------------------------------

/**
 * Read a DER length field at bytes[startOffset].
 * Returns (length_value, offset_after_length_field).
 */
func extReadLength(bytes: Array<Byte>, startOffset: Int64): (Int64, Int64) {
    if (startOffset >= bytes.size) {
        throw CertError("extReadLength: out of bounds at ${startOffset}")
    }
    let first = bytes[startOffset]
    if ((first & 0x80u8) == 0u8) {
        return (Int64(first), startOffset + 1)
    }
    let numBytes = Int64(first & 0x7fu8)
    if (numBytes == 0) {
        throw CertError("extReadLength: indefinite form not supported")
    }
    let end = startOffset + 1 + numBytes
    if (end > bytes.size) {
        throw CertError("extReadLength: multi-byte length out of bounds")
    }
    var len: Int64 = 0
    var i = startOffset + 1
    while (i < end) {
        len = (len << 8) | Int64(bytes[i])
        i++
    }
    (len, end)
}

/** Skip a TLV; returns (valueLength, offsetAfterTagAndLength). */
func extSkipTlv(bytes: Array<Byte>, offset: Int64): (Int64, Int64) {
    if (offset >= bytes.size) {
        throw CertError("extSkipTlv: out of bounds at ${offset}")
    }
    let (len, afterLen) = extReadLength(bytes, offset + 1)
    (len, afterLen)
}

/** Decode a DER OBJECT IDENTIFIER value (no tag/length) to dotted-decimal. */
func extDecodeOID(bytes: Array<Byte>, offset: Int64, length: Int64): String {
    if (length < 1) {
        throw CertError("extDecodeOID: empty OID")
    }
    if (offset + length > bytes.size) {
        throw CertError("extDecodeOID: OID bytes out of bounds")
    }
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
                throw CertError("extDecodeOID: truncated base-128 encoding")
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
