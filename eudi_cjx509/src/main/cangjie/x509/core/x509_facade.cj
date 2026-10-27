package ohos_app_cangjie_eudi_cjx509.x509.core

import stdx.crypto.x509.{X509Certificate, VerifyOption}
import stdx.crypto.common.DerBlob
import std.time.DateTime

/**
 * CertError wraps x509 operation failures.
 */
public class CertError <: Exception {
    public init(msg: String) {
        super(msg)
    }
}

/**
 * Cert is a thin wrapper around stdx X509Certificate.
 * Consumers use Cert exclusively; they do not import stdx directly.
 */
public class Cert {
    let inner: X509Certificate

    init(inner: X509Certificate) {
        this.inner = inner
    }

    /**
     * Parse a single DER-encoded certificate.
     * Throws CertError if the bytes are not a valid certificate.
     */
    public static func fromDer(bytes: Array<Byte>): Cert {
        try {
            Cert(X509Certificate.decodeFromDer(DerBlob(bytes)))
        } catch (e: Exception) {
            throw CertError("fromDer failed: ${e.message}")
        }
    }

    /**
     * Parse one or more PEM-encoded certificates from a PEM string.
     * Returns an array; throws CertError if no certificate is found.
     */
    public static func fromPem(pem: String): Array<Cert> {
        try {
            let certs = X509Certificate.decodeFromPem(pem)
            Array<Cert>(certs.size) { i => Cert(certs[i]) }
        } catch (e: Exception) {
            throw CertError("fromPem failed: ${e.message}")
        }
    }

    /** Hex-encoded serial number (uppercase hex, from stdx SerialNumber.toString()). */
    public prop serialNumber: String {
        get() {
            inner.serialNumber.toString()
        }
    }

    /** Signature algorithm name string. */
    public prop signatureAlgorithm: String {
        get() {
            inner.signatureAlgorithm.toString()
        }
    }

    /** Issuer distinguished name. */
    public prop issuer: String {
        get() {
            inner.issuer.toString()
        }
    }

    /** Subject distinguished name. */
    public prop subject: String {
        get() {
            inner.subject.toString()
        }
    }

    /** Certificate validity start. */
    public prop notBefore: DateTime {
        get() {
            inner.notBefore
        }
    }

    /** Certificate validity end. */
    public prop notAfter: DateTime {
        get() {
            inner.notAfter
        }
    }

    /**
     * Raw SubjectPublicKeyInfo DER bytes (the full SPKI structure).
     * Callers typically use getPublicKeyX963 instead.
     */
    public prop publicKeyDer: Array<Byte> {
        get() {
            inner.publicKey.encodeToDer().body
        }
    }

    /**
     * Re-encode this certificate to DER bytes.
     * Useful for round-trip tests and wire serialization without exposing inner.
     */
    public func toDer(): Array<Byte> {
        inner.encodeToDer().body
    }
}

/**
 * Verify the certificate chain: leaf <- intermediates <- roots.
 *
 * Parameters:
 *   leaf          - the end-entity certificate
 *   intermediates - zero or more intermediate CA certificates
 *   roots         - one or more trusted root CA certificates
 *   date          - verification time; defaults to DateTime.now() if None
 *
 * Returns true when the chain is valid, false when rejected.
 * Throws CertError on internal failures (e.g. memory allocation).
 */
public func verifyChain(
    leaf: Cert,
    intermediates: Array<Cert>,
    roots: Array<Cert>,
    date!: ?DateTime = None
): Bool {
    var opt = VerifyOption()
    opt.roots = Array<X509Certificate>(roots.size) { i => roots[i].inner }
    opt.intermediates = Array<X509Certificate>(intermediates.size) { i => intermediates[i].inner }
    opt.dnsName = ""
    match (date) {
        case Some(d) => opt.time = d
        case None => opt.time = DateTime.now()
    }
    try {
        leaf.inner.verify(opt)
    } catch (e: Exception) {
        throw CertError("verifyChain internal error: ${e.message}")
    }
}

/**
 * Extract the uncompressed EC public key in X9.63 format (0x04 || X || Y)
 * from the certificate's SubjectPublicKeyInfo.
 *
 * SubjectPublicKeyInfo DER layout:
 *   SEQUENCE {
 *     SEQUENCE { OID, params }   <- AlgorithmIdentifier
 *     BIT STRING                 <- 0x00 unused-bits || raw EC point
 *   }
 *
 * For P-256 the EC point is 65 bytes: 0x04 || X(32) || Y(32).
 * The BIT STRING tag is 0x03.
 *
 * Throws CertError if the key is not an uncompressed EC point.
 */
public func getPublicKeyX963(cert: Cert): Array<Byte> {
    let spki = cert.publicKeyDer
    let point = extractBitStringContent(spki)
    if (point.size < 1) {
        throw CertError("getPublicKeyX963: empty BIT STRING content")
    }
    if (point[0] != 0x04u8) {
        throw CertError("getPublicKeyX963: not an uncompressed EC point (prefix=0x${hexByte(point[0])})")
    }
    point
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Parse a SubjectPublicKeyInfo DER byte array and return the content of the
 * BIT STRING field (with the leading unused-bits byte removed).
 *
 * DER parsing mini-rules used here:
 *   - Each TLV: tag(1 byte), length (1 or more bytes), value
 *   - BIT STRING tag = 0x03; first value byte = number of unused bits (always 0 for SPKI)
 *   - SEQUENCE tag = 0x30
 *
 * Returns (value, newOffset) tuples from readDerLength.
 */
func extractBitStringContent(spki: Array<Byte>): Array<Byte> {
    var offset: Int64 = 0
    let n = spki.size

    // Outer SEQUENCE (tag 0x30)
    if (offset >= n || spki[offset] != 0x30u8) {
        throw CertError("extractBitStringContent: expected outer SEQUENCE tag")
    }
    offset++
    let (_, off1) = readDerLength(spki, offset)
    offset = off1
    // Skip the AlgorithmIdentifier SEQUENCE (first child, tag 0x30).
    if (offset >= n || spki[offset] != 0x30u8) {
        throw CertError("extractBitStringContent: expected AlgorithmIdentifier SEQUENCE tag")
    }
    offset++
    let (algLen, off2) = readDerLength(spki, offset)
    offset = off2
    offset += algLen  // skip AlgorithmIdentifier body

    // Now we should be at the BIT STRING (tag 0x03)
    if (offset >= n || spki[offset] != 0x03u8) {
        throw CertError("extractBitStringContent: expected BIT STRING tag (0x03)")
    }
    offset++
    let (bitLen, off3) = readDerLength(spki, offset)
    offset = off3
    if (bitLen < 2) {
        throw CertError("extractBitStringContent: BIT STRING too short")
    }
    // First byte of BIT STRING value is unused-bits count; skip it.
    offset++  // skip unused-bits byte
    let pointLen = bitLen - 1
    if (offset + pointLen > n) {
        throw CertError("extractBitStringContent: BIT STRING content out of bounds")
    }
    spki[offset..offset + pointLen]
}

/**
 * Read a DER length field starting at bytes[startOffset].
 * Returns (length_value, new_offset_after_length_field).
 * Supports both short form (1 byte, value 0-127) and long form (multi-byte).
 */
func readDerLength(bytes: Array<Byte>, startOffset: Int64): (Int64, Int64) {
    if (startOffset >= bytes.size) {
        throw CertError("readDerLength: out of bounds at ${startOffset}")
    }
    let first = bytes[startOffset]
    if ((first & 0x80u8) == 0u8) {
        return (Int64(first), startOffset + 1)
    }
    let numBytes = Int64(first & 0x7fu8)
    if (numBytes == 0) {
        throw CertError("readDerLength: indefinite length not supported")
    }
    var len: Int64 = 0
    var i = startOffset + 1
    while (i < startOffset + 1 + numBytes) {
        if (i >= bytes.size) {
            throw CertError("readDerLength: out of bounds in multi-byte length")
        }
        len = (len << 8) | Int64(bytes[i])
        i++
    }
    (len, startOffset + 1 + numBytes)
}

/** Format a single byte as two hex digits. */
func hexByte(b: UInt8): String {
    let HEX_CHARS: Array<UInt8> = [
        0x30u8, 0x31u8, 0x32u8, 0x33u8, 0x34u8, 0x35u8, 0x36u8, 0x37u8,
        0x38u8, 0x39u8, 0x61u8, 0x62u8, 0x63u8, 0x64u8, 0x65u8, 0x66u8
    ]
    let buf: Array<Byte> = [HEX_CHARS[Int64(b >> 4)], HEX_CHARS[Int64(b & 0x0fu8)]]
    String.fromUtf8(buf)
}
