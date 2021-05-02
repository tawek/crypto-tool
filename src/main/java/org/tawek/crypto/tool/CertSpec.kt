package org.tawek.crypto.tool

import org.bouncycastle.asn1.x500.X500Name
import java.math.BigInteger
import java.time.Instant

@Suppress("ArrayInDataClass")
data class CertSpec(
    var issuerDn: X500Name,
    var subjectDn: X500Name,
    var notBefore: Instant,
    var notAfter: Instant,
    var serialNo: BigInteger,
    var subjectKeyId: ByteArray? = null
)