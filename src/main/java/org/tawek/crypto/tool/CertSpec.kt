package org.tawek.crypto.tool

import org.bouncycastle.asn1.x500.X500Name
import java.math.BigInteger
import java.time.Instant

@Suppress("ArrayInDataClass")
data class CertSpec(
    val issuerDn: X500Name,
    val subjectDn: X500Name,
    val notBefore: Instant,
    val notAfter: Instant,
    val serialNo: BigInteger,
    val subjectKeyId: ByteArray? = null
)