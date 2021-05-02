package org.tawek.crypto.tool

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.*

class CertBuilder(
    private val signerPrivateKey: PrivateKey,
    private val signedPublicKey: PublicKey,
    private val signerKeyId: ByteArray? = null
) {

    fun build(spec: CertSpec): X509Certificate {
        val b = JcaX509v3CertificateBuilder(
            spec.issuerDn,
            spec.serialNo,
            Date.from(spec.notBefore),
            Date.from(spec.notAfter),
            spec.subjectDn,
            signedPublicKey
        )
        if (signerKeyId != null) {
            b.addExtension(Extension.create(Extension.authorityKeyIdentifier, false, DEROctetString(signerKeyId)))
        }
        if (spec.subjectKeyId != null) {
            b.addExtension(Extension.create(Extension.subjectKeyIdentifier, false, DEROctetString(spec.subjectKeyId)))
        }
        val cs = makeContentSigner()
        return getX509Certificate(b.build(cs))
    }

    private fun getX509Certificate(certificateHolder: X509CertificateHolder?): X509Certificate {
        return JcaX509CertificateConverter().getCertificate(certificateHolder)
    }

    private fun makeContentSigner(): ContentSigner {
        return JcaContentSignerBuilder(signatureAlgo(signerPrivateKey.algorithm)).build(signerPrivateKey)
    }

    private fun signatureAlgo(keyType: String): String {
        return when (keyType) {
            "RSA" -> "SHA256WITHRSAANDMGF1"
            "EC" -> "SHA256withECDSA"
            else -> throw UnsupportedOperationException("Unsupported key type $keyType for signing certificates.")
        }
    }
}