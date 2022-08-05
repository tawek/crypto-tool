package org.tawek.crypto.tool

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import java.lang.IllegalArgumentException
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECPublicKeySpec
import java.security.spec.KeySpec
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.RSAPublicKeySpec
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import javax.crypto.SecretKey

object KeyUtils {


    // extract public key from private key
    fun toPublicKey(sk: PrivateKey): PublicKey {
        val kf = KeyFactory.getInstance(sk.algorithm)
        val pkSpec = getPublicKeySpec(sk)
        return kf.generatePublic(pkSpec)
    }

    fun getPublicKeySpec(sk: PrivateKey): KeySpec {
        val keyFactory = KeyFactory.getInstance(sk.algorithm)
        val pkSpec: KeySpec
        if (sk is RSAPrivateCrtKey) {
            pkSpec = RSAPublicKeySpec(sk.modulus, sk.publicExponent)
        } else if (sk is RSAPrivateKey) {
            pkSpec = RSAPublicKeySpec(sk.modulus, (sk.params as RSAKeyGenParameterSpec).publicExponent)
        } else if (sk is ECPrivateKey) {
            val pkParam = ECUtil.generatePrivateKeyParameter(sk) as ECPrivateKeyParameters
            val publicPoint = pkParam.parameters.g.multiply(pkParam.d)
            pkSpec = ECPublicKeySpec(EC5Util.convertPoint(publicPoint), sk.params)
        } else {
            throw IllegalArgumentException("Unsupported private key type: " + sk.algorithm)
        }
        return pkSpec
    }

    fun makeX509SelfSignedCert(
        keyPair: KeyPair,
        dn: String,
        years: Int
    ): X509Certificate {
        val cert = CertBuilder(signedPublicKey = keyPair.public, signerPrivateKey = keyPair.private)
            .build(
                CertSpec(
                    issuerDn = X500Name(dn),
                    subjectDn = X500Name(dn),
                    notBefore = Instant.now(),
                    notAfter = Instant.now().plus(365L * years, ChronoUnit.DAYS),
                    serialNo = BigInteger.valueOf(Random().nextInt(100000000).toLong()),
                )
            )
        return cert
    }

    fun bitSize(key: Key): Int? {
        return when (key) {
            is RSAPrivateKey -> key.modulus.bitLength()
            is ECPrivateKey -> key.params.curve.field.fieldSize
            is RSAPublicKey -> key.modulus.bitLength()
            is ECPublicKey -> key.params.curve.field.fieldSize
            is SecretKey -> key.encoded.size * 8
            else -> null
        }
    }


}