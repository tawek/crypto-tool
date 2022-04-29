package org.tawek.crypto.tool

import org.apache.commons.io.FileUtils
import org.bouncycastle.asn1.x500.X500Name
import org.jline.terminal.Terminal
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.shell.standard.ShellCommandGroup
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ShellMethod
import org.springframework.shell.standard.ShellOption
import org.springframework.shell.standard.ShellOption.NULL
import org.tawek.crypto.tool.KeyOp.*

import java.io.ByteArrayOutputStream
import java.io.File
import java.lang.IllegalArgumentException
import java.lang.IllegalStateException
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import java.util.stream.Collectors.toList
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

@ShellComponent
@ShellCommandGroup("Keystore operations")
class KeystoreManager {

    var keystore: KeyStore? = null
    var modified: Boolean = false

    @Autowired
    lateinit var io: IO

    @Autowired
    lateinit var terminal: Terminal

    @ShellMethod("Keystore information")
    fun keystoreInfo(): String {
        if (keystore == null) {
            return "No keystore"
        }
        return "Provider: ${keystore!!.provider} type: ${keystore!!.type} keys: ${countKeys(keystore!!)} modified:${modified}"
    }

    @ShellMethod("Load keystore from file")
    fun loadKeystore(
        @ShellOption("-f", "--file", help = "Keystore file name") keystoreFile: String,
        @ShellOption("-p", "--password", defaultValue = "") keystorePassword: String
    ): String {
        checkNoKeystore()
        keystore = KeyStore.getInstance(File(keystoreFile), keystorePassword.toCharArray())
        terminal.writer().println("Keystore loaded.")
        return keystoreInfo()
    }

    @ShellMethod("Store keystore to file")
    fun storeKeystore(
        @ShellOption("-f", "--file", help = "Keystore file name") keystoreFile: String,
        @ShellOption("-p", "--password", defaultValue = "") keystorePassword: String
    ) {
        val ks = keystore()
        val baos = ByteArrayOutputStream()
        ks.store(baos, keystorePassword.toCharArray())
        baos.flush()
        baos.close()
        FileUtils.writeByteArrayToFile(File(keystoreFile), baos.toByteArray())
        terminal.writer().println("Keystore stored.")
        modified = false
    }

    @ShellMethod("Create keystore")
    fun createKeystore(
        @ShellOption("-t", "--type", help = "Keystore type (JCEKS is a default)", defaultValue = "JCEKS") type: String
    ): String {
        checkNoKeystore()
        keystore = KeyStore.getInstance(type)
        keystore!!.load(null, "".toCharArray())
        return keystoreInfo()
    }

    @ShellMethod("Close keystore")
    fun closeKeystore(
        @ShellOption("-f", "--force", help = "Force keystore close") force: Boolean
    ) {
        keystore()
        if (modified) {
            if (!force) {
                throw IllegalStateException(KEYSTORE_MODIFIED_MESSAGE)
            } else {
                terminal.writer().println("Force closing modified keystore")
            }
        }
        keystore = null
        modified = false
    }

    @ShellMethod("Delete key")
    fun deleteKey(
        @ShellOption("-l", "--label") label: String,
    ) {
        val ks = keystore()
        checkKey(label)
        ks.deleteEntry(label)
        terminal.writer().println("Key ${label} deleted")
        modified = true
    }

    @ShellMethod("Generate symmetric key")
    fun generateKey(
        @ShellOption("-l", "--label", help = "Label of a new key") label: String,
        @ShellOption("-t", "--type", help = "Type of key to generate (AES/DESede)", defaultValue = "AES") type: String,
        @ShellOption("-b", "--bits", help = "Length of key in bits", defaultValue = NULL) bits: Int?,
    ): String {
        val ks = keystore()
        checkNoKey(label)
        val keyGenerator = KeyGenerator.getInstance(type)
        keyGenerator.init(defaultBits(type, bits))
        val key = keyGenerator.generateKey()
        ks.setKeyEntry(label, key, "".toCharArray(), arrayOf())
        modified = true
        terminal.writer().println("Key generated")
        return describeKey(ks, label)
    }

    @ShellMethod("Import symmetric key")
    fun importKey(
        @ShellOption("-l", "--label", help = "Label of a new key") label: String,
        @ShellOption("-t", "--type", help = "Type of key to import (AES/DESede)", defaultValue = "AES") type: String,
        @ShellOption(
        "-k", "--key",
        help = "Actual key bytes. Prefix with 'HEX:', 'BASE64:', 'TEXT:'",
        defaultValue = NULL
        ) keyData: String?,
    ):  String {
        val ks = keystore()
        checkNoKey(label)
        val keyBytes = io.readInput(null, keyData, null)
        val sks = SecretKeySpec(keyBytes, type)
        ks.setKeyEntry(label, sks, charArrayOf(), arrayOf())
        terminal.writer().println("Key '"+label+"' imported.")
        return describeKey(ks, label)
    }

    @ShellMethod("Generate asymmetric key pair")
    fun generateKeyPair(
        @ShellOption("-l", "--label", help = "Label of a new key-pair") label: String,
        @ShellOption(
            "-t",
            "--type",
            help = "Type of key to generate RSA(default)/EC",
            defaultValue = "RSA"
        )
        type: String,
        @ShellOption(
            "-b",
            "--bits",
            help = "Length of private key in bits (default is 2048 for RSA and 256 for EC). ",
            defaultValue = NULL
        )
        bits: Int?,
        @ShellOption(
            "-c",
            "--curve",
            help = "Curve name for EC (NIST curves are used by default matching bits parameter if curve is not specified)",
            defaultValue = NULL
        )
        curve: String?,
        @ShellOption(
            "-dn",
            help = "Subject DN for self-signed certificate (the default is cn=<label>)",
            defaultValue = NULL
        )
        subjectDN: String?,

        ): String {
        val ks = keystore()
        checkNoKey(label)
        val keyGenerator = KeyPairGenerator.getInstance(type)
        when {
            curve != null -> keyGenerator.initialize(ECGenParameterSpec(curve))
            else -> keyGenerator.initialize(defaultBits(type, bits))
        }
        val keyPair = keyGenerator.generateKeyPair()
        if (bits != null && bitSize(keyPair.private) != bits) {
            throw IllegalArgumentException("Curve ${curve} is not ${bits} bit")
        }
        //make self-signed cert for 100 years
        val years = 100
        val dn = subjectDN ?: "cn=${label}"
        val cert = makeX509SelfSignedCert(keyPair, dn, years)
        ks.setKeyEntry(label, keyPair.private, "".toCharArray(), arrayOf(cert))
        modified = true
        terminal.writer().println("Keypair generated")
        return describeKey(ks, label)
    }

    @ShellMethod("List keys in keystore")
    fun listKeys(): List<String> {
        val ks = keystore()
        return ks.aliases().toList().stream().map { describeKey(ks, it) }.collect(toList())
    }

    fun getKey(keyLabel: String, keyOp: KeyOp): Key {
        val ks = keystore()
        if (ks.isKeyEntry(keyLabel)) {
            val key = ks.getKey(keyLabel, "".toCharArray())
            if (key is SecretKey) {
                return key
            }
        }
        return when (keyOp) {
            CIPHER, VERIFY -> requireNotNull(ks.getCertificate(keyLabel).publicKey, { "No certificate ${keyLabel}" })
            DECIPHER, SIGN -> requireNotNull(ks.getKey(keyLabel, "".toCharArray()), { "No private key ${keyLabel}" })
        }
    }

    private fun checkNoKeystore() {
        check(keystore == null || !modified, { KEYSTORE_MODIFIED_MESSAGE })
    }

    fun keystore() = requireNotNull(keystore, { NO_KEYSTORE_MESSAGE })

    private fun checkNoKey(label: String) {
        check(!keystore!!.containsAlias(label), { "Key ${label} already exists." })
    }

    private fun checkKey(label: String) {
        require(keystore!!.containsAlias(label), { "No key ${label}" })
    }

    fun isLoaded(): Boolean = keystore != null

    companion object {
        const val KEYSTORE_MODIFIED_MESSAGE = "Keystore is modified, save it first or close it with --force flag"
        const val NO_KEYSTORE_MESSAGE = "Keystore is not loaded, load it first"

        fun describeKey(ks: KeyStore, alias: String): String {
            if (ks.isKeyEntry(alias)) {
                val key = ks.getKey(alias, "".toCharArray())
                val keyInfo = "[${alias}] : ${key.algorithm} / ${key.format}"
                return keyInfo + bitSize(key)?.let { " / $it bits" }
            } else {
                val certificate = ks.getCertificate(alias)
                val publicKey = certificate.publicKey
                val certInfo = "[${alias}] : ${publicKey.algorithm} / ${certificate.type}"
                return certInfo + bitSize(publicKey)?.let { " / $it bits" }
            }
        }

        private fun countKeys(ks: KeyStore) = ks.aliases().toList().size
        private fun makeX509SelfSignedCert(
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

        private fun defaultBits(type: String, bits: Int?): Int {
            return bits
                ?: when (type) {
                    "RSA" -> 2048
                    "EC" -> 256
                    "AES" -> 128
                    "DESede" -> 128
                    else -> throw IllegalArgumentException("Unknown key type ${type}")
                }
        }

        private fun bitSize(key: Key): Int? {
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

}
