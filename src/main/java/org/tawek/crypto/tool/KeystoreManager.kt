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
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import java.util.stream.Collectors.toList
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

@ShellComponent
@ShellCommandGroup("Keystore operations")
class KeystoreManager {

    var keystore: KeyStore? = null
    var modified : Boolean = false

    @Autowired
    lateinit var terminal: Terminal

    @ShellMethod("Keystore information")
    fun keystoreInfo(): String {
        if (keystore == null) {
            return "No keystore"
        }
        return "Provider: ${keystore!!.provider} type: ${keystore!!.type} keys: ${countKeys(keystore!!)} modified:${modified}";
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

    private fun checkNoKeystore() {
        if (keystore != null && modified) {
            throw  IllegalStateException("Loaded keystore is modified, close it first")
        }
    }

    @ShellMethod("Store keystore to file")
    fun storeKeystore(
        @ShellOption("-f", "--file", help = "Keystore file name") keystoreFile: String,
        @ShellOption("-p", "--password", defaultValue = "") keystorePassword: String
    ) {
        val ks = checkKeystore()
        val baos = ByteArrayOutputStream();
        ks.store(baos, keystorePassword.toCharArray())
        baos.flush()
        baos.close()
        FileUtils.writeByteArrayToFile(File(keystoreFile), baos.toByteArray())
        terminal.writer().println("Keystore stored.")
        modified = false
    }

    private fun countKeys(ks:KeyStore) = ks.aliases().toList().size

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
        @ShellOption("-f","--force", help = "Force keystore close") force: Boolean
    ) {
        val ks = checkKeystore()
        if (modified) {
            if (!force) {
                throw IllegalStateException("Keystore is modified, save it first or close it with --force flag")
            } else {
                terminal.writer().println("Force closing modified keystore")
            }
        }
        keystore = null;
        modified = false
    }

    @ShellMethod("Generate symmetric key")
    fun generateKey(
        @ShellOption("-l", "--label") label: String,
        @ShellOption("-t", "--type", defaultValue = "AES") type: String,
        @ShellOption("-b", "--bits", defaultValue = NULL) bits: Int?,
    ): String {
        val ks = checkKeystore()
        val keyGenerator = KeyGenerator.getInstance(type)
        keyGenerator.init(defaultBits(type, bits))
        val key = keyGenerator.generateKey()
        ks.setKeyEntry(label, key, "".toCharArray(), arrayOf())
        modified=true
        terminal.writer().println("Key generated")
        return describeKey(ks, label)
    }

    @ShellMethod("Generate asymmetric key pair")
    fun generateKeyPair(
        @ShellOption("-l", "--label") label: String,
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
            help = "Length of private key in bits (default is 2048bits for RSA and 256 for EC) ",
            defaultValue = NULL
        )
        bits: Int?,
    ): String {
        val ks = checkKeystore()
        val keyGenerator = KeyPairGenerator.getInstance(type)
        keyGenerator.initialize(defaultBits(type, bits))
        val keyPair = keyGenerator.generateKeyPair()
        //make self-signed cert for 100 years
        val cert = CertBuilder(signedPublicKey = keyPair.public, signerPrivateKey = keyPair.private)
            .build(
                CertSpec(
                    issuerDn = X500Name("cn=${label}"),
                    subjectDn = X500Name("cn=${label}"),
                    notBefore = Instant.now(),
                    notAfter = Instant.now().plus(365 * 100, ChronoUnit.DAYS),
                    serialNo = BigInteger.valueOf(Math.abs(Random().nextLong())),
                )
            )
        ks.setKeyEntry(label, keyPair.private, "".toCharArray(), arrayOf(cert))
        modified =true
        terminal.writer().println("Keypair generated")
        return describeKey(ks, label)
    }

    private fun defaultBits(type: String, bits: Int?): Int {
        return bits
            ?: when (type) {
                "RSA" -> 2048
                "EC" -> 256
                "AES" -> 128
                else -> throw IllegalArgumentException("Unknown key type ${type}")
            }
    }

    @ShellMethod("List keys in keystore")
    fun listKeys(): List<String> {
        val ks = checkKeystore()
        return ks.aliases().toList().stream().map { describeKey(ks, it) }.collect(toList())
    }

    private fun describeKey(ks: KeyStore, alias: String): String {
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

    fun getKey(keyLabel: String, keyOp: KeyOp): Key {
        val ks = checkKeystore()
        if (ks.isKeyEntry(keyLabel)) {
            val key = ks.getKey(keyLabel, "".toCharArray())
            if (key is SecretKey) {
                return key
            }
        }
        return when (keyOp) {
            CIPHER, VERIFY -> ks.getCertificate(keyLabel).publicKey!!
            DECIPHER, SIGN -> ks.getKey(keyLabel, "".toCharArray())!!
        }
    }

    private fun checkKeystore() = requireNotNull(keystore, { "Keystore not loaded" })

}
