package org.tawek.crypto.tool

import org.apache.commons.io.FileUtils
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.jline.terminal.Terminal
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.shell.standard.ShellCommandGroup
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ShellMethod
import org.springframework.shell.standard.ShellOption
import org.springframework.shell.standard.ShellOption.NULL
import org.tawek.crypto.tool.KeyOp.CIPHER
import org.tawek.crypto.tool.KeyOp.DECIPHER
import org.tawek.crypto.tool.KeyOp.SIGN
import org.tawek.crypto.tool.KeyOp.VERIFY
import org.tawek.crypto.tool.KeyUtils.bitSize
import org.tawek.crypto.tool.KeyUtils.makeX509SelfSignedCert
import org.tawek.crypto.tool.KeyUtils.toPublicKey
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.StringReader
import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
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
        keystore!!.load(null, EMPTY_PASS)
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
        ks.setKeyEntry(label, key, EMPTY_PASS, arrayOf())
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
        @ShellOption(
            "-f", "--key-file",
            help = "Key file name",
            defaultValue = NULL
        ) keyFile: String?,
    ): String {
        val ks = keystore()
        checkNoKey(label)
        val keyBytes = io.readInput(keyFile, keyData, null)
        val sks = SecretKeySpec(keyBytes, type)
        ks.setKeyEntry(label, sks, EMPTY_PASS, arrayOf())
        terminal.writer().println("Key '" + label + "' imported.")
        return describeKey(ks, label)
    }

    @ShellMethod("Import key pair (private part) using PKCS#8")
    fun importPKCS8(
        @ShellOption("-l", "--label", help = "Label of a new key") label: String,
        @ShellOption("-t", "--type", help = "Type of key to import (RSA/EC)", defaultValue = "RSA") type: String,
        @ShellOption(
            "-k", "--key",
            help = "Actual key bytes. Prefix with 'HEX:', 'BASE64:', 'TEXT:'",
            defaultValue = NULL
        ) keyData: String?,
        @ShellOption(
            "-f", "--key-file",
            help = "Key file name",
            defaultValue = NULL
        ) keyFile: String?,
    ): String {
        val ks = keystore()
        checkNoKey(label)
        val keyBytes = io.readInput(keyFile, keyData, null)
        return importPKCS8EncodedKey(type, keyBytes, ks, label)
    }

    @ShellMethod("Import key pair (private part) using PEM")
    fun importPEM(
        @ShellOption("-l", "--label", help = "Label of a new key") label: String,
        @ShellOption("-t", "--type", help = "Type of key to import (RSA/EC)", defaultValue = "RSA") type: String,
        @ShellOption(
            "-k", "--key",
            help = "Actual key bytes. Prefix with 'HEX:', 'BASE64:', 'TEXT:'",
            defaultValue = NULL
        ) keyData: String?,
        @ShellOption(
            "-f", "--key-file",
            help = "Key file name",
            defaultValue = NULL
        ) keyFile: String?,
    ): String {
        val ks = keystore()
        checkNoKey(label)
        val keyBytes = io.readInput(keyFile, keyData, null)
        val pem = PEMParser(StringReader(String(keyBytes, StandardCharsets.ISO_8859_1)))
        val keyPair: PEMKeyPair = pem.readObject() as PEMKeyPair
        val pkcs8 = keyPair.privateKeyInfo.encoded
        return importPKCS8EncodedKey(type, pkcs8, ks, label)
    }

    private fun importPKCS8EncodedKey(
        type: String,
        encodedPrivateKey: ByteArray?,
        ks: KeyStore,
        label: String
    ): String {
        val keyFactory = KeyFactory.getInstance(type)
        val sk = keyFactory.generatePrivate(PKCS8EncodedKeySpec(encodedPrivateKey))
        val pk = toPublicKey(sk)

        val kp = KeyPair(pk, sk)

        val cert = makeX509SelfSignedCert(kp, "cn=" + label, 100)

        ks.setKeyEntry(label, sk, EMPTY_PASS, arrayOf(cert))
        terminal.writer().println("Key '" + label + "' imported.")
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
        ks.setKeyEntry(label, keyPair.private, EMPTY_PASS, arrayOf(cert))
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
            val key = ks.getKey(keyLabel, EMPTY_PASS)
            if (key is SecretKey) {
                return key
            }
        }
        return when (keyOp) {
            CIPHER, VERIFY -> requireNotNull(ks.getCertificate(keyLabel).publicKey, { "No certificate ${keyLabel}" })
            DECIPHER, SIGN -> requireNotNull(ks.getKey(keyLabel, EMPTY_PASS), { "No private key ${keyLabel}" })
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

        val EMPTY_PASS = charArrayOf()

        fun describeKey(ks: KeyStore, alias: String): String {
            if (ks.isKeyEntry(alias)) {
                val key = ks.getKey(alias, EMPTY_PASS)
                val keyInfo = "[${alias}] : ${key.algorithm} / ${key.format}"
                return keyInfo + bitSize(key) ?.let { " / $it bits" }
            } else {
                val certificate = ks.getCertificate(alias)
                val publicKey = certificate.publicKey
                val certInfo = "[${alias}] : ${publicKey.algorithm} / ${certificate.type}"
                return certInfo + bitSize(publicKey)?.let { " / $it bits" }
            }
        }

        private fun countKeys(ks: KeyStore) = ks.aliases().toList().size

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

    }

}
