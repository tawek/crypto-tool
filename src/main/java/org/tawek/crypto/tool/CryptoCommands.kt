package org.tawek.crypto.tool

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.shell.standard.ShellCommandGroup
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ShellMethod
import org.springframework.shell.standard.ShellOption
import org.springframework.shell.standard.ShellOption.NULL
import org.tawek.crypto.tool.DataFormat.Companion.detectAndDecode
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

@ShellComponent
@ShellCommandGroup("Crypto operations")
class CryptoCommands {

    @Autowired
    private lateinit var keystoreManager: KeystoreManager

    @Autowired
    private lateinit var io :IO;

    @ShellMethod("Cipher data")
    fun cipher(
        @KeyLabel
        @ShellOption("-k", "--key", help="Label of a key from a keystore (load it first)") keyLabel: String,
        @ShellOption("-a", "--algo", help="Name of algorithm (ex: 'AES/GCM/NoPadding')") algo: String,
        @ShellOption("-i", "--input", help="Name of input file", defaultValue = NULL) input: String?,
        @ShellOption("-id", "--input-data",
            help="Input data directly from console. Prefix with 'HEX:', 'BASE64:', 'TEXT:' or specify format with -if switch",
            defaultValue = NULL) inputData: String?,
        @ShellOption("-if", "--input-format", help="Input data/file format (default is 'HEX' for console input and 'TEXT' for file input)", defaultValue = NULL) inputFormat: DataFormat?,
        @ShellOption("-of", "--output-format", help="Output data/file format (default is 'HEX' for console output and 'TEXT' for file output)", defaultValue = NULL) outputFormat: DataFormat?,
        @ShellOption("-o", "--output", help="Name of output file (if unspecified data will be written directly to console)", defaultValue = NULL) output: String?,
        @ShellOption("--icv", help="ICV for CBC/GCM and other chaining modes", defaultValue = NULL) icv: String?,
        @ShellOption("--aad", help="Additional authenticated data (used for GCM)", defaultValue = NULL) aad: String?,
    ) {
        val cipher = getCipher(algo)

        val key = keystoreManager.getKey(keyLabel, KeyOp.CIPHER)
        cipher.init(Cipher.ENCRYPT_MODE, key, getParams(algo, icv))
        if (aad != null) {
            cipher.updateAAD(detectAndDecode(aad))
        }

        val result = cipher.doFinal(io.readInput(input, inputData, inputFormat))
        io.writeOutput(result, output, outputFormat)
        if (cipher.iv != null) {
            io.println("ICV HEX:\n${DataFormat.HEX.encode(cipher.iv)}")
        }
    }

    @ShellMethod("Decipher data")
    fun decipher(
        @KeyLabel
        @ShellOption("-k", "--key", help="Label of a key from a keystore (load it first)") keyLabel: String,
        @ShellOption("-a", "--algo", help="Name of algorithm (ex: 'AES/GCM/NoPadding')") algo: String,
        @ShellOption("-i", "--input", help="Name of input file", defaultValue = NULL) input: String?,
        @ShellOption("-id", "--input-data",
            help="Input data directly from console. Prefix with 'HEX:', 'BASE64:', 'TEXT:' or specify format with -if switch",
            defaultValue = NULL) inputData: String?,
        @ShellOption("-if", "--input-format", help="Input data/file format (default is 'HEX' for console input and 'TEXT' for file input)", defaultValue = NULL) inputFormat: DataFormat?,
        @ShellOption("-of", "--output-format", help="Output data/file format (default is 'HEX' for console output and 'TEXT' for file output)", defaultValue = NULL) outputFormat: DataFormat?,
        @ShellOption("-o", "--output", help="Name of output file (if unspecified data will be written directly to console)", defaultValue = NULL) output: String?,
        @ShellOption("--icv", help="ICV for CBC/GCM and other chaining modes", defaultValue = NULL) icv: String?,
        @ShellOption("--aad", help="Additional authenticated data (used for GCM)", defaultValue = NULL) aad: String?,
    ) {
        val cipher = getCipher(algo)

        val key = keystoreManager.getKey(keyLabel, KeyOp.DECIPHER)
        cipher.init(Cipher.DECRYPT_MODE, key, getParams(algo, icv))
        if (aad != null) {
            cipher.updateAAD(detectAndDecode(aad))
        }
        val result = cipher.doFinal(io.readInput(input, inputData, inputFormat))
        io.writeOutput(result, output, outputFormat)
    }

    private fun getParams(algo: String, icv: String?): AlgorithmParameterSpec? {
        return icv
            ?.let { detectAndDecode(it) }
            ?.let {
                when {
                    algo.contains("/GCM") -> GCMParameterSpec(16 * 8, it)
                    else -> IvParameterSpec(it)
                }
            }
    }

    private fun getCipher(algo: String): Cipher {
        return Cipher.getInstance(algo)
    }

}