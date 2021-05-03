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
        @ShellOption("-k", "--key") keyLabel: String,
        @ShellOption("-a", "--algo") algo: String,
        @ShellOption("-i", "--input", defaultValue = NULL) input: String?,
        @ShellOption("-id", "--input-data", defaultValue = NULL) inputData: String?,
        @ShellOption("-if", "--input-format", defaultValue = NULL) inputFormat: DataFormat?,
        @ShellOption("-of", "--output-format", defaultValue = NULL) outputFormat: DataFormat?,
        @ShellOption("-o", "--output", defaultValue = NULL) output: String?,
        @ShellOption("--icv", defaultValue = NULL) icv: String?,
        @ShellOption("--aad", defaultValue = NULL) aad: String?,
    ) {
        val cipher = getCipher(algo)

        val key = keystoreManager.getKey(keyLabel, KeyOp.CIPHER)
        cipher.init(Cipher.ENCRYPT_MODE, key, getParams(algo, icv))
        if (aad != null) {
            cipher.updateAAD(detectAndDecode(aad))
        }

        val result = cipher.doFinal(io.readInput(input, inputData, inputFormat))
        io.writeOutput(result, output, outputFormat)
    }

    @ShellMethod("Decipher data")
    fun decipher(
        @ShellOption("-k", "--key") keyLabel: String,
        @ShellOption("-a", "--algo") algo: String,
        @ShellOption("-i", "--input", defaultValue = NULL) input: String?,
        @ShellOption("-id", "--input-data", defaultValue = NULL) inputData: String?,
        @ShellOption("-if", "--input-format", defaultValue = NULL) inputFormat: DataFormat?,
        @ShellOption("-of", "--output-format", defaultValue = NULL) outputFormat: DataFormat?,
        @ShellOption("-o", "--output", defaultValue = NULL) output: String?,
        @ShellOption("--icv", defaultValue = NULL) icv: String?,
        @ShellOption("--aad", defaultValue = NULL) aad: String?,
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