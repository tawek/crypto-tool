package org.tawek.crypto.tool

import org.jline.terminal.Terminal
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.shell.standard.ShellCommandGroup
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ShellMethod
import org.springframework.shell.standard.ShellOption
import org.springframework.shell.standard.ShellOption.NULL
import org.tawek.crypto.tool.DataFormat.Companion.detectAndDecode
import java.io.File
import java.security.Key
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
    private lateinit var terminal: Terminal

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

        cipher.init(Cipher.ENCRYPT_MODE, getKey(keyLabel, KeyOp.CIPHER), getParams(algo, icv))
        if (aad != null) {
            cipher.updateAAD(detectAndDecode(aad))
        }

        val result = cipher.doFinal(readInput(input, inputData, inputFormat))
        writeOutput(result, output, outputFormat)
    }

    private fun readInput(input: String?, inputData: String?, inputFormat: DataFormat?): ByteArray {
        return when {
            (inputData != null && input != null) -> throw IllegalArgumentException("Specify --input-data or --input, not both")
            inputData != null -> detectAndDecode(inputData)
            input != null -> inputFile(input, inputFormat)
            else -> throw IllegalArgumentException("Specify --input-data or --input, none was given")
        }
    }

    private fun inputFile(fileName: String, fileFormat: DataFormat?): ByteArray {
        return (fileFormat?: DataFormat.TEXT).readFile(File(fileName))
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

        cipher.init(Cipher.DECRYPT_MODE, getKey(keyLabel, KeyOp.DECIPHER), getParams(algo, icv))
        if (aad != null) {
            cipher.updateAAD(detectAndDecode(aad))
        }
        val result = cipher.doFinal(readInput(input, inputData, inputFormat))

        writeOutput(result, output, outputFormat)
    }

    private fun writeOutput(
        result: ByteArray,
        output: String?,
        outputFormat: DataFormat?
    ) {
        if (output == null) {
            val effDataFormat = outputFormat ?: DataFormat.HEX
            val formattedResult = effDataFormat.encode(result)
            terminal.writer().println("OUTPUT ${effDataFormat.name}:")
            terminal.writer().println(formattedResult)
        } else {
            (outputFormat ?: DataFormat.TEXT).writeFile(File(output), result)
        }
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

    private fun getKey(keyLabel: String, keyOp: KeyOp): Key {
        return keystoreManager.getKey(keyLabel, keyOp)
    }

    private fun getCipher(algo: String): Cipher {
        return Cipher.getInstance(algo)
    }

}