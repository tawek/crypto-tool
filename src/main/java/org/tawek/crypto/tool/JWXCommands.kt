package org.tawek.crypto.tool

import org.bouncycastle.util.encoders.UTF8
import org.jose4j.jwe.JsonWebEncryption
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ShellMethod
import org.springframework.shell.standard.ShellOption
import org.springframework.shell.standard.ShellOption.NULL
import org.tawek.crypto.tool.Charsets.UTF8

@ShellComponent
class JWXCommands {

    @Autowired
    lateinit var io: IO

    @Autowired
    lateinit var keystoreManager: KeystoreManager

    @ShellMethod
    fun jweEncode(
        @ShellOption("-k", "--key") keyLabel: String,
        @ShellOption("-alg", "--key-management-algo") kmAlgo: String,
        @ShellOption("-enc", "--content-encryption-algo") ceAlgo: String,
        @ShellOption("-i", "--input", defaultValue = NULL) input: String?,
        @ShellOption("-id", "--input-data", defaultValue = NULL) inputData: String?,
        @ShellOption("-if", "--input-format", defaultValue = NULL) inputFormat: DataFormat?,
        @ShellOption("-o", "--output", defaultValue = NULL) output: String?,
        @ShellOption("-h", "--header", defaultValue = NULL) headers: Array<String>?,
        @ShellOption("-zip", "--compress", defaultValue = NULL) compress: String?,
        @ShellOption("-kid", defaultValue = NULL) keyId: String?,
        @ShellOption("-cty", "--content-type", defaultValue = NULL) contentType: String?
    ) {
        val jwe = JsonWebEncryption()
        jwe.setPlaintext(io.readInput(input, inputData, inputFormat))
        jwe.key = keystoreManager.getKey(keyLabel, KeyOp.CIPHER)
        jwe.algorithmHeaderValue = kmAlgo
        jwe.encryptionMethodHeaderParameter = ceAlgo
        if (headers != null) {
            headers.forEach {
                val split = it.split('=')
                val key = split[0]
                val value = split.slice(1..split.size).joinToString("=")
                jwe.setHeader(key, value)
            }
        }
        jwe.compressionAlgorithmHeaderParameter = compress
        jwe.contentTypeHeaderValue = contentType
        jwe.keyIdHeaderValue = keyId ?: keyLabel
        val result = jwe.compactSerialization.toByteArray(UTF8)
        io.writeOutput(result, output)
    }

    @ShellMethod
    fun jweDecode(
        @ShellOption("-k", "--key") keyLabel: String,
        @ShellOption("-i", "--input", defaultValue = NULL) input: String?,
        @ShellOption("-id", "--input-data", defaultValue = NULL) inputData: String?,
        @ShellOption("-o", "--output", defaultValue = NULL) output: String?,
        @ShellOption("-of", "--output-format", defaultValue = NULL) outputFormat: DataFormat?,
    ) {
        val jwe = JsonWebEncryption()
        jwe.compactSerialization = String(io.readInput(input, inputData, DataFormat.TEXT), UTF8)
        jwe.key = keystoreManager.getKey(keyLabel, KeyOp.CIPHER)
        val result = jwe.plaintextBytes
        io.writeOutput(result, output)
    }

}