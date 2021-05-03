package org.tawek.crypto.tool

import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwx.JsonWebStructure
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

    @ShellMethod("JWE Encode")
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
        setHeaders(headers, jwe)
        if (compress!= null) {
            jwe.compressionAlgorithmHeaderParameter = compress
        }
        if (contentType != null) {
            jwe.contentTypeHeaderValue = contentType
        }
        jwe.keyIdHeaderValue = keyId ?: keyLabel
        val result = jwe.compactSerialization.toByteArray(UTF8)
        printHeaders(jwe)
        io.writeOutput(result, output)
    }

    @ShellMethod("JWE Decode")
    fun jweDecode(
        @ShellOption("-k", "--key") keyLabel: String,
        @ShellOption("-i", "--input", defaultValue = NULL) input: String?,
        @ShellOption("-id", "--input-data", defaultValue = NULL) inputData: String?,
        @ShellOption("-o", "--output", defaultValue = NULL) output: String?,
        @ShellOption("-of", "--output-format", defaultValue = NULL) outputFormat: DataFormat?,
    ) {
        val jwe = JsonWebEncryption()
        jwe.compactSerialization = String(io.readInput(input, inputData, DataFormat.TEXT), UTF8)
        jwe.key = keystoreManager.getKey(keyLabel, KeyOp.DECIPHER)
        val result = jwe.plaintextBytes
        printHeaders(jwe)
        io.writeOutput(result, output)
    }

    private fun printHeaders(jwx: JsonWebStructure) {
        io.terminal.writer().println("Headers :\n${jwx.headers.fullHeaderAsJsonString}")
    }


    @ShellMethod("JWS Encode")
    fun jwsEncode(
        @ShellOption("-k", "--key") keyLabel: String,
        @ShellOption("-alg", "--sign-algo") kmAlgo: String,
        @ShellOption("-i", "--input", defaultValue = NULL) input: String?,
        @ShellOption("-id", "--input-data", defaultValue = NULL) inputData: String?,
        @ShellOption("-if", "--input-format", defaultValue = NULL) inputFormat: DataFormat?,
        @ShellOption("-o", "--output", defaultValue = NULL) output: String?,
        @ShellOption("-h", "--header", defaultValue = NULL) headers: Array<String>?,
        @ShellOption("-kid", defaultValue = NULL) keyId: String?,
        @ShellOption("-cty", "--content-type", defaultValue = NULL) contentType: String?
    ) {
        val jws = JsonWebSignature()
        jws.payloadBytes = io.readInput(input, inputData, inputFormat)
        jws.key = keystoreManager.getKey(keyLabel, KeyOp.SIGN)
        jws.algorithmHeaderValue = kmAlgo
        setHeaders(headers, jws)
        if (contentType != null) {
            jws.contentTypeHeaderValue = contentType
        }
        jws.keyIdHeaderValue = keyId ?: keyLabel
        val result = jws.compactSerialization.toByteArray(UTF8)
        printHeaders(jws)
        io.writeOutput(result, output)
    }

    private fun setHeaders(headers: Array<String>?, jwe: JsonWebStructure) {
        if (headers != null) {
            headers.forEach {
                val split = it.split('=')
                val key = split[0]
                val value = split.slice(1 until split.size).joinToString("=")
                jwe.setHeader(key, value)
            }
        }
    }

    @ShellMethod("JWS Decode")
    fun jwsDecode(
        @ShellOption("-k", "--key") keyLabel: String,
        @ShellOption("-i", "--input", defaultValue = NULL) input: String?,
        @ShellOption("-id", "--input-data", defaultValue = NULL) inputData: String?,
        @ShellOption("-o", "--output", defaultValue = NULL) output: String?,
        @ShellOption("-of", "--output-format", defaultValue = NULL) outputFormat: DataFormat?,
    ) {
        val jws = JsonWebSignature()
        jws.compactSerialization = String(io.readInput(input, inputData, DataFormat.TEXT), UTF8)
        jws.key = keystoreManager.getKey(keyLabel, KeyOp.VERIFY)
        val result = jws.payloadBytes
        printHeaders(jws)
        io.writeOutput(result, output)
    }

}