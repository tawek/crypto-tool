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
import org.tawek.crypto.tool.completion.Constants
import org.tawek.crypto.tool.completion.KeyLabel

@ShellComponent
class JWXCommands {

    @Autowired
    lateinit var io: IO

    @Autowired
    lateinit var keystoreManager: KeystoreManager

    @ShellMethod("JWE Encode")
    fun jweEncode(
        @KeyLabel
        @ShellOption("-k", "--key", help = "Label of a key from a keystore (load it first)") keyLabel: String,
        @Constants(org.jose4j.jwe.KeyManagementAlgorithmIdentifiers::class)
        @ShellOption("-alg", "--key-management-algo", help = "Key management algorithm (ex: RSA1_5)") kmAlgo: String,
        @Constants(org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers::class)
        @ShellOption(
            "-enc",
            "--content-encryption-algo",
            help = "Content encryption algorithm (ex: A128GCM)"
        ) ceAlgo: String,
        @ShellOption("-i", "--input", help = "Name of input file", defaultValue = NULL) input: String?,
        @ShellOption(
            "-id", "--input-data",
            help = "Input data directly from console. Prefix with 'HEX:', 'BASE64:', 'TEXT:' or specify format with -if switch",
            defaultValue = NULL
        ) inputData: String?,
        @ShellOption(
            "-if",
            "--input-format",
            help = "Input data/file format (default is 'HEX' for console input and 'TEXT' for file input)",
            defaultValue = NULL
        ) inputFormat: DataFormat?,
        @ShellOption(
            "-of",
            "--output-format",
            help = "Output data/file format (default is 'HEX' for console output and 'TEXT' for file output)",
            defaultValue = NULL
        ) outputFormat: DataFormat?,
        @ShellOption(
            "-o",
            "--output",
            help = "Name of output file (if unspecified data will be written directly to console)",
            defaultValue = NULL
        ) output: String?,
        @ShellOption(
            "-h",
            "--header",
            help = "Comma-separated list of additional header <key>=<value> pairs",
            defaultValue = NULL
        ) headers: Array<String>?,
        @ShellOption(
            "-kid",
            help = "Key identifier header (if unspecified it will default to key label)",
            defaultValue = NULL
        ) keyId: String?,
        @ShellOption("-cty", "--content-type", help = "'cty' header value", defaultValue = NULL) contentType: String?,
        @ShellOption(
            "-zip",
            "--compress",
            help = "'zip' header value. (ex: DEF)",
            defaultValue = NULL
        ) compress: String?,
    ) {
        val jwe = JsonWebEncryption()
        jwe.setPlaintext(io.readInput(input, inputData, inputFormat))
        jwe.key = keystoreManager.getKey(keyLabel, KeyOp.CIPHER)
        jwe.algorithmHeaderValue = kmAlgo
        jwe.encryptionMethodHeaderParameter = ceAlgo
        setHeaders(headers, jwe)
        if (compress != null) {
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
        @KeyLabel
        @ShellOption("-k", "--key", help = "Label of a key from a keystore (load it first)") keyLabel: String,
        @ShellOption("-i", "--input", help = "Name of input file", defaultValue = NULL) input: String?,
        @ShellOption(
            "-id", "--input-data",
            help = "Input data directly from console. Prefix with 'HEX:', 'BASE64:', 'TEXT:' or specify format with -if switch",
            defaultValue = NULL
        ) inputData: String?,
        @ShellOption(
            "-if",
            "--input-format",
            help = "Input data/file format (default is 'HEX' for console input and 'TEXT' for file input)",
            defaultValue = NULL
        ) inputFormat: DataFormat?,
        @ShellOption(
            "-of",
            "--output-format",
            help = "Output data/file format (default is 'HEX' for console output and 'TEXT' for file output)",
            defaultValue = NULL
        ) outputFormat: DataFormat?,
        @ShellOption(
            "-o",
            "--output",
            help = "Name of output file (if unspecified data will be written directly to console)",
            defaultValue = NULL
        ) output: String?,
    ) {
        val jwe = JsonWebEncryption()
        jwe.compactSerialization = String(io.readInput(input, inputData, DataFormat.TEXT), UTF8)
        jwe.key = keystoreManager.getKey(keyLabel, KeyOp.DECIPHER)
        val result = jwe.plaintextBytes
        printHeaders(jwe)
        io.writeOutput(result, output)
    }

    private fun printHeaders(jwx: JsonWebStructure) {
        io.println("Headers :\n${jwx.headers.fullHeaderAsJsonString}")
    }


    @ShellMethod("JWS Encode")
    fun jwsEncode(
        @KeyLabel
        @ShellOption("-k", "--key", help = "Label of a key from a keystore (load it first)") keyLabel: String,
        @Constants(org.jose4j.jws.AlgorithmIdentifiers::class)
        @ShellOption("-alg", "--sign-algo", help = "Signinig JWS algorithm (ex: 'RS256')") kmAlgo: String,
        @ShellOption("-i", "--input", help = "Name of input file", defaultValue = NULL) input: String?,
        @ShellOption(
            "-id", "--input-data",
            help = "Input data directly from console. Prefix with 'HEX:', 'BASE64:', 'TEXT:' or specify format with -if switch",
            defaultValue = NULL
        ) inputData: String?,
        @ShellOption(
            "-if",
            "--input-format",
            help = "Input data/file format (default is 'HEX' for console input and 'TEXT' for file input)",
            defaultValue = NULL
        ) inputFormat: DataFormat?,
        @ShellOption(
            "-of",
            "--output-format",
            help = "Output data/file format (default is 'HEX' for console output and 'TEXT' for file output)",
            defaultValue = NULL
        ) outputFormat: DataFormat?,
        @ShellOption(
            "-o",
            "--output",
            help = "Name of output file (if unspecified data will be written directly to console)",
            defaultValue = NULL
        ) output: String?,
        @ShellOption(
            "-h",
            "--header",
            help = "Comma-separated list of additional header <key>=<value> pairs",
            defaultValue = NULL
        ) headers: Array<String>?,
        @ShellOption(
            "-kid",
            help = "Key identifier header (if unspecified it will default to key label)",
            defaultValue = NULL
        ) keyId: String?,
        @ShellOption("-cty", "--content-type", help = "'cty' header value", defaultValue = NULL) contentType: String?
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
        headers?.forEach {
            val split = it.split('=')
            val key = split[0]
            val value = split.slice(1 until split.size).joinToString("=")
            jwe.setHeader(key, value)
        }
    }

    @ShellMethod("JWS Decode")
    fun jwsDecode(
        @KeyLabel
        @ShellOption("-k", "--key", help = "Label of a key from a keystore (load it first)") keyLabel: String,
        @ShellOption("-i", "--input", help = "Name of input file", defaultValue = NULL) input: String?,
        @ShellOption(
            "-id", "--input-data",
            help = "Input data directly from console. Prefix with 'HEX:', 'BASE64:', 'TEXT:' or specify format with -if switch",
            defaultValue = NULL
        ) inputData: String?,
        @ShellOption(
            "-if",
            "--input-format",
            help = "Input data/file format (default is 'HEX' for console input and 'TEXT' for file input)",
            defaultValue = NULL
        ) inputFormat: DataFormat?,
        @ShellOption(
            "-of",
            "--output-format",
            help = "Output data/file format (default is 'HEX' for console output and 'TEXT' for file output)",
            defaultValue = NULL
        ) outputFormat: DataFormat?,
        @ShellOption(
            "-o",
            "--output",
            help = "Name of output file (if unspecified data will be written directly to console)",
            defaultValue = NULL
        ) output: String?,
    ) {
        val jws = JsonWebSignature()
        jws.compactSerialization = String(io.readInput(input, inputData, DataFormat.TEXT), UTF8)
        jws.key = keystoreManager.getKey(keyLabel, KeyOp.VERIFY)
        val result = jws.payloadBytes
        printHeaders(jws)
        io.writeOutput(result, output)
    }

}