package org.tawek.crypto.tool

import org.apache.commons.codec.binary.Hex
import org.apache.commons.io.FileUtils
import org.tawek.crypto.tool.Charsets.EXTENDED_ASCII
import org.tawek.crypto.tool.Charsets.UTF8
import java.io.File
import java.util.Base64

enum class DataFormat {
    BASE64 {
        override fun decode(value: String): ByteArray {
            return Base64.getDecoder().decode(removeAny(value, WHITESPACE));
        }

        override fun encode(value: ByteArray): String {
            return Base64.getEncoder().encodeToString(value)
        }

        override fun readFile(file: File): ByteArray {
            return decode(FileUtils.readFileToString(file, EXTENDED_ASCII))
        }

        override fun writeFile(file: File, bytes: ByteArray) {
            FileUtils.writeStringToFile(file, encode(bytes), EXTENDED_ASCII)
        }
    },
    HEX {

        override fun decode(value: String): ByteArray {
            return Hex.decodeHex(removeAny(value, WHITESPACE_AND_COLON));
        }

        override fun encode(value: ByteArray): String {
            return Hex.encodeHexString(value)
        }

        override fun readFile(file: File): ByteArray {
            return decode(FileUtils.readFileToString(file, EXTENDED_ASCII))
        }

        override fun writeFile(file: File, bytes: ByteArray) {
            FileUtils.writeStringToFile(file, encode(bytes), EXTENDED_ASCII)
        }
    },
    TEXT {
        override fun decode(value: String): ByteArray {
            return value.toByteArray(UTF8)
        }

        override fun encode(value: ByteArray): String {
            return String(value, UTF8)
        }

        override fun readFile(file: File): ByteArray {
            return FileUtils.readFileToByteArray(file)
        }

        override fun writeFile(file: File, bytes: ByteArray) {
            FileUtils.writeByteArrayToFile(file, bytes)
        }
    };

    abstract fun decode(value: String): ByteArray

    abstract fun encode(value: ByteArray): String

    abstract fun readFile(file: File): ByteArray

    abstract fun writeFile(file: File, bytes: ByteArray)

    companion object {

        val WHITESPACE_AND_COLON = charArrayOf(
            '\r', // CR
            '\n', // LF
            '\t', // TAB
            ' ', // SPACE
            ':', // COLON
        )

        val WHITESPACE = charArrayOf(
            '\r', // CR
            '\n', // LF
            '\t', // TAB
            ' ', // SPACE
        )


        // check if value is prefixed with any of the data format names
        // if so, remove it and decode the value using the corresponding data format
        // otherwise, decode the value using HEX
        fun detectAndDecode(value: String): ByteArray {
            for (format in values()) {
                val prefix = format.name + ":"
                if (value.startsWith(prefix)) {
                    return format.decode(value.substring(prefix.length))
                }
            }
            return HEX.decode(value)
        }

        // remove any characters of chars from input value
        private fun removeAny(value: String, chars: CharArray): String {
            val sb = StringBuilder()
            for (c in value.toCharArray()) {
                if (!chars.contains(c)) {
                    sb.append(c)
                }
            }
            return sb.toString()
        }

    }

}
