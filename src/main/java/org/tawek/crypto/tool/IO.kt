package org.tawek.crypto.tool

import org.jline.terminal.Terminal
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component
import org.tawek.crypto.tool.DataFormat
import org.tawek.crypto.tool.DataFormat.TEXT
import java.io.File

@Component
class IO {

    @Autowired
    lateinit var terminal: Terminal

    fun writeOutput(
        result: ByteArray,
        output: String?,
        outputFormat: DataFormat? = TEXT
    ) {
        if (output == null) {
            val effDataFormat = outputFormat ?: DataFormat.HEX
            val formattedResult = effDataFormat.encode(result)
            terminal.writer().println("OUTPUT ${effDataFormat.name}:")
            terminal.writer().println(formattedResult)
        } else {
            (outputFormat ?: TEXT).writeFile(File(output), result)
        }
    }


    fun readInput(input: String?, inputData: String?, inputFormat: DataFormat?): ByteArray {
        return when {
            (inputData != null && input != null) -> throw IllegalArgumentException("Specify --input-data or --input, not both")
            inputData != null -> DataFormat.detectAndDecode(inputData)
            input != null -> inputFile(input, inputFormat)
            else -> throw IllegalArgumentException("Specify --input-data or --input, none was given")
        }
    }

    private fun inputFile(fileName: String, fileFormat: DataFormat?): ByteArray {
        return (fileFormat ?: TEXT).readFile(File(fileName))
    }

}