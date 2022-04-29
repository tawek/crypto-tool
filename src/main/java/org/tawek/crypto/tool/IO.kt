package org.tawek.crypto.tool

import org.jline.terminal.Terminal
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Lazy
import org.springframework.stereotype.Component
import org.tawek.crypto.tool.DataFormat
import org.tawek.crypto.tool.DataFormat.TEXT
import java.io.File

@Component
class IO {

    @Autowired
    @Lazy
    lateinit var terminal: Terminal

    fun writeOutput(
        result: ByteArray,
        output: String?,
        outputFormat: DataFormat? = TEXT
    ) {
        if (output == null) {
            val effDataFormat = outputFormat ?: DataFormat.HEX
            val formattedResult = effDataFormat.encode(result)
            println("OUTPUT ${effDataFormat.name}:")
            println(formattedResult)
        } else {
            (outputFormat ?: TEXT).writeFile(File(output), result)
        }
    }

    fun println(s: String) {
        terminal.writer().println(s)
    }


    /**
     * @param input - input file
     * @param inputData - input data (autodetect or according to format)
     * @param inputFormat - format for input data or input file
     */
    fun readInput(input: String?, inputData: String?, inputFormat: DataFormat?): ByteArray {
        return when {
            (inputData != null && input != null) -> throw IllegalArgumentException("Specify --input-data or --input, not both")
            inputData != null -> inputData(inputData, inputFormat)
            input != null -> inputFile(input, inputFormat)
            else -> throw IllegalArgumentException("Specify --input-data or --input, none was given")
        }
    }

    private fun inputData(inputData: String, inputFormat: DataFormat?): ByteArray {
        return when (inputFormat) {
            null -> DataFormat.detectAndDecode(inputData)
            else -> inputFormat.decode(inputData)
        }
    }

    private fun inputFile(fileName: String, fileFormat: DataFormat?): ByteArray {
        return (fileFormat ?: TEXT).readFile(File(fileName))
    }

}