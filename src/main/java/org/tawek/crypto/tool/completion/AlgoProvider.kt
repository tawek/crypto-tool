package org.tawek.crypto.tool.completion

import org.springframework.core.MethodParameter
import org.springframework.shell.CompletionContext
import org.springframework.shell.CompletionProposal
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ValueProvider
import java.security.Provider
import java.security.Security
import javax.crypto.Cipher
import kotlin.streams.toList

@ShellComponent
class AlgoProvider : ValueProvider {

    private val cachedCipherCompletions: List<CompletionProposal> by lazy { computeCipherCompletions() }

    override fun supports(parameter: MethodParameter?, completionContext: CompletionContext?): Boolean {
        return parameter != null && parameter.parameterType == String::class.java && getAnnotation(parameter) != null
    }

    private fun getAnnotation(parameter: MethodParameter): Algo? {
        return parameter.getParameterAnnotation(Algo::class.java)
    }

    private fun computeCipherCompletions(): List<CompletionProposal> {
        val serviceCompletions = getServiceCompletions("Cipher")

        val transformationCompletions = getCipherTransformationCompletions()

        // add all completions to the list
        // but it should be distinct
        // and sorted ascending

        return (serviceCompletions + transformationCompletions)
            .distinct()
            .sortedBy { it.value() }
    }

    private fun getCipherTransformationCompletions() = generateTransformations()
        .stream()
        .map(::makeCipher)
        .filter { it != null }
        .map { makeProposal(it!!) }
        .toList()

    override fun complete(
        parameter: MethodParameter?,
        completionContext: CompletionContext?,
        hints: Array<out String>?
    ): List<CompletionProposal> {
        val annotation = getAnnotation(parameter!!)!!
        return if (annotation.value != "Cipher") {
            getServiceCompletions(annotation.value)
        } else {
            cachedCipherCompletions
        }
    }

    private fun getServiceCompletions(type: String) = Security.getProviders()
        .flatMap { it.services }
        .filter { it.type == type }
        .map { makeProposal(it) }
        .toList()

    private fun makeProposal(it: Cipher): CompletionProposal =
        CompletionProposal(it.algorithm).description(it.provider.name)

    private fun makeCipher(algo: String): Cipher? {
        return try {
            return Cipher.getInstance(algo)
        } catch (e: Exception) {
            null
        }
    }

    private fun generateTransformations(): List<String> {
        val transformations = mutableListOf<String>()
        for (key in keys) {
            for (mode in modes) {
                for (padding in paddings) {
                    transformations.add("$key/$mode/$padding")
                }
            }
        }
        return transformations
    }

    // list of all symmetric modes
    private val modes = listOf(
        "ECB", "CBC", "CTR", "GCM", "CCM", "OCB", "CFB", "OFB", "CFB8", "CFB16", "CFB32", "CFB64", "CFB128", "OFB8", "OFB16", "OFB32", "OFB64", "OFB128"
    )

    // list of all padding modes
    private val paddings = listOf(
        "NoPadding", "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding", "ISO7816-4Padding", "TBCPadding", "ZeroBytePadding"
    )

    // list of all keys
    private val keys = listOf(
        "AES", "ARCFOUR", "Blowfish", "DES", "DESede", "RC2", "RC4", "RC5", "RSA"
    )

    private fun makeProposal(service: Provider.Service): CompletionProposal {
        return CompletionProposal(service.algorithm)
            .description(service.provider.name)
    }

}
