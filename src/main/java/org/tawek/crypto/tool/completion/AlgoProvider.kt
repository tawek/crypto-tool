package org.tawek.crypto.tool.completion

import org.springframework.core.MethodParameter
import org.springframework.shell.CompletionContext
import org.springframework.shell.CompletionProposal
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ValueProvider
import java.security.Provider
import java.security.Security
import javax.crypto.Cipher

@ShellComponent
class AlgoProvider : ValueProvider {

    override fun supports(parameter: MethodParameter?, completionContext: CompletionContext?): Boolean {
        return parameter != null && parameter.parameterType == String::class.java && getAnnotation(parameter) != null
    }

    private fun getAnnotation(parameter: MethodParameter): Algo? {
        return parameter.getParameterAnnotation(Algo::class.java)
    }

    override fun complete(
        parameter: MethodParameter?,
        completionContext: CompletionContext?,
        hints: Array<out String>?
    ): MutableList<CompletionProposal> {
        val annotation = getAnnotation(parameter!!)!!
        return Security.getProviders()
            .flatMap { it.services }
            .filter { it.type == annotation.value }
            .map { makeProposal(it) }
            .toMutableList()
    }

    private fun makeProposal(service: Provider.Service): CompletionProposal {
        return CompletionProposal(service.algorithm)
            .description(service.provider.name)
    }

}
