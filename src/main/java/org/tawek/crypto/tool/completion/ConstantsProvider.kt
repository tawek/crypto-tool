package org.tawek.crypto.tool.completion

import org.springframework.core.MethodParameter
import org.springframework.shell.CompletionContext
import org.springframework.shell.CompletionProposal
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ValueProvider
import java.lang.reflect.Field
import java.lang.reflect.Modifier

@ShellComponent
class ConstantsProvider : ValueProvider {

    override fun supports(parameter: MethodParameter?, completionContext: CompletionContext?): Boolean {
        return parameter != null && parameter.parameterType == String::class.java && getAnnotation(parameter) != null
    }

    private fun getAnnotation(parameter: MethodParameter): Constants? {
        return parameter.getParameterAnnotation(Constants::class.java)
    }

    override fun complete(
        parameter: MethodParameter?,
        completionContext: CompletionContext?,
        hints: Array<out String>?
    ): MutableList<CompletionProposal> {
        val annotation = getAnnotation(parameter!!)!!
        return annotation.value.java.declaredFields
            .filter { it.type == String::class.java }
            .filter { Modifier.isStatic(it.modifiers) }
            .map { makeProposal(it) }
            .filterNotNull()
            .toMutableList()
    }

    private fun makeProposal(it: Field): CompletionProposal? {
        it.trySetAccessible()
        val value = it.get(null)
        return CompletionProposal(value as String)
            .description(it.name)
    }

}
