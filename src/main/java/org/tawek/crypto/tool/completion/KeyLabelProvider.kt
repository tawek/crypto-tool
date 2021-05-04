package org.tawek.crypto.tool.completion

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.core.MethodParameter
import org.springframework.shell.CompletionContext
import org.springframework.shell.CompletionProposal
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ValueProvider
import org.tawek.crypto.tool.KeystoreManager

@ShellComponent
class KeyLabelProvider : ValueProvider {

    @Autowired
    lateinit var keystoreManager: KeystoreManager

    override fun supports(parameter: MethodParameter?, completionContext: CompletionContext?): Boolean {
        return keystoreManager.isLoaded() &&  parameter != null && parameter.parameterType == String::class.java && getAnnotation(parameter) != null
    }

    private fun getAnnotation(parameter: MethodParameter): KeyLabel? {
        return parameter.getParameterAnnotation(KeyLabel::class.java)
    }

    override fun complete(
        parameter: MethodParameter?,
        completionContext: CompletionContext?,
        hints: Array<out String>?
    ): MutableList<CompletionProposal> {
        val ks = keystoreManager.keystore()
        return ks.aliases().toList().map {
            CompletionProposal(it).description(KeystoreManager.describeKey(ks, it))
        }.toMutableList()
    }

}
