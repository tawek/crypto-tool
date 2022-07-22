package org.tawek.crypto.tool

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ShellMethod
import org.springframework.shell.standard.ShellOption
import org.tawek.crypto.tool.GlobPattern.compile
import java.security.Provider
import java.security.Security
import java.util.regex.Pattern

@ShellComponent
class ProviderCommands {

    @Autowired
    private lateinit var io: IO

    @Autowired
    private lateinit var providerSelection: ProviderSelection

    /**
     * List registered providers
     */
    @ShellMethod("List providers")
    fun listProviders(
        @ShellOption(defaultValue = "*", help = "Glob pattern to filter providers") filter: String,
        @ShellOption(defaultValue = "short", help = "Select what is printed short/full") format: String
    ) {
        println("Providers:")
        val mask = compile(filter)
        var index = 1
        for (provider in Security.getProviders()) {
            if (!matches(mask, provider)) {
                continue
            }
            showProvider(index, provider, format)
            index++
        }
    }

    private val horizontalLine = "-----------------------------------------------------"

    private fun showProvider(
        index: Int,
        provider: Provider,
        format: String = "full"
    ) {
        println(horizontalLine)
        println("#" + index + " : " + provider.name)
        println(horizontalLine)
        println("Info:" + provider.info)
        println("Version:" + provider.versionStr)
        if (format == "full") {
            println(horizontalLine)
            println("Services:")
            for (service in provider.services) {
                println(service.algorithm + " : " + service.className)
            }
        }
        println(horizontalLine)
        println("")
    }

    @ShellMethod("Select provider")
    fun selectProvider(
        @ShellOption(defaultValue = ShellOption.NULL, help = "Provider name") name: String?
    ) {
        val provider = Security.getProvider(name)
        providerSelection.provider = provider
        println("Provider selected: " + provider.name)
    }

    @ShellMethod("Unselect provider")
    fun unselectProvider() {
        providerSelection.provider = null
        println("Provider unselected")
    }

    @ShellMethod("Show selected provider")
    fun showSelectedProvider(
        @ShellOption(
            defaultValue = "short",
            help = "Select format of displayed info short/full"
        ) format: String
    ) {
        val provider = providerSelection.provider
        if (provider == null) {
            println("No provider selected")
            return
        }
        showProvider(indexOfProvider(provider), provider, format)
    }

    @ShellMethod("Show provider services")
    fun showServices(
        @ShellOption(defaultValue = "*") filter: String
    ) {
        val provider = providerSelection.provider
        if (provider == null) {
            println("No provider selected")
            return
        } else {
            val mask = compile(filter)
            for (service in provider.services) {
                if (mask.matcher(service.algorithm).matches()) {
                    println(service.algorithm + " : " + service.className)
                }
            }
        }
    }

    private fun indexOfProvider(provider: Provider): Int {
        var index = 1
        for (p in Security.getProviders()) {
            if (p == provider) {
                return index
            }
            index++
        }
        return -1
    }


    private fun matches(filter: Pattern, provider: Provider): Boolean {
        return filter.matcher(provider.name).matches()
    }

    private fun println(horizontalLine: String) {
        io.println(horizontalLine)
    }
}