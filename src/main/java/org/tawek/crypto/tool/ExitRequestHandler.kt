package org.tawek.crypto.tool

import org.jline.terminal.Terminal
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Lazy
import org.springframework.shell.ExitRequest
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ShellMethod

@ShellComponent
class ExitCommand  {

    @Autowired
    lateinit var keystoreManager: KeystoreManager

    @Autowired
    @Lazy
    lateinit var terminal: Terminal

    @ShellMethod("Exit from shell")
    fun exit(): ExitRequest? {
        if (keystoreManager.modified) {
            terminal.writer().println("Keystore is modified, close or save first")
            return null
        } else {
            return ExitRequest(1)
        }
    }
}