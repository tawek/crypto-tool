package org.tawek.crypto.tool

import org.jline.terminal.Terminal
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Lazy
import org.springframework.shell.ResultHandler
import org.springframework.shell.standard.ShellComponent
import java.lang.reflect.UndeclaredThrowableException

@ShellComponent
class UndeclaredThrowableResultHandler : ResultHandler<UndeclaredThrowableException> {

    @Autowired
    @Lazy
    lateinit var terminal: Terminal

    override fun handleResult(result: UndeclaredThrowableException) {
        terminal.writer().println(result.cause)
    }
}