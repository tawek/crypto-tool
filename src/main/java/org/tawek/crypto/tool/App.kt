package org.tawek.crypto.tool

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.Arrays
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.yaml.snakeyaml.util.ArrayUtils
import java.security.Security

@SpringBootApplication
open class App {

    companion object {

        init {
            Security.insertProviderAt(BouncyCastleProvider(), 2)
        }

        @JvmStatic
        fun main(args: Array<String>) {
            val newargs = Arrays.append(args, "--spring.shell.command.quit.enabled=false")
            SpringApplication.run(App::class.java, *newargs)
        }
    }
}