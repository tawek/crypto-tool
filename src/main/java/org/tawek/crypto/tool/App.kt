package org.tawek.crypto.tool

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import java.security.Security

@SpringBootApplication(scanBasePackages = ["org.tawek.crypto.tool"])

open class App {

    companion object {

        init {
            Security.insertProviderAt(BouncyCastleProvider(), 2)
        }

        @JvmStatic
        fun main(args: Array<String>) {
            SpringApplication.run(App::class.java, *args)
        }
    }
}