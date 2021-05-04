package org.tawek.crypto.tool.completion

@Target(AnnotationTarget.VALUE_PARAMETER)
@Retention(AnnotationRetention.RUNTIME)
annotation class Algo(val value: String)
