package org.tawek.crypto.tool.completion

import kotlin.reflect.KClass

@Target(AnnotationTarget.VALUE_PARAMETER)
@Retention(AnnotationRetention.RUNTIME)
annotation class Constants(
    val value: KClass<*>
)
