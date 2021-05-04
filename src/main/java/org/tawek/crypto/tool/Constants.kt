package org.tawek.crypto.tool

import kotlin.reflect.KClass

@Target(AnnotationTarget.VALUE_PARAMETER)
@Retention(AnnotationRetention.RUNTIME)
annotation class Constants(
    val value: KClass<*>
)
