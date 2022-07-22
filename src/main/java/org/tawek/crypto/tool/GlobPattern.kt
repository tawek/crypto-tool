package org.tawek.crypto.tool

import java.util.regex.Pattern

/**
 * Handles '*' and '?' wildcards in glob patterns.
 */
object GlobPattern {
    /**
     * Compiles glob pattern into a regular expression.
     * @param glob glob pattern
     * @return regular expression
     * @throws IllegalArgumentException if pattern is invalid
     */
    @JvmStatic
    fun compile(glob: String?): Pattern {
        requireNotNull(glob) { "glob must not be null" }
        val regex = StringBuilder()
        regex.append('^')
        for (i in 0 until glob.length) {
            val c = glob[i]
            when (c) {
                '*' -> regex.append(".*")
                '?' -> regex.append('.')
                '.', '(', ')', '+', '|', '$', '^', '\\', '{', '}', '[', ']', '#', ' ', '\t' -> {
                    regex.append('\\')
                    regex.append(c)
                }
                else -> regex.append(c)
            }
        }
        regex.append('$')
        return Pattern.compile(regex.toString())
    }

    @JvmStatic
    fun all(): Pattern {
        return Pattern.compile(".*")
    }
}