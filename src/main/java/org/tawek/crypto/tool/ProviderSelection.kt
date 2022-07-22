package org.tawek.crypto.tool

import lombok.Getter
import lombok.Setter
import org.springframework.stereotype.Component
import java.security.Provider

@Component
class ProviderSelection {

    var provider: Provider? = null
}