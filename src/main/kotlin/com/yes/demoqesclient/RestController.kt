package com.yes.demoqesclient

import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.*
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.servlet.view.RedirectView
import org.springframework.web.util.UriComponentsBuilder

@RestController
@SessionAttributes("oauthSession", "documentSession")
class RestController {
    data class Identity(val iss: String = "")
    data class RemoteSignatureCreation(
            val qtsp_id: String = "",
            val signDoc: String = "",
            val conformance_levels_supported: Set<String> = setOf()
    )

    data class ServiceConfiguration(
            val identity: Identity = Identity(),
            val remote_signature_creation: Set<RemoteSignatureCreation> = setOf()
    )

    @GetMapping("/qes/ac")
    fun accountChooserResult(
            @RequestParam issuer_url: String,
            model: Model,
            @ModelAttribute("documentSession") docSess: DocumentSession
    ): RedirectView {
        println("Issuer URL: ${issuer_url}")

        val restTemplate = RestTemplate()
        // Get Service Configuration
        val serviceConfigurationEntity: ResponseEntity<ServiceConfiguration> = restTemplate.exchange(
                "https://api.sandbox.yes.com/service-configuration/v1/?iss=${issuer_url}",
                HttpMethod.GET,
                null,
                ServiceConfiguration::class.java
        )

        val serviceConfiguration = serviceConfigurationEntity.body
        // Security check
        if (serviceConfigurationEntity.statusCode != HttpStatus.OK || serviceConfiguration == null) {
            throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR)
        }
        println(serviceConfiguration)

        val issuerUrl = serviceConfiguration.identity.iss

        val oauthConfiguration: OAuthConfiguration? = restTemplate.getForObject(
                "${issuerUrl}/.well-known/oauth-authorization-server",
                OAuthConfiguration::class.java
        )

        // Security check
        if (oauthConfiguration == null || oauthConfiguration.issuer != issuerUrl) {
            throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR)
        }

        println(oauthConfiguration)

        val oauthSession = OAuthSession(oauthConfiguration)
        println("OAuthSession: ${oauthSession}")
        model.addAttribute("oauthSession", oauthSession)

        val requestURI = pushedAuthRequest(
                oauthConfiguration.pushed_authorization_request_endpoint,
                oauthSession,
                docSess
        )

        val builder = UriComponentsBuilder
                .fromUriString(oauthConfiguration.authorization_endpoint)
                .queryParam("request_uri", requestURI)
                .queryParam("client_id", clientID)
                .queryParam("response_type", "code")
                .encode()
                .build()

        val redirectView = RedirectView()
        redirectView.url = builder.toUriString()
        return redirectView
    }
}