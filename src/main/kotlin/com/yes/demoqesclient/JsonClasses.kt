package com.yes.demoqesclient

data class OAuthConfiguration(
        val authorization_endpoint: String = "",
        val token_endpoint: String = "",
        val registration_endpoint: String = "",
        val introspection_endpoint: String = "",
        val revocation_endpoint: String = "",
        val pushed_authorization_request_endpoint: String = "",
        val issuer: String = "",
        val jwks_uri: String = "",
        val scopes_supported: Set<String> = setOf(),
        val response_types_supported: Set<String> = setOf(),
        val response_modes_supported: Set<String> = setOf(),
        val grant_types_supported: Set<String> = setOf(),
        val code_challenge_methods_supported: Set<String> = setOf(),
        val token_endpoint_auth_methods_supported: Set<String> = setOf(),
        val token_endpoint_auth_signing_alg_values_supported: Set<String> = setOf(),
        val request_object_signing_alg_values_supported: Set<String> = setOf(),
        val request_object_encryption_alg_values_supported: Set<String> = setOf(),
        val request_object_encryption_enc_values_supported: Set<String> = setOf(),
        val ui_locales_supported: Set<String> = setOf(),
        val request_parameter_supported: Boolean = false,
        val require_request_uri_registration: Boolean = false,
        val tls_client_certificate_bound_access_tokens: Boolean = false,
        val request_uri_quota: Long = 0,
        val subject_types_supported: Set<String> = setOf(),
        val userinfo_endpoint: String = "",
        val acr_values_supported: Set<String> = setOf(),
        val id_token_signing_alg_values_supported: Set<String> = setOf(),
        val id_token_encryption_alg_values_supported: Set<String> = setOf(),
        val id_token_encryption_enc_values_supported: Set<String> = setOf(),
        val userinfo_signing_alg_values_supported: Set<String> = setOf(),
        val userinfo_encryption_alg_values_supported: Set<String> = setOf(),
        val userinfo_encryption_enc_values_supported: Set<String> = setOf(),
        val display_values_supported: Set<String> = setOf(),
        val claim_types_supported: Set<String> = setOf(),
        val claims_supported: Set<String> = setOf(),
        val claims_parameter_supported: Boolean = false,
        val frontchannel_logout_support: Boolean = false,
        val frontchannel_logout_session_support: Boolean = false,
        val backchannel_logout_supported: Boolean = false,
        val backchannel_logout_session_supported: Boolean = false,
        val verified_claims_supported: Boolean = false
)