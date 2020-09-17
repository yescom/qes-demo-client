package com.yes.demoqesclient

import com.nimbusds.jose.util.IOUtils
import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.auth.SelfSignedTLSClientAuthentication
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import com.nimbusds.openid.connect.sdk.AuthenticationRequest
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser
import net.minidev.json.JSONArray
import net.minidev.json.JSONObject
import org.apache.http.HttpHost
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.tomcat.util.codec.binary.Base64
import java.net.*
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import javax.net.ssl.*
import javax.net.ssl.X509TrustManager as X509TrustManager1

val clientID = "sandbox.yes.com:0b59836f-5c46-46ff-ad84-853405c6f26e"
val redirectURI = "http://localhost:9090/qes/oauth"

data class OAuthSession(
        val oAuthConfiguration: OAuthConfiguration,
        val pkceVerifier: CodeVerifier = CodeVerifier(), val state: State = State(),
        val documentHash: String = ""
)


fun pushedAuthRequest(url: String, oauthSession: OAuthSession, documentSession: DocumentSession): String {
    val endpoint = URI(url)

    // Rich Authorization Request
    val rar = """
        [
           {
              "type":"sign", 
              "locations":[ 
                 "sp:sandbox.yes.com:85ac6820-8518-4aa1-ba85-de4307175b64"
              ],
              "credentialID":"qes_eidas", 
              "documentDigests":[  
                 {
                    "hash":"${documentSession.hash}",
                    "label":"UnsignedDocument"
                 }
              ],
              "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1" 
           }
        ]
    """

    val authRequest = AuthenticationRequest.Builder(
            ResponseType("code"),
            Scope("openid"),
            ClientID(clientID),
            URI(redirectURI)
    )
            .codeChallenge(oauthSession.pkceVerifier, CodeChallengeMethod.S256)
            .state(oauthSession.state)
            .customParameter("authorization_details", rar)
            .build()

    val clientAuth = SelfSignedTLSClientAuthentication(
            ClientID(clientID),
            loadCertificate()
    )

    val sslContext = createSSLContext()

    val httpRequest = PushedAuthorizationRequest(
            endpoint, clientAuth, authRequest
    ).toHTTPRequest().apply {
        sslSocketFactory = sslContext.socketFactory
    }
    // httpRequest.proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", 8080))
    // httpRequest.hostnameVerifier = NoopHostnameVerifier.INSTANCE
    val httpResponse = httpRequest.send()

    val regResponse = PushedAuthorizationResponse.parse(httpResponse)

    if (!regResponse.indicatesSuccess()) {
        println("PAR request failed: ${regResponse.toErrorResponse().errorObject}")
        throw Exception()
    }

    val successResponse = regResponse.toSuccessResponse()

    println("Request URI: ${successResponse.requestURI.toASCIIString()}")
    println("Request URI expires in: ${successResponse.lifetime} seconds")

    return successResponse.requestURI.toASCIIString()
}

fun loadCertificate(): X509Certificate {
    val fact = CertificateFactory.getInstance("X.509")
    val inputStream = ClassLoader.getSystemClassLoader().getResourceAsStream("certificate/cert.pem")
    return fact.generateCertificate(inputStream) as X509Certificate
}

fun loadPrivateKey(): PrivateKey {
    val inputStream = ClassLoader.getSystemClassLoader().getResourceAsStream("certificate/key.pem")
    val pemPrivateKey = IOUtils.readInputStreamToString(inputStream, StandardCharsets.US_ASCII).run {
        val tmp = this.replace("-----BEGIN PRIVATE KEY-----", "")
        tmp.replace("-----END PRIVATE KEY-----", "")
    }
    val buffer = Base64.decodeBase64(pemPrivateKey)
    val spec: PKCS8EncodedKeySpec = PKCS8EncodedKeySpec(buffer)
    val kf: KeyFactory = KeyFactory.getInstance("RSA")
    return kf.generatePrivate(spec)
}

fun createSSLContext(): SSLContext {
    // Store the private key together with the certificate
    val ks = KeyStore.getInstance("JKS")
    ks.load(null) // init

    ks.setKeyEntry(
            "client-auth",
            loadPrivateKey(),
            CharArray(0),
            arrayOf<Certificate>(loadCertificate())
    )

    // Key manager factory for the SSL context
    val kmf: KeyManagerFactory = KeyManagerFactory.getInstance("SunX509")
    kmf.init(ks, CharArray(0))

    // Trust manager factory for the SSL context
    val tmf: TrustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(null as KeyStore?) // null here initialises the TMF with the default trust store.

    // *********** Only for Debugging *********************************
    // Create a trust manager that does not validate certificate chains
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager1 {
        @Throws(CertificateException::class)
        override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {
        }

        @Throws(CertificateException::class)
        override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {
        }

        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> {
            return arrayOf()
        }
    })
    // *****************************************************************

    // Create a new SSL context
    val sslContext: SSLContext = SSLContext.getInstance("TLS")
    sslContext.init(kmf.keyManagers, tmf.trustManagers, SecureRandom())
    return sslContext
}


fun fetchToken(code: String, oauthSession: OAuthSession): String {
    val tokenEndpoint = URI(oauthSession.oAuthConfiguration.token_endpoint)

    val parsedCode = AuthorizationCode(code)
    val callback = URI(redirectURI)
    val codeGrant = AuthorizationCodeGrant(parsedCode, callback, oauthSession.pkceVerifier)

    val clientAuth = SelfSignedTLSClientAuthentication(
            ClientID(clientID),
            loadCertificate()
    )

    val sslContext = createSSLContext()

    val httpRequest = TokenRequest(tokenEndpoint, clientAuth, codeGrant).toHTTPRequest().apply {
        sslSocketFactory = sslContext.socketFactory
    }
    val tokenResponse = OIDCTokenResponseParser.parse(httpRequest.send())

    if (!tokenResponse.indicatesSuccess()) {
        val errorResponse = tokenResponse.toErrorResponse()
        println(errorResponse.toJSONObject())
        throw Exception()
    }

    val successResponse = tokenResponse.toSuccessResponse()

    val accessToken = successResponse.tokens.accessToken
    println("Access Token: ${accessToken.value}")
    return accessToken.value
}
