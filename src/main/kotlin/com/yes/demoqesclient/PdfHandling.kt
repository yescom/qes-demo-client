package com.yes.demoqesclient

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonProperty
import com.itextpdf.kernel.pdf.*
import com.itextpdf.signatures.ExternalBlankSignatureContainer
import com.itextpdf.signatures.PdfSignatureAppearance
import com.itextpdf.signatures.PdfSigner
import org.apache.http.HttpHost
import org.apache.http.client.HttpClient
import org.apache.http.conn.ssl.AllowAllHostnameVerifier
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import java.io.FileOutputStream
import java.io.InputStream
import java.net.URI
import org.apache.http.impl.client.HttpClients
import org.json.JSONArray
import org.json.JSONObject
import org.springframework.http.HttpEntity
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.client.RestTemplate
import org.springframework.web.server.ResponseStatusException
import java.net.InetSocketAddress
import java.net.Proxy
import java.security.MessageDigest
import java.util.*
import javax.net.ssl.SSLContext

val SRC = "documents/UnsignedDocument.pdf"
val PREPARED = "documents/prepared.pdf"
val DEST = "documents/SignedDocument.pdf"

fun prepareDocument(): String {
    var hash: ByteArray? = null
    val reader = PdfReader(SRC)
    val fout = FileOutputStream(PREPARED)

    val sp = StampingProperties()
    sp.useAppendMode()

    val pdfSigner = PdfSigner(reader, fout, sp)
    pdfSigner.fieldName = "Signature"

    val appearance: PdfSignatureAppearance = pdfSigner.signatureAppearance
    appearance.pageNumber = 1

    val estimatedSize = 12000
    val container = ExternalHashingSignatureContainer(PdfName.Adobe_PPKLite, PdfName.Adbe_pkcs7_detached)
    pdfSigner.signExternalContainer(container, estimatedSize)
    println("PDF Hash: ${container.hash!!.contentToString()}")
    val encodedHash = Base64.getEncoder().encodeToString(container.hash)
    println("PDF Hash Encoded: ${encodedHash}")
    return encodedHash
}

class ExternalHashingSignatureContainer(filter: PdfName, subFilter: PdfName) : ExternalBlankSignatureContainer(filter, subFilter) {

    var hash: ByteArray? = null

    override fun modifySigningDictionary(signDic: PdfDictionary?) {
        super.modifySigningDictionary(signDic)

        for (key in signDic!!.keySet()) {
            println("Signing Dictionary: ${key} - ${signDic.getAsString(key)}")
        }
    }

    override fun sign(data: InputStream): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        println("InputStream available: ${data.available()}")

        var tmp = data.readAllBytes()
        var bytes = ByteArray(0)
        while (tmp.size != 1) {
            bytes += tmp
            tmp = data.readAllBytes()
        }
        println("Bytes length: ${bytes.size}")

        hash = md.digest(bytes)
        return ByteArray(0)
   }
}

data class DocumentDigests(
        val hashes: Set<String> = setOf(),
        val hashAlgorithmOID: String = ""
)
data class SignatureRequest(
        @get:JsonProperty("SAD") val SAD: String = "",
        val credentialID: String = "",
        val documentDigests: DocumentDigests = DocumentDigests(),
        val profile: String = "",
        val signature_format: String = "",
        val conformance_level: String = ""
)

data class RevocationInfo(val ocsp: Set<String> = setOf())
data class SignatureResponse(
        val SignatureObject: Set<String> = setOf(),
        val revocationInfo: RevocationInfo = RevocationInfo(),
        val crl: Set<String> = setOf()
)

fun requestSignature(accessToken: String, hash: String): String {
    val endpoint = URI("https://yesqtsp.test.namirialtsp.com/qtsp-rest-api/signature/signDoc")

    val sslContext: SSLContext = createSSLContext()
    val client: HttpClient = HttpClients.custom()
            .setSSLContext(sslContext)
            //.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
            //.setProxy(HttpHost("127.0.0.1", 8080))
            .build()
    val requestFactory = HttpComponentsClientHttpRequestFactory()
    requestFactory.httpClient = client
    val restTemplate: RestTemplate = RestTemplate(requestFactory)

    // make signature request to the QTSP
    val payload = SignatureRequest(
            accessToken,
            "qes_eidas",
            DocumentDigests(setOf(hash), "2.16.840.1.101.3.4.2.1"),
            "http://uri.etsi.org/19432/v1.1.1#/creationprofile#",
            "P",
            "AdES-B-T"
    )
    val entity = HttpEntity<SignatureRequest>(payload, null)
    // TODO use SignatureResponse class to parse the response (somehow failed here)
    val response: ResponseEntity<String> = restTemplate.exchange(
            endpoint,
            HttpMethod.POST,
            entity,
            String::class.java
    )

    if (response.body == null || response.statusCode != HttpStatus.OK) {
        throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR)
    }

    // dirty workaround because parsing with SignatureResponse did not work
    val jsonResponse = JSONObject(response.body)
    val signature = (jsonResponse["SignatureObject"] as JSONArray)[0] as String

    println("Signature Response: ${signature}")
    return signature
}

fun embedSignatureInDocument(signature: String) {
    val sigBytes: ByteArray = Base64.getDecoder().decode(signature)

    val reader = PdfReader(PREPARED)
    val document = PdfDocument(reader)
    val fout = FileOutputStream(DEST)
    PdfSigner.signDeferred(document, "Signature", fout, ExternalPrecalculatedSignatureContainer(sigBytes))
}

class ExternalPrecalculatedSignatureContainer(val cms: ByteArray) : ExternalBlankSignatureContainer(PdfDictionary()) {

    override fun sign(data: InputStream): ByteArray {
        return cms
    }
}


