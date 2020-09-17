package com.yes.demoqesclient

import com.fasterxml.jackson.annotation.JsonProperty
import org.apache.http.client.HttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSDictionary
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.cos.COSStream
import org.apache.pdfbox.examples.signature.SigUtils
import org.apache.pdfbox.examples.signature.validation.CertInformationCollector
import org.apache.pdfbox.io.IOUtils
import org.apache.pdfbox.io.ScratchFile
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.JSONArray
import org.json.JSONObject
import org.springframework.http.HttpEntity
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.web.client.RestTemplate
import org.springframework.web.server.ResponseStatusException
import java.io.*
import java.net.URI
import java.security.MessageDigest
import java.security.Security
import java.util.*
import javax.net.ssl.SSLContext

val SRC = "documents/UnsignedDocument.pdf"
val DEST = "documents/SignedDocument.pdf"
val DEST_WITH_DSS = "documents/SignedWithDSS.pdf"
val SIGNATURE_IMAGE = ClassLoader.getSystemClassLoader().getResource("signature/signature.png")?.path

/**
 * Prepare the PDF document to
 * integrate the CMS object later
 * and calculate the SHA-256 hash.
 */
fun boxPrepareDocument(): DocumentSession {
    val document = PDDocument.load(File(SRC))
    val signature = PDSignature()
    signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
    signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED)
    signature.name = "TestUser"
    signature.location = "Anywhere"
    signature.reason = "Test document signing"
    val date = Calendar.getInstance()
    signature.signDate = date

    val signatureOptions = SignatureOptions()
    val pdfSigProperties = PDVisibleSigProperties()
    pdfSigProperties.signerName("TestUser")
    pdfSigProperties.signerLocation("Anywhere")
    pdfSigProperties.signatureReason("Test document signing")
    pdfSigProperties.preferredSize(0)
    pdfSigProperties.page(0)
    pdfSigProperties.visualSignEnabled(true)

    if (SIGNATURE_IMAGE == null) throw FileNotFoundException("Signature image file not found")
    val image = FileInputStream(SIGNATURE_IMAGE)

    val visibleSig = PDVisibleSignDesigner(SRC, image, 1)
    visibleSig.xAxis(0f).yAxis(0f).zoom(-50f).signatureFieldName("signature")

    pdfSigProperties.setPdVisibleSignature(visibleSig)
    pdfSigProperties.buildSignature()

    signatureOptions.setVisualSignature(pdfSigProperties)
    signatureOptions.page = 0
    signatureOptions.preferredSignatureSize = 12000

    document.addSignature(signature, signatureOptions)

    val fout = FileOutputStream(DEST)
    val externalSigningSupport = document.saveIncrementalForExternalSigning(fout)

    val content = IOUtils.toByteArray(externalSigningSupport.content)
    println("Document length: ${content.size}")

    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(content)
    val hashEncoded = Base64.getEncoder().encodeToString(hash)
    println("Encoded PDF Hash: ${hashEncoded}")

    return DocumentSession(hashEncoded, document, externalSigningSupport)
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

data class RevocationInfo(
        val ocsp: Set<String> = setOf(),
        val crl: Set<String> = setOf()
)
data class SignatureResponse(
        val SignatureObject: Set<String> = setOf(),
        val revocationInfo: RevocationInfo = RevocationInfo()
)

/**
 * Send the PDF hash to the QTSP
 * to get the signature back.
 */
fun requestSignature(accessToken: String, documentSession: DocumentSession) {
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
            DocumentDigests(setOf(documentSession.hash), "2.16.840.1.101.3.4.2.1"),
            "http://uri.etsi.org/19432/v1.1.1#/creationprofile#",
            "P",
            "AdES-B-LT"
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
    documentSession.signature = signature

    val revocationInfo = jsonResponse["revocationInfo"] as JSONObject
    val ocsp = revocationInfo["ocsp"] as JSONArray
    documentSession.ocsp = ocsp
    val crl = revocationInfo["crl"] as JSONArray
    documentSession.crl = crl
    println("OCSPs: ${ocsp}")
    println("CRLs: ${crl}")
}


/**
 * Integrate CMS object
 * into the PDF document.
 */
fun boxEmbedSignature(documentSession: DocumentSession) {
    val sigBytes: ByteArray = Base64.getDecoder().decode(documentSession.signature)
    documentSession.externalSigningSupport.setSignature(sigBytes)
    documentSession.document.close()

    addRevocationInformation(documentSession)
}

/**
 * Add certificates, OCSPs and CRLs to
 * a DSS dictionary.
 */
fun addRevocationInformation(documentSession: DocumentSession) {
    val document = PDDocument.load(File(DEST))

    val docCatalog = document.documentCatalog
    val catalog = docCatalog.cosObject
    catalog.isNeedToBeUpdated = true

    val dss = AddValidationInformation.getOrCreateDictionaryEntry(COSDictionary::class.java, catalog, "DSS")
    dss.setName(COSName.TYPE, "DSS")

    AddValidationInformation.addExtensions(docCatalog)

    // extract certificates from the CMS object and add them to the DSS dictionary
    val certInformationHelper = CertInformationCollector()
    val signature = SigUtils.getLastRelevantSignature(document)
    Security.addProvider(BouncyCastleProvider())
    val certInfo = certInformationHelper.getLastCertInfo(signature, File(DEST).absolutePath)
    val certificates = getAllCertificates(mutableSetOf<ByteArray>(), certInfo)

    val certs = AddValidationInformation.getOrCreateDictionaryEntry(COSArray::class.java, dss, "Certs")
    for (cert in certificates) {
        println("Add certificate: ${cert.contentToString()}")
        val ocspStream = AddValidationInformation.writeDataToStream(cert, document)
        certs.add(ocspStream)
    }

    // add the OCSP responses to the DSS dictionary
    val ocsps = AddValidationInformation.getOrCreateDictionaryEntry(COSArray::class.java, dss, "OCSPs")
    for (ocsp in documentSession.ocsp!!.iterator()) {
        val bytes: ByteArray = Base64.getDecoder().decode((ocsp as String))
        val ocspStream = AddValidationInformation.writeDataToStream(bytes, document)
        ocsps.add(ocspStream)
    }

    // add the CRLs to the DSS dictionary
    val crls = AddValidationInformation.getOrCreateDictionaryEntry(COSArray::class.java, dss, "CRLs")
    for (crl in documentSession.crl!!.iterator()) {
        val bytes: ByteArray = Base64.getDecoder().decode((crl as String))
        val crlStream = AddValidationInformation.writeDataToStream(bytes, document)
        crls.add(crlStream)
    }

    // save changes
    val output = FileOutputStream(DEST_WITH_DSS)
    document.saveIncremental(output)
    output.close()
    document.close()
}

/**
 * Collect all certificates recursively from
 * bottom to top.
 */
fun getAllCertificates(certificates: MutableSet<ByteArray>, certInfo: CertInformationCollector.CertSignatureInformation): MutableSet<ByteArray> {
    println("Certificate: ${certInfo.certificate.subjectDN}")
    var certs = certificates
    certs.add(certInfo.certificate.encoded)
    if (certInfo.alternativeCertChain != null) {
        certs = getAllCertificates(certs, certInfo.alternativeCertChain)
    }
    if (certInfo.certChain != null) {
        certs = getAllCertificates(certs, certInfo.certChain)
    }
    if (certInfo.tsaCerts != null) {
        certs = getAllCertificates(certs, certInfo.tsaCerts)
    }
    return certs
}


data class DocumentSession(
        val hash: String,
        val document: PDDocument,
        val externalSigningSupport: ExternalSigningSupport,
        var signature: String? = null,
        var ocsp: JSONArray? = null,
        var crl: JSONArray? = null
)
