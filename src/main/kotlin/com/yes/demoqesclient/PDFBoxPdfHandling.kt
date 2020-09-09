package com.yes.demoqesclient

import org.apache.pdfbox.io.IOUtils
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.*
import java.security.MessageDigest
import java.util.*
import javax.imageio.ImageIO

fun boxPrepareDocument(): DocumentSession {
    val document = PDDocument.load(File(SRC))
    document.documentId = 42L
    println("Document ID: ${document.documentId}")
    val signature = PDSignature()
    signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
    signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
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

    val image = FileInputStream("documents/signature.png")

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
    fout.flush()

    val content = IOUtils.toByteArray(externalSigningSupport.content)
    println("Document length: ${content.size}")
    //println("Document content: ${content?.contentToString()}")
    println("Document encoded content: ${Base64.getEncoder().encodeToString(content)}")
    val digest = MessageDigest.getInstance("SHA-256", BouncyCastleProvider())
    val hash = digest.digest(content)
    //println("Hash: ${hash?.contentToString()}")
    val hashEncoded = Base64.getEncoder().encodeToString(hash)
    println("Encoded PDF Hash: ${hashEncoded}")

    return DocumentSession(hashEncoded, document, externalSigningSupport)
}

fun boxEmbedSignature(documentSession: DocumentSession, signature: String) {
    val sigBytes: ByteArray = Base64.getDecoder().decode(signature)
    documentSession.externalSigningSupport.setSignature(sigBytes)
    documentSession.document.close()
}