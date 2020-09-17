package com.yes.demoqesclient

import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ModelAttribute
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.SessionAttributes


@Controller
@SessionAttributes("oauthSession", "documentSession")
class MainController {

    @GetMapping("/main")
    fun main(model: Model): String? {
        val docSess = boxPrepareDocument()
        println("Document Session ${docSess}")
        model.addAttribute("documentSession", docSess)
        return "main"
    }

    @GetMapping("/qes/oauth")
    fun fetchToken(
            @RequestParam code: String,
            @RequestParam state: String,
            @RequestParam iss: String,
            model: Model,
            @ModelAttribute("oauthSession") oAuthSession: OAuthSession,
            @ModelAttribute("documentSession") docSess: DocumentSession
    ): String? {
        model.addAttribute("code", code)
        println("OAuthSession: ${oAuthSession}")
        println("Document Session: ${docSess}")

        val accessToken = fetchToken(code, oAuthSession)
        model.addAttribute("access_code", accessToken)

        requestSignature(accessToken, docSess)
        boxEmbedSignature(docSess)

        return "token"
    }

}
