package com.yes.demoqesclient

import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ModelAttribute
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.SessionAttributes


@Controller
@SessionAttributes("oauthSession")
class MainController {

    @GetMapping("/main")
    fun main(): String? {
        return "main"
    }

    @GetMapping("/qes/oauth")
    fun fetchToken(
            @RequestParam code: String,
            @RequestParam state: String,
            @RequestParam iss: String,
            model: Model,
            @ModelAttribute("oauthSession") oAuthSession: OAuthSession
    ): String? {
        model.addAttribute("code", code)
        println("OAuthSession: ${oAuthSession}")

        val accessCode = fetchToken(code, oAuthSession)
        model.addAttribute("access_code", accessCode)

        return "token"
    }

}