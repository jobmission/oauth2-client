package com.revengemission.sso.oauth2.client.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@Controller
public class FrontIndexController {


    @GetMapping(value = {"/", "/index"})
    public String index(HttpServletRequest request,
                        Model model) {

        return "index";
    }

    @GetMapping(value = "/user")
    public String user(HttpServletRequest request,
                       Principal principal,
                       Model model) {
        return "securedPage";
    }

    @GetMapping(value = "/error")
    public String error(HttpServletRequest request,
                        Model model) {


        return "securedPage";
    }

    @RequestMapping(value = "/loginError", method = RequestMethod.GET)
    public String loginError(Model model) {
        return "loginError";
    }
}
