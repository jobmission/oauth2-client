package com.revengemission.sso.oauth2.client.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@Controller
public class FrontIndexController {

    @Value("${security.oauth2.resource.user-info-uri}")
    private String userInfoUri;

    @Autowired
    OAuth2RestTemplate oAuth2RestTemplate;

    @GetMapping(value = {"/", "/index"})
    public String index(HttpServletRequest request,
                        Model model) {

        return "index";
    }

    @GetMapping(value = "/user")
    public String user(HttpServletRequest request,
                       Model model) {
        Map<String, String> result = new HashMap<>();
        result = oAuth2RestTemplate.getForObject(userInfoUri, result.getClass());
        System.out.println("result= " + result);
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
