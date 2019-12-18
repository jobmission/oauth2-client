package com.revengemission.sso.oauth2.client.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.function.client.WebClient;

import javax.servlet.http.HttpServletRequest;

@Controller
public class FrontIndexController {

    @Autowired
    WebClient webClient;

    @GetMapping(value = {"/", "/index"})
    public String index(HttpServletRequest request,
                        OAuth2AuthenticationToken oAuth2AuthenticationToken,
                        Model model) {
        return "index";
    }

    @GetMapping(value = "/user")
    public String user(HttpServletRequest request,
                       OAuth2AuthenticationToken oAuth2AuthenticationToken,
                       @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
                       Model model) {
        return "securedPage";
    }

    @ResponseBody
    @GetMapping(value = "/resource")
    public Object resource(HttpServletRequest request,
                           OAuth2AuthenticationToken oAuth2AuthenticationToken,
                           @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
                           Model model) {
        Object object = webClient.get().uri("http://localhost:10580/coupon/list").attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient)).retrieve().bodyToMono(Object.class);
        return object;
    }

}
