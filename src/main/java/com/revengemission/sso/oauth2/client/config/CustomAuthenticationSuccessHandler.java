package com.revengemission.sso.oauth2.client.config;

import io.micrometer.core.instrument.util.StringUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    RequestCache requestCache = new HttpSessionRequestCache();

    @Value("${oauth2.token.cookie.domain}")
    private String cookieDomain;


    @Autowired
    OAuth2AuthorizedClientService authorizedClientService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication)
        throws IOException, ServletException {

        String redirectUrl = "";
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null && StringUtils.isNotEmpty(savedRequest.getRedirectUrl())) {
            redirectUrl = savedRequest.getRedirectUrl();
        }


        // 根据需要设置 cookie,js携带token直接访问api接口等
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthorizedClient client = authorizedClientService
                .loadAuthorizedClient(
                    ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId(),
                    authentication.getName());
            String token = client.getAccessToken().getTokenValue();
            Cookie tokenCookie = new Cookie("access_token", token);
            tokenCookie.setHttpOnly(true);
            tokenCookie.setDomain(cookieDomain);
            tokenCookie.setPath("/");
            response.addCookie(tokenCookie);
        }

        //设置回调成功的页面，
        if (StringUtils.isNotEmpty(redirectUrl)) {
            super.onAuthenticationSuccess(request, response, authentication);
        } else {
            response.sendRedirect("/");
        }

    }

}
