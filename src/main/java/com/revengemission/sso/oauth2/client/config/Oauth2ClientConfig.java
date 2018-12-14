package com.revengemission.sso.oauth2.client.config;

import io.micrometer.core.instrument.util.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Configuration
@EnableOAuth2Client
public class Oauth2ClientConfig {

    @Value("${security.oauth2.client.id}")
    private String id;

    @Value("${security.oauth2.client.access-token-uri}")
    private String accessTokenUri;

    @Value("${security.oauth2.client.client-id}")
    private String clientId;

    @Value("${security.oauth2.client.client-secret}")
    private String clientSecret;

    @Value("#{'${security.oauth2.client.scope}'.split(',')}")
    private List<String> scope;

    @Value("${security.oauth2.client.user-authorization-uri}")
    private String userAuthorizationUri;

    @Value("${security.oauth2.client.check-token-uri}")
    private String checkTokenUrl;

    @Value("${security.oauth2.client.pre-established-redirect-uri}")
    private String preEstablishedRedirectUri;

    @Value("${oauth2.token.cookie.domain}")
    private String cookieDomain;

    @Autowired
    OAuth2ClientContext oAuth2ClientContext;

    RequestCache requestCache = new HttpSessionRequestCache();

    @Bean
    public OAuth2ProtectedResourceDetails oAuth2ProtectedResourceDetails() {
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setId(id);
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setAccessTokenUri(accessTokenUri);
        details.setUserAuthorizationUri(userAuthorizationUri);
        details.setScope(scope);
        return details;
    }


    /**
     * 注册处理redirect uri的filter
     *
     * @return
     */
    @Bean
    public OAuth2ClientAuthenticationProcessingFilter oauth2ClientAuthenticationProcessingFilter() {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(preEstablishedRedirectUri);

        RemoteTokenServices tokenService = new RemoteTokenServices();
        tokenService.setCheckTokenEndpointUrl(checkTokenUrl);
        tokenService.setClientId(clientId);
        tokenService.setClientSecret(clientSecret);
        tokenService.setRestTemplate(oAuth2RestTemplate());


        filter.setRestTemplate(oAuth2RestTemplate());
        filter.setTokenServices(tokenService);


        //设置回调成功的页面，设置token cookie,js携带token直接访问api接口等
        filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler() {
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException, IOException, ServletException {

                String redirectUrl = "/";
                SavedRequest savedRequest = requestCache.getRequest(request, response);
                if (savedRequest != null && StringUtils.isNotEmpty(savedRequest.getRedirectUrl())) {
                    redirectUrl = savedRequest.getRedirectUrl();
                }

                if (authentication instanceof OAuth2Authentication) {
                    String token = ((OAuth2AuthenticationDetails) authentication.getDetails()).getTokenValue();
                    Cookie tokenCookie = new Cookie("access_token", token);
                    tokenCookie.setHttpOnly(true);
                    tokenCookie.setDomain(cookieDomain);
                    tokenCookie.setPath("/");
                    response.addCookie(tokenCookie);
                }

                this.setDefaultTargetUrl(redirectUrl);
                super.onAuthenticationSuccess(request, response, authentication);
            }
        });
        return filter;
    }

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }


    @Bean
    public OAuth2RestTemplate oAuth2RestTemplate() {
        return new OAuth2RestTemplate(oAuth2ProtectedResourceDetails(), oAuth2ClientContext);
    }


}
