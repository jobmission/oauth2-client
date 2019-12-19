package com.revengemission.sso.oauth2.client.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * 刷新过期access_token
 */
@Component
public class RefreshExpiredTokenFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RefreshExpiredTokenFilter.class);

    @Value("${oauth2.token.cookie.domain}")
    private String cookieDomain;

    @Autowired
    private OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    private Duration accessTokenExpiresSkew = Duration.ofMillis(10000);

    private Clock clock = Clock.systemUTC();

    @Autowired
    OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService;

    private DefaultRefreshTokenTokenResponseClient accessTokenResponseClient;

    public RefreshExpiredTokenFilter() {
        super();
        this.accessTokenResponseClient = new DefaultRefreshTokenTokenResponseClient();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        log.debug("entering Refresh ExpiredToken Filter......");
        /**
         * check if authentication is done.
         */
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (null != authentication && authentication instanceof OAuth2AuthenticationToken) {

            OAuth2AuthenticationToken oldOAuth2Token = (OAuth2AuthenticationToken) authentication;
            OAuth2AuthorizedClient authorizedClient = this.oAuth2AuthorizedClientService
                .loadAuthorizedClient(oldOAuth2Token.getAuthorizedClientRegistrationId(), oldOAuth2Token.getName());
            /**
             * Check if token existing token is expired.
             */
            if (authorizedClient != null && isExpired(authorizedClient.getAccessToken())) {

                log.info("===================== Token Expired , going to refresh");
                ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
                /*
                 * Call Auth server token endpoint to refresh token.
                 */
                OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(clientRegistration, authorizedClient.getAccessToken(), authorizedClient.getRefreshToken());
                OAuth2AccessTokenResponse accessTokenResponse = this.accessTokenResponseClient.getTokenResponse(refreshTokenGrantRequest);

                OAuth2User newOAuth2User = oAuth2UserService.loadUser(new OAuth2UserRequest(clientRegistration, accessTokenResponse.getAccessToken()));

                log.info("===================== Token Refresh Done !");
                /*
                 * Create new authentication(OAuth2AuthenticationToken).
                 */
                OAuth2AuthenticationToken updatedUser = new OAuth2AuthenticationToken(newOAuth2User, newOAuth2User.getAuthorities(), oldOAuth2Token.getAuthorizedClientRegistrationId());
                /*
                 * Update access_token and refresh_token by saving new authorized client.
                 */
                OAuth2AuthorizedClient updatedAuthorizedClient = new OAuth2AuthorizedClient(clientRegistration,
                    oldOAuth2Token.getName(), accessTokenResponse.getAccessToken(),
                    accessTokenResponse.getRefreshToken());
                this.oAuth2AuthorizedClientService.saveAuthorizedClient(updatedAuthorizedClient, updatedUser);
                /*
                 * Set new authentication in SecurityContextHolder.
                 */
                SecurityContextHolder.getContext().setAuthentication(updatedUser);

                Cookie tokenCookie = new Cookie("access_token", accessTokenResponse.getAccessToken().getTokenValue());
                tokenCookie.setHttpOnly(true);
                tokenCookie.setDomain(cookieDomain);
                tokenCookie.setPath("/");
                response.addCookie(tokenCookie);
            }

        }
        log.debug("exit Refresh ExpiredToken Filter......");
        filterChain.doFilter(request, response);
    }

    private Boolean isExpired(OAuth2AccessToken oAuth2AccessToken) {
        Instant now = this.clock.instant();
        Instant expiresAt = oAuth2AccessToken.getExpiresAt();
        return now.isAfter(expiresAt.minus(this.accessTokenExpiresSkew));
    }

}
