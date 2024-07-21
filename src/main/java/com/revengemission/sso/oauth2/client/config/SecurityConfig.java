package com.revengemission.sso.oauth2.client.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;

import java.util.*;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private Logger log = LoggerFactory.getLogger(this.getClass());

    @Autowired
    CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    ObjectMapper objectMapper;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(requestMatcherRegistry ->
                requestMatcherRegistry.requestMatchers("/", "/login/**", "/oauth2/**", "/assets/**").permitAll()
                    .anyRequest().authenticated())
            .csrf(AbstractHttpConfigurer::disable)
            .logout(logoutCustomizer ->
                logoutCustomizer
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/"))
            .oauth2Login(oauth2Login ->
                oauth2Login.successHandler(customAuthenticationSuccessHandler)
                    .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig.userService(oauth2UserService())));

        return http.build();
    }

    /**
     * 从access_token中直接抽取角色等信息
     * https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2login-advanced-map-authorities-oauth2userservice
     *
     * @return
     */
    @SuppressWarnings("unchecked")
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {

        return (userRequest) -> {
            String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
            if (!StringUtils.hasText(userNameAttributeName)) {
                userNameAttributeName = "sub";
            }
            OAuth2AccessToken accessToken = userRequest.getAccessToken();
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
            try {
                SignedJWT jwt = SignedJWT.parse(accessToken.getTokenValue());
                String claimJsonString = jwt.getJWTClaimsSet().toString();

                Collection<String> roles = new HashSet<>();
                JsonNode treeNode = objectMapper.readTree(claimJsonString);
                List<JsonNode> jsonNodes = treeNode.findValues("roles");
                jsonNodes.forEach(jsonNode -> {
                    if (jsonNode.isArray()) {
                        jsonNode.elements().forEachRemaining(e -> {
                            roles.add(e.asText());
                        });
                    } else {
                        roles.add(jsonNode.asText());
                    }
                });

                jsonNodes = treeNode.findValues("authorities");
                jsonNodes.forEach(jsonNode -> {
                    if (jsonNode.isArray()) {
                        jsonNode.elements().forEachRemaining(e -> {
                            roles.add(e.asText());
                        });
                    } else {
                        roles.add(jsonNode.asText());
                    }
                });

                for (String authority : roles) {
                    grantedAuthorities.add(new SimpleGrantedAuthority(authority));
                }
                Map<String, Object> userAttributes = new HashMap<>(16);
                userAttributes.put(userNameAttributeName, treeNode.findValue(userNameAttributeName));
                userAttributes.put("preferred_username", treeNode.findValue("preferred_username"));
                userAttributes.put("email", treeNode.findValue("email"));
                OAuth2User oAuth2User = new DefaultOAuth2User(grantedAuthorities, userAttributes, userNameAttributeName);

                return oAuth2User;
            } catch (Exception e) {
                log.error("oauth2UserService Exception", e);
            }
            return null;
        };
    }

    /**
     * 自动刷新token
     * https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2Client-webclient-servlet
     *
     * @param clientRegistrationRepository
     * @param authorizedClientRepository
     * @return
     */
   /*
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientRepository authorizedClientRepository) {

        OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken()
                .clientCredentials()
                .password()
                .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
            new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

    @Bean
    WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
            new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);

        return WebClient.builder()
            .apply(oauth2Client.oauth2Configuration())
            .build();
    }*/
}
