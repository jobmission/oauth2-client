package com.revengemission.sso.oauth2.client.config;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.StringUtils;

import java.util.*;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private Logger log = LoggerFactory.getLogger(this.getClass());
    @Autowired
    CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http
            .logout()
            .logoutUrl("/logout").logoutSuccessUrl("/")
            .and()
            .authorizeRequests()
            .mvcMatchers("/", "/login/**", "/assets/**")
            .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .oauth2Login()
            .successHandler(customAuthenticationSuccessHandler)
            .userInfoEndpoint().userService(oauth2UserService());

    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().mvcMatchers("/assets/**", "/img/**", "/favicon.ico");
    }

    /**
     * 从user-info-uri 返回结果中抽取权限信息，如角色等，默认为scope
     * Mapping User Authorities
     * https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2login-advanced-map-authorities
     */
    @Deprecated
    private GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (OidcUserAuthority.class.isInstance(authority)) {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                    OidcIdToken idToken = oidcUserAuthority.getIdToken();
                    OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

                    System.out.println(oidcUserAuthority);

                    // Map the claims found in idToken and/or userInfo
                    // to one or more GrantedAuthority's and add it to mappedAuthorities

                } else if (OAuth2UserAuthority.class.isInstance(authority)) {
                    OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority) authority;

                    Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();
                    System.out.println(userAttributes);
                    // Map the attributes found in userAttributes
                    // to one or more GrantedAuthority's and add it to mappedAuthorities

                } else if (SimpleGrantedAuthority.class.isInstance(authority)) {
                    SimpleGrantedAuthority simpleGrantedAuthority = (SimpleGrantedAuthority) authority;

                    System.out.println(simpleGrantedAuthority);

                }
            });

            return mappedAuthorities;
        };
    }

    com.jayway.jsonpath.Configuration conf = com.jayway.jsonpath.Configuration.builder().options(Option.SUPPRESS_EXCEPTIONS).build();

    /**
     * 从access_token中直接抽取角色等信息
     * https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2login-advanced-map-authorities-oauth2userservice
     *
     * @return
     */
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {

        return (userRequest) -> {
            String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
            if (!StringUtils.hasText(userNameAttributeName)) {
                userNameAttributeName = "sub";
            }
            OAuth2AccessToken accessToken = userRequest.getAccessToken();
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
            try {
                SignedJWT jwt = SignedJWT.parse(accessToken.getTokenValue());
                String claimJsonString = jwt.getJWTClaimsSet().toJSONObject().toJSONString();
                Object document = com.jayway.jsonpath.Configuration.defaultConfiguration().jsonProvider().parse(claimJsonString);

                List<Object> authorities = JsonPath.using(conf).parse(document).read("$..roles");

                if (authorities == null || authorities.size() == 0) {
                    authorities = JsonPath.using(conf).parse(document).read("$..authorities");
                }
                Collection<String> roles = new ArrayList<>();
                authorities.forEach(authorityItem -> {
                    if (authorityItem instanceof String) {
                        roles.add((String) authorityItem);
                    } else if (authorityItem instanceof JSONArray) {
                        roles.addAll((Collection<String>) authorityItem);
                    } else if (authorityItem instanceof Collection) {
                        roles.addAll((Collection<String>) authorityItem);
                    }
                });

                for (String authority : roles) {
                    grantedAuthorities.add(new SimpleGrantedAuthority(authority));
                }
                Map<String, Object> userAttributes = new HashMap<>(16);
                userAttributes.put(userNameAttributeName, JsonPath.using(conf).parse(document).read("$." + userNameAttributeName));
                userAttributes.put("preferred_username", JsonPath.using(conf).parse(document).read("$.preferred_username"));
                userAttributes.put("email", JsonPath.using(conf).parse(document).read("$.email"));
                OAuth2User oAuth2User = new DefaultOAuth2User(grantedAuthorities, userAttributes, userNameAttributeName);

                return oAuth2User;
            } catch (Exception e) {
                log.error("oauth2UserService Exception", e);
            }
            return null;
        };
    }

}
