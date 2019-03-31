package com.revengemission.sso.oauth2.client.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

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
                .userInfoEndpoint()
                .userAuthoritiesMapper(this.userAuthoritiesMapper());


    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().mvcMatchers("/assets/**", "/img/**", "/favicon.ico");
    }

    /*
     * UserInfo Endpoint
     * Mapping User Authorities
     *
     * https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2login-advanced-map-authorities
     * */
    private GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority) authority;

                Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                // Map the attributes found in userAttributes
                // to one or more GrantedAuthority's and add it to mappedAuthorities
                if (userAttributes.containsKey("authorities")) {
                    String authoritiesStr = userAttributes.get("authorities").toString();
                    String[] roles = authoritiesStr.split(",");
                    for (String role : roles) {
                        mappedAuthorities.add(new SimpleGrantedAuthority(role));
                    }
                }

            });

            return mappedAuthorities;
        };
    }

}