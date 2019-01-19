package com.revengemission.sso.oauth2.client.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .logout()
                .logoutUrl("/logout").logoutSuccessUrl("/")
                .and()
                .antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/", "/login/**", "/assets/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .csrf().disable();

        http.oauth2Login().successHandler(customAuthenticationSuccessHandler);

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/assets/**", "/img/**", "/favicon.ico");
    }


}