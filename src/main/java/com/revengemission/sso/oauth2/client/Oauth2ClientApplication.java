package com.revengemission.sso.oauth2.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/*
*http://www.baeldung.com/sso-spring-security-oauth2
*
*https://github.com/eugenp/tutorials/tree/master/spring-security-sso
*
* https://github.com/spring-guides/tut-spring-boot-oauth2/blob/master/manual/src/main/java/com/example/SocialApplication.java
* */
@SpringBootApplication
public class Oauth2ClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2ClientApplication.class, args);
    }
}
