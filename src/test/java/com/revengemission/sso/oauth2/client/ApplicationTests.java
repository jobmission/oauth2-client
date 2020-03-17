package com.revengemission.sso.oauth2.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ApplicationTests {

    @Ignore
    @Test
    public void contextLoads() {

        //用登陆后的token ,请求api资源
        //header格式，Authorization : Bearer xxxxx

        RestTemplate restTemplate = new RestTemplate();
        JavaTimeModule module = new JavaTimeModule();
        LocalDateTimeDeserializer localDateTimeDeserializer = new LocalDateTimeDeserializer(
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        module.addDeserializer(LocalDateTime.class, localDateTimeDeserializer);

        ObjectMapper objectMapper = Jackson2ObjectMapperBuilder.json().modules(module)
            .featuresToDisable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS).build();

        MappingJackson2HttpMessageConverter jsonMessageConverter = new MappingJackson2HttpMessageConverter();
        jsonMessageConverter.setObjectMapper(objectMapper);
        restTemplate.getMessageConverters().add(0, jsonMessageConverter);

        // request some api


    }

}
