package com.revengemission.sso.oauth2.client;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ApplicationTests {

    @Value("${host.api}")
    private String apiHost;

    @Test
    public void contextLoads() {

        //用登陆后的token ,请求api资源
        //header格式，Authorization : Bearer xxxxx


    }

}
