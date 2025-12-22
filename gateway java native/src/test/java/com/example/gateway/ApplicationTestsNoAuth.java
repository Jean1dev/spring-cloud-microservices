package com.example.gateway;

import com.example.gateway.security.TestSecurityConfig;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.reactive.ReactiveOAuth2ClientAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.reactive.ReactiveOAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles({"test", "no-security"})
@Import(TestSecurityConfig.class)
@EnableAutoConfiguration(exclude = {
    ReactiveOAuth2ClientAutoConfiguration.class,
    ReactiveOAuth2ResourceServerAutoConfiguration.class
})
public abstract class ApplicationTestsNoAuth {
}
