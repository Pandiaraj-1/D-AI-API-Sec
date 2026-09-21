package com.aisecfirewall.gateway.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class GatewayConfig {

    /**
     * Dedicated WebClient for the Threat Engine call. Kept separate from any
     * other outbound client so its connection pool and timeouts never get
     * shared with (or starved by) unrelated traffic.
     */
    @Bean
    public WebClient threatEngineWebClient(
            org.springframework.core.env.Environment env) {
        String baseUrl = env.getProperty("firewall.threat-engine-url", "http://threat-engine:8000");
        return WebClient.builder().baseUrl(baseUrl).build();
    }
}
