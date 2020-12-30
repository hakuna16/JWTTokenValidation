package com.testvscode.demo.configuration;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * This class is used to configure the spring security features in the
 * application.
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("#{'${range.allowed.origins}'.split(',')}")
    private List<String> allowedOrigins;
    @Value("#{'${range.allowed.methods}'.split(',')}")
    private List<String> allowedMethods;
    @Value("#{'${range.allowed.headers}'.split(',')}")
    private List<String> allowedHeaders;
    @Value("#{'${range.exposed.headers}'.split(',')}")
    private List<String> exposedHeaders;

    /**
     * This method is used to configure the {@link HttpSecurity} to the application.
     * Here we are enabling cors policy and we are disabling the csrf.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable();
    }

    /**
     * This method is used to configure tha security properties which are there in
     * the application.properties files. We are first reading all the property from
     * the file using {@link SpelExpression} and we are then enabling all the
     * configuration for the same.<br/>
     * Here we have configured<br/>
     * 1. What are the allowed origin from which we hit the application. <br/>
     * 2. What are the different HTTP methods available from the application server.
     * <br/>
     * 3. What are the different allowed header for your application. <br/>
     * 
     * @return the web-security configuration for the project
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(allowedOrigins);
        corsConfiguration.setAllowedMethods(allowedMethods);
        corsConfiguration.setAllowedHeaders(allowedHeaders);
        corsConfiguration.setExposedHeaders(exposedHeaders);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }

}
