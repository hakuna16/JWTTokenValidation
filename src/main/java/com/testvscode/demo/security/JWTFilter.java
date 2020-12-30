package com.testvscode.demo.security;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JWTFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String requestUri = request.getRequestURI();
        final String requestMethod = request.getMethod();

        final String userAccessToken = request.getHeader("Authorization");
        String tokenarray[] = userAccessToken.split("Bearer ");

        String jwtTokenn = tokenarray[1];
        System.out.println(jwtTokenn);

        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWKSource keySource = new RemoteJWKSet(new URL("https://api-ppe.tesco.com/.well-known/jwks.json"));

        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        // Process the token

        JWTClaimsSet claimsSet = null;
        try {
            claimsSet = jwtProcessor.process(jwtTokenn, null);
        } catch (ParseException e) {
            System.out.println("Invalid token");
        } catch (BadJOSEException e) {
            System.out.println("Invalid token");
        } catch (JOSEException e) {
            System.out.println("Invalid token");
        }

        if (claimsSet == null) {
            System.out.println("Invalid token");
            try {
                throw new Exception("Invalid token");
            } catch (Exception e) {
                filterChain.doFilter(request, response);
            }
        }
        // Print out the token claims set
        System.out.println(claimsSet.toJSONObject());

        long expTime = claimsSet.getExpirationTime().getTime();

        if (System.currentTimeMillis() > (expTime * 1000)) {
            System.out.println("Not valid token");
        } else {
            System.out.println("Valid token");
        }
        System.out.println(claimsSet.getExpirationTime());

        filterChain.doFilter(request, response);
    }

}
