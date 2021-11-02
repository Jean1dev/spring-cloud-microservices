package com.poc.microservices.auth.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.poc.microservices.curso.model.ApplicationUser;
import com.poc.microservices.curso.property.JwtConfig;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

public class EnsureAuthenticatedFilter extends UsernamePasswordAuthenticationFilter {

    @Autowired
    private AuthenticationManager authenticationManager;

    private final JwtConfig jwtConfig = new JwtConfig();

    @lombok.SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        logger.info("Configurando autenticacao. . . .");
        ApplicationUser applicationUser = new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class);

        if (Objects.isNull(applicationUser)) {
            throw new UsernameNotFoundException("Usuario nao encontrado");
        }

        logger.info("Criando autenticacao para o usuario {}");

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(applicationUser.getUserName(), applicationUser.getPassword());

        authenticationToken.setDetails(applicationUser);
        return authenticationManager.authenticate(authenticationToken);
    }

    @SneakyThrows
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        SignedJWT signedJWT = createSigned(authResult);
        String encrypt = encrypt(signedJWT);

        response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, " + jwtConfig.getHeader().getName());
        response.addHeader(jwtConfig.getHeader().getName(), jwtConfig.getHeader().getPrefix() + encrypt);
    }

    @SneakyThrows
    private SignedJWT createSigned(Authentication authentication) {
        ApplicationUser applicationUser = (ApplicationUser) authentication.getPrincipal();
        JWTClaimsSet jwtClaimsSet = createClaimSet(authentication, applicationUser);
        KeyPair keyPair = generate();

        JWK key = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .keyID(UUID.randomUUID().toString())
                .build();

        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(key)
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);

        RSASSASigner signer = new RSASSASigner(keyPair.getPrivate());

        signedJWT.sign(signer);
        return signedJWT;
    }

    private String encrypt(SignedJWT token) throws JOSEException {
        DirectEncrypter encrypter = new DirectEncrypter(jwtConfig.getPrivateKey().getBytes());
        JWEObject jwt = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .contentType("JWT")
                .build(), new Payload(token));

        jwt.encrypt(encrypter);
        return jwt.serialize();
    }

    @SneakyThrows
    private KeyPair generate() {
        KeyPairGenerator instance = KeyPairGenerator.getInstance("RSA");
        instance.initialize(2048);
        return instance.generateKeyPair();
    }

    private JWTClaimsSet createClaimSet(Authentication auth, ApplicationUser user) {
        return new JWTClaimsSet.Builder()
                .subject(user.getUserName())
                .claim("authorities", auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .issuer("http://localhost")
                .issueTime(new Date())
                .expirationTime(new Date(String.valueOf(LocalDate.now().plusDays(1))))
                .build();
    }
}
