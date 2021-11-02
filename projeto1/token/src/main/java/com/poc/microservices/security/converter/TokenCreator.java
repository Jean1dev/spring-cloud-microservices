package com.poc.microservices.security.converter;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.poc.microservices.curso.model.ApplicationUser;
import com.poc.microservices.curso.property.JwtConfig;
import lombok.SneakyThrows;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import com.nimbusds.jose.jwk.RSAKey;

import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class TokenCreator {

    protected final JwtConfig jwtConfig = new JwtConfig();

    @SneakyThrows
    public SignedJWT createSigned(Authentication authentication) {
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


    public String encrypt(SignedJWT token) throws JOSEException {
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
                .claim("userId", user.getId())
                .issuer("http://localhost")
                .issueTime(new Date())
                .expirationTime(new Date(String.valueOf(LocalDate.now().plusDays(1))))
                .build();
    }

}
