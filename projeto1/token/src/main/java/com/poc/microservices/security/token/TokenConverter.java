package com.poc.microservices.security.token;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.poc.microservices.curso.property.JwtConfig;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.security.AccessControlException;


@Service
public class TokenConverter {
    private final JwtConfig jwtConfig = new JwtConfig();

    @SneakyThrows
    public String decriptToken(String encriptToken) {
        JWEObject parse = JWEObject.parse(encriptToken);

        DirectDecrypter decrypter = new DirectDecrypter(jwtConfig.getPrivateKey().getBytes());

        parse.decrypt(decrypter);
        return parse.getPayload().toSignedJWT().serialize();
    }

    @SneakyThrows
    public void validateTokenSignateure(String signedToken) {
        SignedJWT signedJWT = SignedJWT.parse(signedToken);

        RSAKey publicKey = RSAKey.parse(signedJWT.getHeader().getJWK().toJSONObject());
        if (!signedJWT.verify(new RSASSAVerifier(publicKey))) {
            throw new AccessControlException("token invalido");
        }
    }
}
