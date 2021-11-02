package com.poc.microservices.security.filter;

import com.nimbusds.jwt.SignedJWT;
import com.poc.microservices.curso.property.JwtConfig;
import com.poc.microservices.security.token.TokenConverter;
import com.poc.microservices.security.utils.SecurityContextUtil;
import lombok.SneakyThrows;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

public class JWTTokenAuthorizationFilter extends OncePerRequestFilter {
    protected final JwtConfig jwtConfig = new JwtConfig();

    @Autowired
    protected TokenConverter converter;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = httpServletRequest.getHeader(jwtConfig.getHeader().getName());

        if (Objects.isNull(header) || !header.startsWith(jwtConfig.getHeader().getPrefix())) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        String stringToken = header.replace(jwtConfig.getHeader().getPrefix(), "").trim();
        SecurityContextUtil.setSecurityContext(StringUtils.equalsIgnoreCase("signed", jwtConfig.getType()) ?
                validate(stringToken) :
                decryptValidating(stringToken));

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    @SneakyThrows
    protected SignedJWT decryptValidating(String encryptToken) {
        String decriptToken = converter.decriptToken(encryptToken);
        converter.validateTokenSignateure(decriptToken);
        return SignedJWT.parse(decriptToken);
    }

    @SneakyThrows
    protected SignedJWT validate(String signedToken) {
        converter.validateTokenSignateure(signedToken);
        return SignedJWT.parse(signedToken);
    }
}
