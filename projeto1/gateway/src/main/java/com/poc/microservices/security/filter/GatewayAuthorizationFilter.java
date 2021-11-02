package com.poc.microservices.security.filter;

import com.netflix.zuul.context.RequestContext;
import com.nimbusds.jwt.SignedJWT;
import com.poc.microservices.security.utils.SecurityContextUtil;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.Objects;

public class GatewayAuthorizationFilter extends JWTTokenAuthorizationFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = httpServletRequest.getHeader(jwtConfig.getHeader().getName());

        if (Objects.isNull(header) || !header.startsWith(jwtConfig.getHeader().getPrefix())) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        try {
            String stringToken = header.replace(jwtConfig.getHeader().getPrefix(), "").trim();
            String decriptToken = converter.decriptToken(stringToken);
            converter.validateTokenSignateure(decriptToken);
            SecurityContextUtil.setSecurityContext(SignedJWT.parse(decriptToken));

            if (jwtConfig.getType().equalsIgnoreCase("signed"))
                RequestContext.getCurrentContext().addZuulRequestHeader("Authorization", jwtConfig.getHeader().getPrefix() + decriptToken);

            filterChain.doFilter(httpServletRequest, httpServletResponse);
        } catch (ParseException e) {
            e.printStackTrace();
            throw new ServletException("");
        }
    }
}
