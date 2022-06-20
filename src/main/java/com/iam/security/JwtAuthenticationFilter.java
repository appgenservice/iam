package com.iam.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    public static final String BEARER_TOKEN_HEADER = "Bearer ";
    private String jwtAudience;
    private String jwtIssuer;
    private String jwtSecret;
    private String jwtType;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager,
                                   String jwtAudience, String jwtIssuer,
                                   String jwtSecret, String jwtType, String loginPath) {
        this.jwtAudience = jwtAudience;
        this.jwtIssuer = jwtIssuer;
        this.jwtSecret = jwtSecret;
        this.jwtType = jwtType;
        this.setAuthenticationManager(authenticationManager);
        setFilterProcessesUrl(loginPath);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
                User user = (User)authentication.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC512(jwtSecret.getBytes());
        String token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 864000000))
                .withIssuer(jwtIssuer)
                .withClaim("roles", user.getAuthorities().stream().map(grantedAuthority
                        -> grantedAuthority.getAuthority()).collect(Collectors.toList()))
                .sign(algorithm);
        response.addHeader(HttpHeaders.AUTHORIZATION, BEARER_TOKEN_HEADER + token);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.startsWithIgnoreCase(authorization, "basic ")) {
            String credentials = authorization.length() <= "Basic ".length() ? "" : authorization.substring("Basic ".length());
            String decoded = new String(this.base64Decode(credentials), StandardCharsets.UTF_8);
            String[] userCred = decoded.split(":", 2);
            if (userCred.length == 2) {
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userCred[0], userCred[1]);
                return getAuthenticationManager().authenticate(token);
            }
        }
        throw new AuthenticationException("Please check user credentials") {};
    }

    private byte[] base64Decode(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (Exception var3) {
            return new byte[0];
        }
    }
}
