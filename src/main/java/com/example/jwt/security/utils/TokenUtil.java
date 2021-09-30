package com.example.jwt.security.utils;

import cn.hutool.core.util.IdUtil;
import com.example.jwt.security.conf.ConfConstant;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.ArrayList;

/**
 * @author yuhy
 * @date 2021/9/27 16:14
 */
public class TokenUtil {
    private final static JwtBuilder JWT_BUILDER;
    private final static JwtParser JWT_PARSER;

    static {
        byte[] keyBytes = Decoders.BASE64.decode(ConfConstant.B64);
        Key key = Keys.hmacShaKeyFor(keyBytes);
        JWT_BUILDER = Jwts.builder().signWith(key, SignatureAlgorithm.HS512);
        JWT_PARSER = Jwts.parserBuilder().setSigningKey(key).build();
    }

    public static String createToken(Authentication authentication) {
        return JWT_BUILDER.setId(IdUtil.simpleUUID())
                .claim(ConfConstant.PRE, authentication.getName())
                .setSubject(authentication.getName())
                .compact();
    }

    public static String getUsername(String token) {
        return getClaims(token).getSubject();
    }

    public static Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        User principal = new User(claims.getSubject(), "******", new ArrayList<>());
        return new UsernamePasswordAuthenticationToken(principal, token, new ArrayList<>());
    }

    public static String getToken(HttpServletRequest request) {
        final String requestHeader = request.getHeader(ConfConstant.HEADER_KEY);
        if (requestHeader != null && requestHeader.startsWith(ConfConstant.TOKEN_PRE)) {
            return requestHeader.substring(7);
        }
        return null;
    }

    private static Claims getClaims(String token) {
        return JWT_PARSER
                .parseClaimsJws(token)
                .getBody();
    }
}
