package com.example.jwt.security.controller;

import com.alibaba.fastjson.JSONObject;
import com.example.jwt.security.conf.ConfConstant;
import com.example.jwt.security.utils.TokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * @author yuhy
 * @date 2021/9/27 15:27
 */
@RequiredArgsConstructor
@RequestMapping("/auth")
@RestController
public class AuthController {
    final AuthenticationManagerBuilder authenticationManagerBuilder;
    final StringRedisTemplate redisTemplate;

    @PostMapping("/login")
    public Object login(String username, String password) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = ConfConstant.TOKEN_PRE + TokenUtil.createToken(authentication);
        redisTemplate.opsForValue().set(token, JSONObject.toJSONString(authentication.getPrincipal()), 8, TimeUnit.HOURS);
        return token;
    }

    @PostMapping("/logout")
    public Object logout(HttpServletRequest request) {
        redisTemplate.delete(ConfConstant.TOKEN_PRE + Objects.requireNonNull(TokenUtil.getToken(request)));
        return "ok";
    }

    @GetMapping("/user_info")
    @PreAuthorize("hasAnyAuthority('admin')")
    public Object get() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
