package com.example.jwt.security.filter;

import com.alibaba.fastjson.JSONObject;
import com.example.jwt.security.conf.ConfConstant;
import com.example.jwt.security.entity.JwtUser;
import com.example.jwt.security.utils.TokenUtil;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * @author yuhy
 * @date 2021/9/27 13:59
 */
@RequiredArgsConstructor
public class TokenFilter extends GenericFilterBean {
    private static final Logger log = LoggerFactory.getLogger(TokenFilter.class);
    final UserDetailsService userDetailsService;
    final StringRedisTemplate redisTemplate;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        String token = resolveToken(httpServletRequest);
        if (StringUtils.hasText(token)) {
            JwtUser jwtUser = JSONObject.parseObject(redisTemplate.opsForValue().get(ConfConstant.TOKEN_PRE + token), JwtUser.class);
            if (jwtUser != null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(TokenUtil.getUsername(token));
                Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, token, userDetails.getAuthorities());
                //Authentication authentication = TokenUtil.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                redisTemplate.expire(ConfConstant.TOKEN_PRE + token, 8, TimeUnit.HOURS);
            }
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    /**
     * 初步检测Token
     *
     * @param request /
     * @return /
     */
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(ConfConstant.HEADER_KEY);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(ConfConstant.TOKEN_PRE)) {
            // 去掉令牌前缀
            return bearerToken.replace(ConfConstant.TOKEN_PRE, "");
        } else {
            log.debug("非法Token：{}", bearerToken);
        }
        return null;
    }
}
