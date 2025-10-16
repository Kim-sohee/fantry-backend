package com.eneifour.fantry.security.oauth;

import com.eneifour.fantry.member.domain.RoleType;
import com.eneifour.fantry.security.dto.CustomOAuth2User;
import com.eneifour.fantry.security.service.RedisTokenService;
import com.eneifour.fantry.security.util.CookieUtil;
import com.eneifour.fantry.security.util.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

// SNS 로그인 성공 시 해당 핸들러 실행
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuthSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;
    private final RedisTokenService redisTokenService;

    @Value("${spring.jwt.refresh-hour}")
    private int refreshHour;

    @Value("${fantry.web.oauth-redirect-url}")
    private String redirectUrl;

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String username;
        RoleType role;

        Object principal = authentication.getPrincipal();
        if (principal instanceof CustomOAuth2User customUser) {
            username = customUser.getName();
        } else if (principal instanceof DefaultOidcUser oidcUser) {
            username = oidcUser.getEmail();
        } else if (principal instanceof OAuth2User oAuth2User) {
            username = oAuth2User.getAttribute("email");
        } else {
            throw new IllegalStateException("Unexpected principal type: " + principal.getClass());
        }

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String roleStr = auth.getAuthority();
        String roleString = roleStr.split("_")[1];
        role = RoleType.valueOf(roleString);

        //JWT 생성
        int userVersion = redisTokenService.currentUserVersion(username);
        String accessToken = jwtUtil.createAccessToken(username, userVersion, "access", role);
        String refreshToken = jwtUtil.createRefreshToken(username, "refresh", role);

        //Redis에 RefreshToken 저장
        long ttlSec = refreshHour * 60 * 60;
        redisTokenService.saveRefreshToken(username, refreshToken, ttlSec);
        CookieUtil.setRefreshCookie(response, refreshToken, (int) ttlSec);

        // 프론트엔드로 AccessToken을 포함하여 리다이렉트
        Map<String, String> userInfo = new HashMap<>();
        userInfo.put("id", username);
        userInfo.put("role", roleStr);

        String targetUrl = UriComponentsBuilder.fromUriString(redirectUrl)
                .queryParam("accessToken", accessToken)
                .queryParam("id", URLEncoder.encode(userInfo.get("id"), StandardCharsets.UTF_8))
                .queryParam("role", userInfo.get("role"))
                .build().toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
