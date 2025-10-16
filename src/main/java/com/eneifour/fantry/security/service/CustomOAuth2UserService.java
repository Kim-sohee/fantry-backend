package com.eneifour.fantry.security.service;

import com.eneifour.fantry.member.domain.Member;
import com.eneifour.fantry.member.domain.Role;
import com.eneifour.fantry.member.domain.RoleType;
import com.eneifour.fantry.member.repository.JpaMemberRepository;
import com.eneifour.fantry.member.repository.RoleRepository;
import com.eneifour.fantry.security.dto.*;
import com.eneifour.fantry.security.exception.AuthErrorCode;
import com.eneifour.fantry.security.exception.AuthException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final JpaMemberRepository jpaMemberRepository;
    private final RoleRepository roleRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.debug("당신이 가입한 프로바이더는 {}", registrationId);

        OAuthResponse oAuthResponse;
        if(registrationId.equals("naver")) {
            oAuthResponse = new NaverResponse(oAuth2User.getAttributes());
        } else if(registrationId.equals("google")) {
            oAuthResponse = new GoogleResponse(oAuth2User.getAttributes());
        } else {
            //시스템에서 지원하지 않는 프로바이더인 경우 -> 로그인 실패 예외
            throw new AuthException(AuthErrorCode.OAUTH_UNSUPPORTED_PROVIDER);
        }

        //회원 정보 꺼내기
        log.debug("유저 정보는 {}", oAuthResponse);

        //회원 인지 아닌지 판단
        //회원이 아니면 -> 강제 가입, 회원이면 로그인 처리
        String username = oAuthResponse.getProviderId();
        Member existData = jpaMemberRepository.findById(username);

        if(existData == null) {
            Role userRole = roleRepository.findByRoleType(RoleType.USER);
            Member newMember = new Member();
            newMember.setId(username);
            newMember.setEmail(oAuthResponse.getEmail());
            newMember.setName(oAuthResponse.getName());
            newMember.setRole(userRole);
            newMember.setSns(oAuthResponse.getProvider()); // sns 필드 활용
            newMember.setIsActive(0); // 활성 상태

            jpaMemberRepository.save(newMember);

            CustomUserDetails userDetails = new CustomUserDetails(newMember);
            return new CustomOAuth2User(userDetails);
        } else {
            //이미 가입된 경우, 정보 업데이트
            existData.setEmail(oAuthResponse.getEmail());
            existData.setName(oAuthResponse.getName());
            jpaMemberRepository.save(existData);

            CustomUserDetails userDetails = new CustomUserDetails(existData);
            return new CustomOAuth2User(userDetails);
        }
    }
}
