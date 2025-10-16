package com.eneifour.fantry.security.util;

import java.util.Map;

//Provider에서 제공해주는 속성값 파싱
public class OAuthUserInfoExtractor {
    // 고유 ID 추출
    public static String getProviderId(String regId, Map<String, Object> attr){
        String providerId = null;

        if(regId.equals("google")){
            providerId = (String) attr.get("sub");
        }else if(regId.equals("naver")){
            Map<String, Object> resp =  (Map<String, Object>) attr.get("response");
            providerId = (String) resp.get("id");
        }
        return providerId;
    }

    // Email 추출
    public static String getEmail(String regId, Map<String, Object> attr){
        String email = null;
        if(regId.equals("google")){
            email = (String) attr.get("email");
        }else if(regId.equals("naver")){
            Map<String, Object> account = (Map<String, Object>)attr.get("response");
            email = (String)account.get("email");
        }
        return email;
    }

    //name 추출
    public static String getName(String regId, Map<String, Object> attr){
        String name = null;
        if(regId.equals("google")){
            name = (String) attr.get("name");
        }else if(regId.equals("naver")){
            Map<String, Object> response=(Map<String, Object>)attr.get("response");
            Object n = response.get("name");    //실명을 주지 않을 수도 있음...
            name = (n!=null)? n.toString(): (String) response.get("nickname");
        }
        return name;
    }
}
