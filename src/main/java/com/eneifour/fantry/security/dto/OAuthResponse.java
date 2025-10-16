package com.eneifour.fantry.security.dto;

public interface OAuthResponse {
    String getProvider();
    String getProviderId();
    String getEmail();
    String getName();
}
