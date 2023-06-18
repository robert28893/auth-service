package vn.unigap.java.common.accesstoken;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;

import java.time.temporal.ChronoUnit;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessTokenResponse {
    @JsonProperty(value = "access_token")
    private String accessToken;
    @JsonProperty(value = "token_type")
    private String tokenType;
    @JsonProperty(value = "expires_in")
    private Long expiresIn;
    @JsonProperty("refresh_token")
    private String refreshToken;
    private String scope;

    public static AccessTokenResponse from(OAuth2AccessTokenAuthenticationToken token) {
        AccessTokenResponse.AccessTokenResponseBuilder builder = AccessTokenResponse.builder()
                .accessToken(token.getAccessToken().getTokenValue())
                .tokenType(token.getAccessToken().getTokenType().getValue())
                .scope(String.join(" ", token.getAccessToken().getScopes()));

        if (token.getAccessToken().getIssuedAt() != null && token.getAccessToken().getExpiresAt() != null) {
            builder.expiresIn(ChronoUnit.SECONDS.between(token.getAccessToken().getIssuedAt(), token.getAccessToken().getExpiresAt()));
        }

        if (token.getRefreshToken() != null) {
            builder = builder.refreshToken(token.getRefreshToken().getTokenValue());
        }
        return builder.build();
    }
}
