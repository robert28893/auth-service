package vn.unigap.java.api.dto.out;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import vn.unigap.java.common.accesstoken.AccessTokenResponse;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LoginDtoOut {
    private AccessTokenResponse accessToken;
}
