package vn.unigap.java.api.service;

import vn.unigap.java.api.dto.in.LoginDtoIn;
import vn.unigap.java.api.dto.in.RefreshTokenDtoIn;
import vn.unigap.java.api.dto.out.LoginDtoOut;
import vn.unigap.java.api.dto.out.RefreshTokenDtoOut;

import java.util.Map;

public interface AccountService {
    LoginDtoOut login(LoginDtoIn loginDtoIn);
    RefreshTokenDtoOut refreshToken(RefreshTokenDtoIn refreshTokenDtoIn);
}
