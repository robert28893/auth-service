package vn.unigap.java.api.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Service;
import vn.unigap.java.api.dto.in.LoginDtoIn;
import vn.unigap.java.api.dto.in.RefreshTokenDtoIn;
import vn.unigap.java.api.dto.out.LoginDtoOut;
import vn.unigap.java.api.dto.out.RefreshTokenDtoOut;
import vn.unigap.java.authentication.OAuth2AccessTokenCustomGenerator;
import vn.unigap.java.common.accesstoken.AccessTokenResponse;

@Service
public class AccountServiceImpl implements AccountService {

    private final OAuth2AccessTokenCustomGenerator oAuth2AccessTokenCustomGenerator;
    private final OAuth2RefreshTokenAuthenticationProvider oAuth2RefreshTokenAuthenticationProvider;
    private final RegisteredClientRepository registeredClientRepository;

    @Autowired
    public AccountServiceImpl(
            OAuth2AccessTokenCustomGenerator oAuth2AccessTokenCustomGenerator,
            OAuth2RefreshTokenAuthenticationProvider oAuth2RefreshTokenAuthenticationProvider,
            RegisteredClientRepository registeredClientRepository) {
        this.oAuth2AccessTokenCustomGenerator = oAuth2AccessTokenCustomGenerator;
        this.oAuth2RefreshTokenAuthenticationProvider = oAuth2RefreshTokenAuthenticationProvider;
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public LoginDtoOut login(LoginDtoIn loginDtoIn) {
        OAuth2AccessTokenAuthenticationToken token = this.oAuth2AccessTokenCustomGenerator.generate(
                loginDtoIn.getUsername(), loginDtoIn.getPassword(), "oidc-client");

        return LoginDtoOut.builder()
                .accessToken(AccessTokenResponse.from(token))
                .build();
    }

    @Override
    public RefreshTokenDtoOut refreshToken(RefreshTokenDtoIn refreshTokenDtoIn) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId("oidc-client");
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = new OAuth2ClientAuthenticationToken(
                registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret");

//        oAuth2ClientAuthenticationToken.setAuthenticated(true);

        OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication = new OAuth2RefreshTokenAuthenticationToken(
                refreshTokenDtoIn.getRefreshToken(), oAuth2ClientAuthenticationToken, null, null);

        AuthorizationServerContext authorizationServerContext = new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return "oidc-client";
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return null;
            }
        };

        AuthorizationServerContextHolder.setContext(authorizationServerContext);

        OAuth2AccessTokenAuthenticationToken token = (OAuth2AccessTokenAuthenticationToken) oAuth2RefreshTokenAuthenticationProvider.authenticate(refreshTokenAuthentication);
        return RefreshTokenDtoOut.builder()
                .accessToken(AccessTokenResponse.from(token))
                .build();
    }
}
