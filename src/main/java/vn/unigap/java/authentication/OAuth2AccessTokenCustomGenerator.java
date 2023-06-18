package vn.unigap.java.authentication;

import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
//import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;

@Component
public class OAuth2AccessTokenCustomGenerator {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
	private final OAuth2AuthorizationService authorizationService;
	private final UserDetailsService userDetailsService;
	private final PasswordEncoder passwordEncoder;
	private final RegisteredClientRepository registeredClientRepository;

	public OAuth2AccessTokenCustomGenerator(OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
											UserDetailsService userDetailsService, PasswordEncoder passwordEncoder,
											RegisteredClientRepository registeredClientRepository) {
		this.registeredClientRepository = registeredClientRepository;
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		Assert.notNull(userDetailsService, "userDetailsService cannot be null");
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
		this.userDetailsService = userDetailsService;
		this.passwordEncoder = passwordEncoder;
	}

	public OAuth2AccessTokenAuthenticationToken generate(String username, String password, String clientId) throws AuthenticationException {

		// check username and password of user
		UserDetails userDetails;
		try {
			userDetails = userDetailsService.loadUserByUsername(username);
		} catch (UsernameNotFoundException e) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
					"The username not found.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		} catch (Exception e) {
			e.printStackTrace();
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"Internal error.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		if (!passwordEncoder.matches(password, userDetails.getPassword())) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
					"Invalid password.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.principalName(clientId)
				.authorizedScopes(registeredClient.getScopes())
				.attribute(Principal.class.getName(), new UsernamePasswordAuthenticationToken(username, password))
				.build();

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(new UsernamePasswordAuthenticationToken(username, password))
//				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorization(authorization)
				.authorizedScopes(authorization.getAuthorizedScopes())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
//				.authorizationGrant(authorizationCodeAuthentication);
		// @formatter:on

		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

		// ----- Access token -----
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
				generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
		if (generatedAccessToken instanceof ClaimAccessor) {
			authorizationBuilder.token(accessToken, (metadata) ->
					metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims()));
		} else {
			authorizationBuilder.accessToken(accessToken);
		}

		// ----- Refresh token -----
		OAuth2RefreshToken refreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
			OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
						"The token generator failed to generate the refresh token.", ERROR_URI);
				throw new OAuth2AuthenticationException(error);
			}

			refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(refreshToken);
		}
//
//
//		// @formatter:off
//		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
//				.registeredClient(registeredClient)
//				.principal(new UsernamePasswordAuthenticationToken(authorizationPasswordAuthentication.getUsername(), authorizationPasswordAuthentication.getPassword()))
//				.providerContext(ProviderContextHolder.getProviderContext())
//				.authorization(authorization)
//				.authorizedScopes(authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME))
//				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
//				.authorizationGrant(authorizationPasswordAuthentication);
//		// @formatter:on
//
//		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);
//
//		// ----- Access token -----
//		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
//		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
//		if (generatedAccessToken == null) {
//			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
//					"The token generator failed to generate the access token.", ERROR_URI);
//			throw new OAuth2AuthenticationException(error);
//		}
//		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
//				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
//				generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
//		if (generatedAccessToken instanceof ClaimAccessor) {
//			authorizationBuilder.token(accessToken, (metadata) ->
//					metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims()));
//		} else {
//			authorizationBuilder.accessToken(accessToken);
//		}
//
//		// ----- Refresh token -----
//		OAuth2RefreshToken refreshToken = null;
//		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
//				// Do not issue refresh token to public client
//				!clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
//
//			tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
//			OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
//			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
//				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
//						"The token generator failed to generate the refresh token.", ERROR_URI);
//				throw new OAuth2AuthenticationException(error);
//			}
//			refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
//			authorizationBuilder.refreshToken(refreshToken);
//		}

		authorization = authorizationBuilder.build();
		authorizationService.save(authorization);

		Map<String, Object> additionalParameters = Collections.emptyMap();

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		return new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);
	}

	static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}
}
