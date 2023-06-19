package vn.unigap.java.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import vn.unigap.java.common.Constants;

import java.util.Map;

public class OAuth2CustomPasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
	private final String username;
	private final String password;

	public OAuth2CustomPasswordAuthenticationToken(String username, String password, Authentication clientPrincipal, Map<String, Object> additionalParameters) {
		super(Constants.AUTHORIZATION_GRANT_TYPE_CUSTOM_PASSWORD, clientPrincipal, additionalParameters);
		this.username = username;
		this.password = password;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}
}
