package vn.unigap.java.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import vn.unigap.java.api.repository.account.AccountRepository;
import vn.unigap.java.api.repository.role.RoleRepository;

import java.io.File;
import java.io.FileReader;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(
			HttpSecurity http,
			OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<?> tokenGenerator,
			ObjectMapper objectMapper,
			UserDetailsService userDetailsService,
			PasswordEncoder passwordEncoder)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		AuthenticationEntryPointFailureHandler failureHandler = new AuthenticationEntryPointFailureHandler(
				new CustomAuthenticationEntryPoint(objectMapper));
		failureHandler.setRethrowAuthenticationServiceException(false);

		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
				.clientAuthentication(client -> client.errorResponseHandler(failureHandler))
				.authorizationEndpoint(authorizationEndpoint -> {
					authorizationEndpoint.errorResponseHandler(failureHandler);
				})
				.tokenEndpoint(tokenEndpoint -> {
					tokenEndpoint.accessTokenRequestConverter(new OAuth2CustomPasswordAuthenticationConverter());
					tokenEndpoint.authenticationProvider(new OAuth2CustomPasswordAuthenticationProvider(
							authorizationService, tokenGenerator, userDetailsService, passwordEncoder));
//					tokenEndpoint.errorResponseHandler(
//							new AuthenticationEntryPointFailureHandler(
//									new CustomAuthenticationEntryPoint(objectMapper)));
					tokenEndpoint.errorResponseHandler(failureHandler);
				});
//				.oidc(Customizer.withDefaults());    // Enable OpenID Connect 1.0
		http
				// Redirect to the login page when not authenticated from the
				// authorization endpoint
				.exceptionHandling(exception -> exception.authenticationEntryPoint(new CustomAuthenticationEntryPoint(objectMapper)))
//				.exceptionHandling((exceptions) -> exceptions
//						.defaultAuthenticationEntryPointFor(
//								new LoginUrlAuthenticationEntryPoint("/login"),
//								new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//						)
//				)
				.oauth2ResourceServer((resourceServer) -> resourceServer
						.jwt(Customizer.withDefaults())
				)
		;

		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, ObjectMapper objectMapper)
			throws Exception {
		http
				.headers(header -> header.frameOptions(frame -> frame.disable()))
				.csrf(csrf -> csrf.disable())
				.authorizeHttpRequests((authorize) -> authorize
						.requestMatchers(
								new AntPathRequestMatcher("/h2-console/**"),
//								new AntPathRequestMatcher("/account/login"),
//								new AntPathRequestMatcher("/account/refresh-token"),
								new AntPathRequestMatcher("/")
						).permitAll()
						.anyRequest().authenticated()
				)
				// Form login handles the redirect to the login page from the
				// authorization server filter chain
//                .formLogin(Customizer.withDefaults())
				.oauth2ResourceServer(resourceServer ->
								resourceServer
										.accessDeniedHandler(new CustomAccessDeniedHandler(objectMapper))
										.authenticationEntryPoint(new CustomAuthenticationEntryPoint(objectMapper))
//										.jwt(jwtConfigurer -> jwtConfigurer.jwkSetUri("http://localhost:8051/oauth2/jwks"))
										.jwt(Customizer.withDefaults())
				);

		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService(AccountRepository accountRepository, RoleRepository roleRepository) {
//		UserDetails userDetails = User.withDefaultPasswordEncoder()
//				.username("user")
//				.password("password")
//				.roles("USER")
//				.build();

//		return new InMemoryUserDetailsManager(userDetails);

		return new CustomUserDetailService(accountRepository, roleRepository);
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
//		RegisteredClient registeredClient = RegisteredClient.withId("7a4290cc-0e56-11ee-be56-0242ac120002")
//				.clientId("clientId")
//				.clientSecret("{noop}secret")
//				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//				.authorizationGrantType(Constants.AUTHORIZATION_GRANT_TYPE_CUSTOM_PASSWORD)
//				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
////				.postLogoutRedirectUri("http://127.0.0.1:8080/")
////				.scope(OidcScopes.OPENID)
////				.scope(OidcScopes.PROFILE)
//				.tokenSettings(TokenSettings.builder()
//						.accessTokenTimeToLive(Duration.ofDays(1))
//						.reuseRefreshTokens(true)
//						.refreshTokenTimeToLive(Duration.ofDays(90))
//						.build())
//				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//				.build();

		JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
//		jdbcRegisteredClientRepository.save(registeredClient);
		return jdbcRegisteredClientRepository;
//		return new InMemoryRegisteredClientRepository(oidcClient);;
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = readRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	private static KeyPair readRsaKey() {
		KeyPair keyPair;
		try {
			keyPair = new KeyPair(
					readPublicKey(new ClassPathResource("public-key.pem").getFile()),
					readPrivateKey(new ClassPathResource("private-key.pem").getFile())
			);
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	public OAuth2AuthorizationService oAuth2AuthorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder) {
		JwtGenerator jwtGenerator = jwtGenerator(jwtEncoder);
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
//        CustomRefreshTokenGenerator refreshTokenGenerator = new CustomRefreshTokenGenerator(jwtEncoder);
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = new DelegatingOAuth2TokenGenerator(
				jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
		return tokenGenerator;
	}

	private JwtGenerator jwtGenerator(JwtEncoder jwtEncoder) {
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		return jwtGenerator;
	}

	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		JwtEncoder jwtEncoder = null;
		try {
			jwtEncoder = new NimbusJwtEncoder(jwkSource);
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
		return jwtEncoder;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

//	@Bean
//	public OAuth2RefreshTokenAuthenticationProvider oAuth2RefreshTokenAuthenticationProvider(
//			OAuth2AuthorizationService oAuth2AuthorizationService,
//			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
//		return new OAuth2RefreshTokenAuthenticationProvider(oAuth2AuthorizationService, tokenGenerator);
//	}

	private static RSAPrivateKey readPrivateKey(File file) throws Exception {
		try (FileReader keyReader = new FileReader(file)) {

			PEMParser pemParser = new PEMParser(keyReader);
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());

			return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
		}
	}

	private static RSAPublicKey readPublicKey(File file) throws Exception {
		try (FileReader keyReader = new FileReader(file)) {
			PEMParser pemParser = new PEMParser(keyReader);
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
			return (RSAPublicKey) converter.getPublicKey(publicKeyInfo);
		}
	}
}

