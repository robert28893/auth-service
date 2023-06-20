package vn.unigap.java.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import vn.unigap.java.common.errorcode.ErrorCode;
import vn.unigap.java.common.response.ApiResponse;

import java.io.IOException;

public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private final AuthenticationEntryPoint bearerTokenAuthenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();

	private final ObjectMapper objectMapper;

	public CustomAuthenticationEntryPoint(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
		bearerTokenAuthenticationEntryPoint.commence(request, response, authException);
		response.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		response.getWriter().println(
				objectMapper.writeValueAsString(ApiResponse.error(ErrorCode.UNAUTHORIZED, HttpStatus.UNAUTHORIZED, HttpStatus.UNAUTHORIZED.getReasonPhrase()))
		);
	}
}
