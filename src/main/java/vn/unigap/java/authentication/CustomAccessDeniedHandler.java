package vn.unigap.java.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandler;
import vn.unigap.java.common.errorcode.ErrorCode;
import vn.unigap.java.common.response.ApiResponse;

import java.io.IOException;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {
	private final BearerTokenAccessDeniedHandler bearerTokenAccessDeniedHandler = new BearerTokenAccessDeniedHandler();

	private final ObjectMapper objectMapper;

	public CustomAccessDeniedHandler(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
		bearerTokenAccessDeniedHandler.handle(request, response, accessDeniedException);
		response.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		response.getWriter().println(
				objectMapper.writeValueAsString(ApiResponse.error(ErrorCode.FORBIDDEN, HttpStatus.FORBIDDEN, HttpStatus.FORBIDDEN.getReasonPhrase()))
		);
	}
}
