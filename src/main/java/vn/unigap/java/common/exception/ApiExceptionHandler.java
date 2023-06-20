package vn.unigap.java.common.exception;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import vn.unigap.java.common.errorcode.ErrorCode;
import vn.unigap.java.common.response.ApiResponse;


@ControllerAdvice
@Order
public class ApiExceptionHandler {
	@ExceptionHandler(value = ApiException.class)
	public ResponseEntity<?> handleApiException(ApiException e) {
		return new ResponseEntity<>(
				ApiResponse.builder()
						.errorCode(e.getErrorCode())
						.statusCode(e.getHttpStatus().value())
						.message(e.getMessage())
						.build(),
				e.getHttpStatus());
	}

	@ExceptionHandler(value = AccessDeniedException.class)
	public ResponseEntity<?> handleAccessDeniedException() {
		return new ResponseEntity<>(
				ApiResponse.builder()
						.errorCode(ErrorCode.FORBIDDEN)
						.statusCode(HttpStatus.FORBIDDEN.value())
						.message(HttpStatus.FORBIDDEN.getReasonPhrase())
						.build(),
				HttpStatus.FORBIDDEN);
	}

	@ExceptionHandler(value = Exception.class)
	public ResponseEntity<?> handleUnknownException(Exception e) {
		e.printStackTrace();
		return new ResponseEntity<>(
				ApiResponse.builder()
						.errorCode(ErrorCode.INTERNAL_ERR)
						.statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
						.message(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase())
						.build(),
				HttpStatus.INTERNAL_SERVER_ERROR);
	}
}
