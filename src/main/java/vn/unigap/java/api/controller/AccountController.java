package vn.unigap.java.api.controller;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import vn.unigap.java.api.dto.in.ConfirmRegisterDtoIn;
import vn.unigap.java.api.dto.in.RegisterDtoIn;
import vn.unigap.java.api.service.AccountService;
import vn.unigap.java.common.controller.AbstractResponseController;
import vn.unigap.java.common.exception.ApiException;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(value = "/account", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
public class AccountController extends AbstractResponseController {

	private final AccountService accountService;

	@Autowired
	public AccountController(AccountService accountService) {
		this.accountService = accountService;
	}

	/*
		1. Tao tai khoan Account voi enabled = 0, gan tai khoan cho role
		2. Tao 1 token gan voi tai khoan
	 */
	@PostMapping(value = "/register")
	public ResponseEntity<?> register(@RequestBody @Valid RegisterDtoIn registerDtoIn) {
		return responseEntity(() -> {
			accountService.register(registerDtoIn);
			return new HashMap<>();
		});
	}

	/*
		1. Kiem tra xem token co hop le khong
		2. Kich hoat tai khoan gan voi token
	 */
	@PostMapping(value = "/confirm-register")
	public ResponseEntity<?> confirmRegister(@RequestBody @Valid ConfirmRegisterDtoIn confirmRegisterDtoIn) {
		return responseEntity(() -> {
			accountService.confirmRegister(confirmRegisterDtoIn);
			return new HashMap<>();
		});
	}

	@GetMapping(value = "/test")
//	@PreAuthorize(value = "hasAnyAuthority('ADMIN')")
	public ResponseEntity<?> test() {
		return responseEntity(() -> {
//			throw new RuntimeException();
//			throw new ApiException(2, HttpStatus.BAD_REQUEST, "error");
			Map<String, String> map = new HashMap<>();
			map.put("x", "y");
			return map;
		});
	}
}
