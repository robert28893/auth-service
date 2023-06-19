package vn.unigap.java.api.controller;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import vn.unigap.java.api.dto.in.RegisterDtoIn;
import vn.unigap.java.api.service.AccountService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(value = "/account", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
public class AccountController {

	private final AccountService accountService;

	@Autowired
	public AccountController(AccountService accountService) {
		this.accountService = accountService;
	}

	@PostMapping(value = "/register")
	public ResponseEntity<?> register(@RequestBody @Valid RegisterDtoIn registerDtoIn) {
		return null;
	}

	@GetMapping(value = "/test")
	public ResponseEntity<?> test() {
		Map<String, String> map = new HashMap<>();
		map.put("x", "y");
		return ResponseEntity.ok(map);
	}
}
