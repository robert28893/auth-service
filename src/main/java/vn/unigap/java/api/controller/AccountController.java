package vn.unigap.java.api.controller;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import vn.unigap.java.api.dto.in.LoginDtoIn;
import vn.unigap.java.api.dto.in.RefreshTokenDtoIn;
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

    @PostMapping(value = "/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginDtoIn loginDtoIn) {
        return ResponseEntity.ok(accountService.login(loginDtoIn));
    }

    @PostMapping(value = "/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody @Valid RefreshTokenDtoIn refreshTokenDtoIn) {
        return ResponseEntity.ok(accountService.refreshToken(refreshTokenDtoIn));
    }

    @GetMapping(value = "/test")
    public ResponseEntity<?> test() {
        Map<String, String> map = new HashMap<>();
        map.put("x", "y");
        return ResponseEntity.ok(map);
    }
}
