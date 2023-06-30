package vn.unigap.java.api.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import vn.unigap.java.api.dto.in.ConfirmRegisterDtoIn;
import vn.unigap.java.api.dto.in.RegisterDtoIn;
import vn.unigap.java.api.dto.out.AccountDtoOut;
import vn.unigap.java.api.entity.Account;
import vn.unigap.java.api.repository.account.AccountRepository;
import vn.unigap.java.common.errorcode.ErrorCode;
import vn.unigap.java.common.exception.ApiException;

@Service
public class AccountServiceImpl implements AccountService {

    private final AccountRepository accountRepository;

    @Autowired
    public AccountServiceImpl(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @Override
    public void register(RegisterDtoIn registerDtoIn) {
        // TODO: implement register
    }

    @Override
    public void confirmRegister(ConfirmRegisterDtoIn confirmRegisterDtoIn) {
        // TODO: implement confirm register
    }

    @Override
    public AccountDtoOut getProfile() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        Account account = accountRepository.findByUsername(username).orElseThrow(
                () -> new ApiException(ErrorCode.NOT_FOUND, HttpStatus.NOT_FOUND,
                        String.format("username not found: %s", username))
        );

        return AccountDtoOut.builder()
                .id(account.getId())
                .email(account.getEmail())
                .fullName(account.getFullName())
                .username(account.getUsername())
                .build();
    }
}
