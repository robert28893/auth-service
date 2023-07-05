package vn.unigap.java.api.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import vn.unigap.java.api.dto.in.ConfirmRegisterDtoIn;
import vn.unigap.java.api.dto.in.RegisterDtoIn;
import vn.unigap.java.api.dto.out.AccountDtoOut;
import vn.unigap.java.api.entity.Account;
import vn.unigap.java.api.entity.AccountRole;
import vn.unigap.java.api.entity.Role;
import vn.unigap.java.api.entity.Token;
import vn.unigap.java.api.repository.account.AccountRepository;
import vn.unigap.java.api.repository.accountrole.AccountRoleRepository;
import vn.unigap.java.api.repository.role.RoleRepository;
import vn.unigap.java.api.repository.token.TokenRepository;
import vn.unigap.java.common.Common;
import vn.unigap.java.common.enums.RoleEnum;
import vn.unigap.java.common.enums.TokenStatus;
import vn.unigap.java.common.errorcode.ErrorCode;
import vn.unigap.java.common.exception.ApiException;

@Service
public class AccountServiceImpl implements AccountService {

	private final AccountRepository accountRepository;
	private final PasswordEncoder passwordEncoder;
	private final RoleRepository roleRepository;
	private final AccountRoleRepository accountRoleRepository;
	private final TokenRepository tokenRepository;

	@Autowired
	public AccountServiceImpl(
			AccountRepository accountRepository,
			PasswordEncoder passwordEncoder,
			RoleRepository roleRepository,
			AccountRoleRepository accountRoleRepository,
			TokenRepository tokenRepository) {
		this.accountRepository = accountRepository;
		this.passwordEncoder = passwordEncoder;
		this.roleRepository = roleRepository;
		this.accountRoleRepository = accountRoleRepository;
		this.tokenRepository = tokenRepository;
	}

	@Override
	public void register(RegisterDtoIn registerDtoIn) {
		accountRepository.findByUsername(registerDtoIn.getEmail()).ifPresentOrElse(
				account -> {
					throw new ApiException(ErrorCode.BAD_REQUEST, HttpStatus.BAD_REQUEST,
							String.format("email already existed: %s", registerDtoIn.getEmail()));
				},
				() -> {
					Role role = roleRepository.findByName(RoleEnum.USER.getRoleName()).orElseThrow(
							() -> new IllegalStateException(String.format("Role not found: %s", RoleEnum.USER.getRoleName()))
					);

					Account account = accountRepository.save(
							Account.builder()
									.username(registerDtoIn.getEmail())
									.password(passwordEncoder.encode(registerDtoIn.getPassword()))
									.email(registerDtoIn.getEmail())
									.fullName(registerDtoIn.getFullName())
									.build()
					);

					accountRoleRepository.save(AccountRole.builder()
							.accountId(account.getId())
							.roleId(role.getId())
							.build());

					Token token = tokenRepository.save(Token.builder()
							.code(Common.uuid())
							.status(TokenStatus.INIT.getStatus())
							.resourceId(account.getId())
							.build());
					// TODO: send token to email
				}
		);
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
