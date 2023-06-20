package vn.unigap.java.authentication;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import vn.unigap.java.api.entity.Account;
import vn.unigap.java.api.entity.Role;
import vn.unigap.java.api.repository.account.AccountRepository;
import vn.unigap.java.api.repository.role.RoleRepository;

import java.util.List;
import java.util.stream.Collectors;

public class CustomUserDetailService implements UserDetailsService {

	private final AccountRepository accountRepository;
	private final RoleRepository roleRepository;

	public CustomUserDetailService(AccountRepository accountRepository, RoleRepository roleRepository) {
		this.accountRepository = accountRepository;
		this.roleRepository = roleRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Account account = accountRepository.findByUsername(username).orElseThrow(
				() -> new UsernameNotFoundException(String.format("username not found: %s", username))
		);

		List<Role> roles = roleRepository.listRoleByAccountId(account.getId());
		if (roles.isEmpty()) {
			throw new AuthenticationServiceException(String.format("role not found for username: %s", username));
		}

		boolean enabled = account.getEnabled() != 0;
		boolean nonExpired = account.getExpired() == 0;
		boolean credentialsNonExpired = account.getCredentialsExpired() == 0;
		boolean nonLocked = account.getLocked() == 0;


		List<GrantedAuthority> authorities = roles.stream().map(role -> new SimpleGrantedAuthority(role.getName()))
				.collect(Collectors.toList());

		return new User(account.getUsername(), account.getPassword(), enabled, nonExpired, credentialsNonExpired,
				nonLocked, authorities);
	}
}
