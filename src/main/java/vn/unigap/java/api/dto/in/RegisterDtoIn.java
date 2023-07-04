package vn.unigap.java.api.dto.in;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class RegisterDtoIn {
	@NotEmpty
	@Email
	private String email;

	@NotEmpty
	private String fullName;

	@NotEmpty
	private String password;
}
