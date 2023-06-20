package vn.unigap.java.api.dto.in;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class ConfirmRegisterDtoIn {
	@NotEmpty
	private String tokenId;
}
