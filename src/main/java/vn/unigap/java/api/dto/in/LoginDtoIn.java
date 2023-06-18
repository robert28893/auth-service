package vn.unigap.java.api.dto.in;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class LoginDtoIn {
    @NotEmpty
    private String username;

    @NotEmpty
    private String password;
}
