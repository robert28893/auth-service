package vn.unigap.java.api.dto.out;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AccountDtoOut {
    private String id;
    private String username;
    private String email;
    private String fullName;
}
