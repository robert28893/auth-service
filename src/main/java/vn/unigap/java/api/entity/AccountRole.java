package vn.unigap.java.api.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import vn.unigap.java.common.Common;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "ACCOUNT_ROLE")
public class AccountRole {
	@Id
	@Column(name = "ID")
	@Builder.Default
	private String id = Common.uuid();

	@Column(name = "ACCOUNT_ID")
	private String accountId;

	@Column(name = "ROLE_ID")
	private String roleId;
}
