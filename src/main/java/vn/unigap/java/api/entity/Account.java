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

import java.util.Date;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "ACCOUNT")
public class Account {
	@Id
	@Column(name = "UUID_ACCOUNT")
	@Builder.Default
	private String uuidAccount = Common.uuid();

	@Column(name = "USERNAME", unique = true)
	private String username;

	@Column(name = "EMAIL")
	private String email;

	@Column(name = "FULL_NAME")
	private String fullName;

	@Builder.Default
	@Column(name = "ACTIVATED")
	private Integer activated = 0; // 0: chua kich hoat, 1: kich hoat

	@Column(name = "CREATED_DATE")
	private Date createdDate;

	@Column(name = "UPDATED_DATE")
	private Date updatedDate;

}
