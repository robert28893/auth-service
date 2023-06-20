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
	@Column(name = "ID")
	@Builder.Default
	private String id = Common.uuid();

	@Column(name = "USERNAME", unique = true)
	private String username;

	@Column(name = "PASSWORD")
	private String password;

	@Column(name = "EMAIL")
	private String email;

	@Column(name = "FULL_NAME")
	private String fullName;

	@Builder.Default
	@Column(name = "ENABLED")
	private Integer enabled = 0; // 0: chua kich hoat, 1: kich hoat

	@Builder.Default
	@Column(name = "EXPIRED")
	private Integer expired = 0; // 0: chua het han, 1: het han

	@Builder.Default
	@Column(name = "LOCKED")
	private Integer locked = 0; // 0: Khong khoa, 1: Khoa

	@Builder.Default
	@Column(name = "CREDENTIALS_EXPIRED")
	private Integer credentialsExpired = 0; // mat khau het han 0: chua het han, 1: het han

	@Builder.Default
	@Column(name = "CREATED_DATE")
	private Date createdDate = new Date();

	@Builder.Default
	@Column(name = "UPDATED_DATE")
	private Date updatedDate = new Date();

}
