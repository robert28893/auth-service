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
@Table(name = "TOKEN")
public class Token {
	@Id
	@Column(name = "ID")
	@Builder.Default
	private String id = Common.uuid();

	@Column(name = "CODE", unique = true)
	private String code;

	@Builder.Default
	@Column(name = "TYPE")
	private Integer type = 1; // 1: kich hoat tai khoan

	@Builder.Default
	@Column(name = "STATUS")
	private Integer status = 0; // 0: chua su dung, 1: da su dung

	@Column(name = "RESOURCE_ID")
	private String resourceId; // id cua doi tuong lien quan den token: account_id, ...

	@Builder.Default
	@Column(name = "CREATED_DATE")
	private Date createdDate = new Date();

	@Column(name = "EXPIRED_DATE")
	private Date expiredDate; // thoi gian token se het han
}
