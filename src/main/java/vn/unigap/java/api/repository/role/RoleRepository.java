package vn.unigap.java.api.repository.role;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import vn.unigap.java.api.entity.Role;

import java.util.List;

@Repository
public interface RoleRepository extends JpaRepository<Role, String> {
	@Query(
			value = "SELECT A.* " +
					"FROM ROLE A " +
					"INNER JOIN ACCOUNT_ROLE B ON A.ID = B.ROLE_ID " +
					"INNER JOIN ACCOUNT C ON B.ACCOUNT_ID = C.ID " +
					"WHERE C.ID = :ACCOUNT_ID",
			nativeQuery = true
	)
	List<Role> listRoleByAccountId(@Param(value = "ACCOUNT_ID") String accountId);
}
