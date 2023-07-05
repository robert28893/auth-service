package vn.unigap.java.api.repository.role;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import vn.unigap.java.api.entity.Role;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, String> {
	@Query(
			value = "SELECT A.* " +
					"FROM role A " +
					"INNER JOIN account_role B ON A.ID = B.ROLE_ID " +
					"INNER JOIN account C ON B.ACCOUNT_ID = C.ID " +
					"WHERE C.ID = :ACCOUNT_ID",
			nativeQuery = true
	)
	List<Role> listRoleByAccountId(@Param(value = "ACCOUNT_ID") String accountId);

	Optional<Role> findByName(String name);
}
