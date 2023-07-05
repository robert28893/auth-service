package vn.unigap.java.api.repository.accountrole;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import vn.unigap.java.api.entity.AccountRole;

@Repository
public interface AccountRoleRepository extends JpaRepository<AccountRole, String> {
}
