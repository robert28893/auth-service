package vn.unigap.java.api.repository.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import vn.unigap.java.api.entity.Token;

@Repository
public interface TokenRepository extends JpaRepository<Token, String> {
}
