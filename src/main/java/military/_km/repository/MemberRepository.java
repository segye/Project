package military._km.repository;

import military._km.domain.Member;
import military._km.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByEmail(String email);
    boolean existsByEmail(String email);
    boolean existsByNickname(String nickname);

    @Query(value = "select m.role from Member m where m.email = :email")
    Role checkSocialMemberByEmail(String email);
}
