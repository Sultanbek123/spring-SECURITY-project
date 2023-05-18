package kz.bitlab.springsecuritytesting.repositories;

import jakarta.transaction.Transactional;
import kz.bitlab.springsecuritytesting.entities.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
@Transactional
public interface UsersRepository extends JpaRepository<Users,Long> {
    Users findByEmail(String email);
}
