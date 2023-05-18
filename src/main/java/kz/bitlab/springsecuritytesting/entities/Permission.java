package kz.bitlab.springsecuritytesting.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Table(name="permissions")
@Getter
@Setter
public class Permission extends BaseEntity implements GrantedAuthority {
    private String role;

    @Override
    public String getAuthority() {
        return role;
    }
}
