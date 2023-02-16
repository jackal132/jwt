package acc.jwt.security.domain;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;

@Entity
@Getter
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@AllArgsConstructor(access= AccessLevel.PROTECTED)
@Builder
public class Authority implements GrantedAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="AUTHORITY_ID")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name= "MEMBER_ID")
    private Member member;

    private String role;

    public static Authority ofUser(Member member){
        return Authority.builder()
                .role("ROLE_USER")
                .member(member)
                .build();
    }

    public static Authority ofAdmin(Member member){
        return Authority.builder()
                .role("ROLE_ADMIN")
                .member(member)
                .build();
    }

    @Override
    public String getAuthority() {
        return role;
    }
}
