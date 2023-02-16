package acc.jwt.security.dto;

import lombok.*;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class JoinDto {

    private String email;
    private String password;
    private String nickname;
}
