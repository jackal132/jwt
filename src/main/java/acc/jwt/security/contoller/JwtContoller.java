package acc.jwt.security.contoller;

import acc.jwt.security.dto.JoinDto;
import acc.jwt.security.dto.LoginDto;
import acc.jwt.security.dto.MemberInfo;
import acc.jwt.security.dto.TokenDto;
import acc.jwt.security.service.MemberService;
import acc.jwt.security.util.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class JwtContoller {

    private final MemberService memberService;
    private final JwtTokenUtil jwtTokenUtil;

    @GetMapping("/health")
    public String health(){
        return "OK";
    }

    @PostMapping("/join")
    public String join(@RequestBody JoinDto joinDto){
        memberService.join(joinDto);
        return "USER 회원가입";
    }

    @PostMapping("/join/admin")
    public String joinAdmin(@RequestBody JoinDto joinDto){
        memberService.joinAdmin(joinDto);
        return "ADMIN 회원가입";
    }

    /**
     * accessToekn을 발급받고, refreshToken을 Redis에 저장
     * @param loginDto
     * @return
     */
    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@RequestBody LoginDto loginDto){
        return ResponseEntity.ok(memberService.login(loginDto));
    }

    @GetMapping("/members/{email}")
    public MemberInfo getMemberInfo(@PathVariable String email){
        return memberService.getMemberInfo(email);
    }

    /**
     * 토큰은 유효기간이 있기 때문에, 기간이 지났을 경우를 위해
     * redis에 저장한 refreshToken의 남은 만료기간에 따라
     * accessToken과 refreshToken 두개 모두 혹은 accessToken만 재발급
     * @param refreshToken
     * @return
     */
    @PostMapping("/reissue")
    public ResponseEntity<TokenDto> reissue(@RequestHeader("RefreshToken") String refreshToken){
        return ResponseEntity.ok(memberService.reissue(refreshToken));
    }

    /**
     * assessToken의 남은 유효기간 동안 Redis에 logoutAccessToken을 저장하여 해당 토큰으로 접근 하는것을 금지시킨다
     * @param accessToken
     * @param refreshToken
     */
    @PostMapping("/logout")
    public void logout(@RequestHeader("Authorization") String accessToken,
                       @RequestHeader("RefreshToken") String refreshToken){
        String username = jwtTokenUtil.getUsername(resolveToken(accessToken));
        memberService.logout(TokenDto.of(accessToken, refreshToken), username);
    }

    private String resolveToken(String accessToken){
        return accessToken.substring(7);
    }
}
