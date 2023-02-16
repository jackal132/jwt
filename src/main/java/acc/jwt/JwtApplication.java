package acc.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * JWT 기본으로 요청 및 토큰일 만료되었을 경우에 대한 플로우
 * 1. JWT 토을을 들고 요청 ->
 * <- 1.토큰 체크, 권한 체크, 응답 반환
 *
 * 2. JWT토큰을 들고 요청(만료된 토큰) ->
 * <- 2.만료된 토큰이라고 응답 반환
 *
 * 2. 만료 응답을 받은후 accessToken, refreshToken을 전달 ->
 * <- 2.만료기간에 따라 accessToken 혹은 assessToekn, refreshToken 모두 재발급
 */

@SpringBootApplication
public class JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
	}

}
