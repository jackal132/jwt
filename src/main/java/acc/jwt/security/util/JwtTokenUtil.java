package acc.jwt.security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import static acc.jwt.security.enums.JwtExpirationEnums.ACCESS_TOKEN_EXPIRATION_TIME;
import static acc.jwt.security.enums.JwtExpirationEnums.REFRESH_TOKEN_EXPIRATION_TIME;

@Slf4j
@Component
public class JwtTokenUtil {

    @Value("${jwt.secret}")
    private String SECRET_KEY;

    /**
     * 토큰 추출 메서드
     * 서명했을때 secretkey 로 서명하고 토큰을 만들때 username,발급날짜,만료기간을 넣었단 payload를 가져온다.
     * @param token
     * @return
     */
    public Claims extratAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey(SECRET_KEY))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getUsername(String token){
        return extratAllClaims(token).get("username", String.class);
    }

    private Key getSigningKey(String secretKey){
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Boolean isTokenExpired(String token){
        Date expiration = extratAllClaims(token).getExpiration();
        return expiration.before(new Date());
    }

    public String generateAccessToken(String username){
        return doGenerateToken(username, ACCESS_TOKEN_EXPIRATION_TIME.getValue());
    }

    public String generateRefreshToken(String username){
        return doGenerateToken(username, REFRESH_TOKEN_EXPIRATION_TIME.getValue());
    }

    /**
     * 토큰 생성 매서드
     * JWT 구성 ( header.payload.signature )
     * username,발급날짜,만료기간을 payload 에 넣고 application.yml 에 설정한 secretkey 로 서명 후 HS256알고리즘으로 암호화한다.
     * @param username
     * @param expireTime
     * @return
     */
    private String doGenerateToken(String username, long expireTime){
        Claims claims = Jwts.claims();
        claims.put("username", username);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expireTime))
                .signWith(getSigningKey(SECRET_KEY), SignatureAlgorithm.HS256)
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails){
        String username = getUsername(token);
        return username.equals(userDetails.getUsername())
                    && !isTokenExpired(token);
    }

    public long getRemainMilliSeconds(String token){
        Date expiration = extratAllClaims(token).getExpiration();
        Date now = new Date();
        return expiration.getTime() - now.getTime();
    }
}
