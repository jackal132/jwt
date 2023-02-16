package acc.jwt.security.config;

import acc.jwt.security.dao.LogoutAccessTokenRedisRepository;
import acc.jwt.security.service.CustomUserDetailsService;
import acc.jwt.security.util.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final CustomUserDetailsService customUserDetailsService;
    private final LogoutAccessTokenRedisRepository logoutAccessTokenRedisRepository;

    /**
     * 1. getToken 메서드로 헤더에서 JWT를  'Bearer'를 제외하고 가져온다. 만약 JWT프론트에서 주지 않았을경우 null 그대로 반환
     * 2. 해당 토큰이 null이 아닐 경우 로그아웃된 토큰인지 검증
     * 3. JwtTokenUtil에 선언된 메서드에서 username을 가져온다
     * 4. username이 null이 아닌경우 앞서 만든 CustomUserDetailService에서 UserDetails객체를 가져온다.
     * 5. 토큰에서 추출한 username과 userDetailService에서 가져온 username이 맞는지 검증하고 토큰 유효성 검사 진행
     * 6. 검증 과정에 예외가 발생하지 않으면 해당 유저 정보는 SecurityContext에 넣어준다.
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = getToken(request);
        if(accessToken != null){
            checkLogout(accessToken);
            String username = jwtTokenUtil.getUsername(accessToken);
            if(username != null){
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
                equalsUsernameFromTokenAndUserDetails(userDetails.getUsername(), username);
                validateAccessToken(accessToken, userDetails);
                processSecurity(request, userDetails);
            }
        }
        filterChain.doFilter(request, response);
    }

    private String getToken(HttpServletRequest request){
        String headerAuth = request.getHeader("Authorization");
        if(StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")){
            return headerAuth.substring(7);
        }
        return null;
    }

    private void checkLogout(String accessToken){
        if(logoutAccessTokenRedisRepository.existsById(accessToken)){
            throw new IllegalArgumentException("이미 로그아웃된 회원입니다.");
        }
    }

    private void equalsUsernameFromTokenAndUserDetails(String userDetailsUsername, String tokenUsername){
        if(!userDetailsUsername.equals(tokenUsername)){
            throw new IllegalArgumentException("username이 토큰과 맞지 않습니다");
        }
    }

    private void validateAccessToken(String accessToken, UserDetails userDetails){
        if(!jwtTokenUtil.validateToken(accessToken, userDetails)){
            throw new IllegalArgumentException("토큰 검증 실패");
        }
    }

    private void processSecurity(HttpServletRequest request, UserDetails userDetails){
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }
}
