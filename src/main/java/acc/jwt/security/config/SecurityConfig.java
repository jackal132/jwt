package acc.jwt.security.config;

import acc.jwt.security.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    /**
     * 시큐리티 권한 제한없이 접근할 url경로 설정
     */
    private final String WHITELIST[] = {
            "/",
            "/join/**",
            "/login",
            "/health",
            "/h2-console/**",
            "/favicon.ico"
    };

    /**
     * 시큐리티 필터 과정중 에러가 발생할 경우 jwtEntryPoint에서 처리
     */
    private final JwtEntryPoint jwtEntryPoint;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    /**
     * 시큐리티에서 제공하는 유저의 정보를 가져오기 위한 클래스인 UserDetailsService를 커스터마이징하여 구현
     */
    private final CustomUserDetailsService customUserDetailsService;

    /**
     *  비밀번호 암호화 클래스
     *  Bcrypt strong hashing function을 통해 암호화 (단방향)
     * @return
     */
    @Bean
    private static BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .csrf().disable()
                .authorizeRequests()
                .antMatchers(WHITELIST).permitAll()
                .anyRequest().hasRole("USER")
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(jwtEntryPoint)

                .and()
                .headers()
                .frameOptions().disable()

                .and()
                .logout().disable() //jwt 기반으로 로그인 로그아웃 처리할 것이기 때문에 disable설정
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 기본 로그인 로그아웃시 세션을 통해 요저 정보들을 저장하지만 Redis를 사용할 것이기 때문에 상태를 저장하지 않는 STATELESS 설정

                .and() // JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 전에 필터를 추가하겠다는 의미
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }
}
