package military._km.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import military._km.jwt.JwtAccessDeniedHandler;
import military._km.jwt.JwtAuthenticationEntryPointHandler;
import military._km.jwt.JwtFilter;
import military._km.jwt.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAccessDeniedHandler deniedHandler;
    private final JwtAuthenticationEntryPointHandler authenticationEntryPointHandler;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate<String, String> redisTemplate;

    private static final String[] PERMIT_ALL_PATTERNS = new String[] {
            "/login","/signup","/logout","/reissue",
            "/auth/naver","/auth/kakao","/auth/google"
            ,"/email/send", "/email/verify", "/check"
    };

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.addAllowedOriginPattern("http://10.0.2.2:8080");
                        config.addAllowedOriginPattern("http://127.0.0.1:8080");
                        config.setAllowedMethods(List.of("GET","POST","DELETE","PATCH","OPTION","PUT"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        return config;
                    }
                }))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler(deniedHandler)
                        .authenticationEntryPoint(authenticationEntryPointHandler))
                .authorizeHttpRequests((requests) -> requests
                                .requestMatchers(Arrays.stream(PERMIT_ALL_PATTERNS)
                                        .map(AntPathRequestMatcher::antMatcher)
                                        .toArray(AntPathRequestMatcher[]::new)
                                ).permitAll()
                                .anyRequest().authenticated()
                        //.requestMatchers(HttpMethod.GET,"/**").hasAnyRole("USER","SOCIAL")
                        //.requestMatchers(HttpMethod.POST,"/**").hasAnyRole("USER","ADMIN","SOCIAL")
                )
                .addFilterBefore(new JwtFilter(jwtTokenProvider, redisTemplate), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }


    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}