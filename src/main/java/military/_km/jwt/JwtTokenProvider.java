package military._km.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import military._km.dto.TokenDto;
import military._km.service.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;


import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtTokenProvider {


    private final RedisTemplate<String, String> redisTemplate;

    private final CustomUserDetailService userDetailService;

    private static final String AUTHORITIES_KEY = "auth";
    private static final String BEARER_TYPE = "Bearer";
    private final SecretKey key;

    private final static Long ACCESS_TOKEN_EXPIRE_TIME = 30 * 60 * 1000L; // 30분
    private final static Long REFRESH_TOKEN_EXPIRE_TIME = 7 * 24 * 60 * 60 * 1000L; // 일주일

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey,
                            RedisTemplate<String, String> redisTemplate, CustomUserDetailService userDetailService) {
        this.userDetailService = userDetailService;
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.redisTemplate = redisTemplate;
    }

    /*
       AccessToken 생성
    */
    public String createAccessToken(String email, String authorities) {
        Date now = new Date();
        Date access_expire = new Date(now.getTime() + ACCESS_TOKEN_EXPIRE_TIME);

        return Jwts.builder()
                .subject(email)
                .claim(AUTHORITIES_KEY,authorities)
                .issuedAt(now)
                .expiration(access_expire)
                .signWith(key)
                .compact();
    }

    /*
       RefreshToken 생성
    */
    public String createRefreshToken(String email, String authorities) {
        Date now = new Date();
        Date refresh_expire = new Date(now.getTime() + REFRESH_TOKEN_EXPIRE_TIME);

       return Jwts.builder()
                .subject(email)
                .claim("isRefreshToken", true)
                .issuedAt(now)
                .expiration(refresh_expire)
                .signWith(key)
                .compact();
    }

    public TokenDto createTokens(Authentication authentication) {

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        String accessToken = createAccessToken(authentication.getName(),authorities);
        String refreshToken = createRefreshToken(authentication.getName(), authorities);

        log.info("accessToken = {}", accessToken);
        log.info("refreshToken = {}", refreshToken);

        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public TokenDto reissue(String freshToken) {
        Claims claims = parse(freshToken);

        if (!validateToken(freshToken) || claims.get("isRefreshToken") == null || !Boolean.TRUE.equals(claims.get("isRefreshToken"))) {
            log.info("유효하지 않은 리프레쉬 토큰 입니다.");
        }

        String email = claims.getSubject();
        String authorities = claims.get(AUTHORITIES_KEY).toString();

        String accessToken = createAccessToken(email, authorities);
        String refreshToken = createRefreshToken(email, authorities);

        redisTemplate.opsForValue().set(
                email,
                refreshToken
        );

        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = parse(token);

        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .toList();

        UserDetails principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal,"", authorities);

    }

    public Authentication getAuthenticationByRefreshToken(String refreshToken) {
        Claims claims = parse(refreshToken);

        if (!validateToken(refreshToken) || claims.get("isRefreshToken") == null || !Boolean.TRUE.equals(claims.get("isRefreshToken"))) {
            log.info("유요하지 않은 리프레쉬 토큰 입니다.");
        }
        String email = parse(refreshToken).getSubject();
        UserDetails userDetails = userDetailService.loadUserByUsername(email);

        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public Long getExpirationFromNow(String accessToken) { // 남은 만료기간
        Date expiration = Jwts.parser().verifyWith(key).build().parseSignedClaims(accessToken).getPayload().getExpiration();

        long now = new Date().getTime();
        return expiration.getTime()-now;
    }

    public Long getExpiration(String token) {
        return parse(token).getExpiration().getTime();
    }



    public boolean validateToken(String token) {
        String value = redisTemplate.opsForValue().get(token);
        try {
            if (value != null && value.equals("logout")) { // 로그아웃
                return false;
            }
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.info("토큰이 만료되었습니다.");
            throw new RuntimeException("토큰 만료");
        } catch (JwtException e) {
            log.info("잘못된 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("claim이 비어있습니다.");
        } catch (NullPointerException e) {
            log.info("Jwt token이 비어있습니다.");
        }
        return false;
    }

    public boolean validateAccessTokenByExpired(String accessToken) {
        try {
            return parse(accessToken)
                    .getExpiration()
                    .before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private Claims parse(String accessToken) {
        try {
            return Jwts.parser().verifyWith(key).build().parseSignedClaims(accessToken).getPayload();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

}
