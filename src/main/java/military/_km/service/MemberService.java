package military._km.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import military._km.domain.Member;
import military._km.domain.Military;
import military._km.domain.RefreshToken;
import military._km.domain.Role;
import military._km.dto.MemberLoginDto;
import military._km.dto.MemberSignupDto;
import military._km.dto.TokenDto;
import military._km.jwt.JwtTokenProvider;
import military._km.repository.MemberRepository;
import military._km.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class MemberService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisTemplate<String, String> redisTemplate;
    private final RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional
    public Member signup(MemberSignupDto memberSignupDto) {
        if(!validateEmail(memberSignupDto.getEmail())){
            throw new IllegalArgumentException("이미 존재하는 이메일입니다.");
        }
        if (!validateNickName(memberSignupDto.getNickname())) {
            throw new IllegalArgumentException("이미 존재하는 닉네임입니다.");
        }
        Member member = Member.builder()
                .email(memberSignupDto.getEmail())
                .password(passwordEncoder.encode(memberSignupDto.getPassword()))
                .role(Role.ROLE_USER)
                .nickname(memberSignupDto.getNickname())
                .military(Military.fromValue(memberSignupDto.getMilitary()))
                .startdate(memberSignupDto.getStartdate())
                .finishdate(memberSignupDto.getFinishdate())
                .build();

            memberRepository.save(member);
            return member;
    }

    @Transactional
    public TokenDto login(MemberLoginDto loginDto) {
        validate(loginDto);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginDto.getEmail(), loginDto.getPassword()
        );

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        TokenDto tokenDto = jwtTokenProvider.createTokens(authentication);

        if (redisTemplate.opsForValue().get(loginDto.getEmail()) != null) {
            redisTemplate.delete(loginDto.getEmail());
            redisTemplate.opsForValue().set(loginDto.getEmail(), tokenDto.getRefreshToken(), jwtTokenProvider.getExpiration(tokenDto.getRefreshToken()), TimeUnit.MILLISECONDS);
            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setEmail(loginDto.getEmail());
            refreshToken.setToken(tokenDto.getRefreshToken());
            refreshTokenRepository.save(refreshToken);
        }

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setEmail(loginDto.getEmail());
        refreshToken.setToken(tokenDto.getRefreshToken());
        refreshToken.setTime(jwtTokenProvider.getExpiration(tokenDto.getRefreshToken()).toString());

        refreshTokenRepository.save(refreshToken);

        redisTemplate.opsForValue().set(
                loginDto.getEmail(),
                tokenDto.getRefreshToken(),
                jwtTokenProvider.getExpiration(tokenDto.getRefreshToken()),
                TimeUnit.MILLISECONDS
        );

        return tokenDto;
    }

    public void storeRefreshToken(String email, String refreshToken) {
        //기존 리프레시 토큰이 있는 경우 삭제
        if (redisTemplate.opsForValue().get(email) != null) {
            redisTemplate.delete(email);
        }

        //새로운 리프레시 토큰 저장
        redisTemplate.opsForValue().set(email, refreshToken, jwtTokenProvider.getExpiration(refreshToken), TimeUnit.MILLISECONDS);

        RefreshToken newRefreshToken = new RefreshToken();
        newRefreshToken.setEmail(email);
        newRefreshToken.setToken(refreshToken);
        newRefreshToken.setTime(jwtTokenProvider.getExpiration(refreshToken).toString());

        refreshTokenRepository.save(newRefreshToken);
    }

    @Transactional
    public ResponseEntity<HttpStatus> logout(String header) {
        String token = header.substring(7);
        if (!jwtTokenProvider.validateToken(token)) {
            throw new IllegalArgumentException("로그아웃: 유효하지 않은 토큰입니다.");
        }
        Long expiration = jwtTokenProvider.getExpirationFromNow(token);
        Authentication authentication = jwtTokenProvider.getAuthentication(token);

        if (redisTemplate.opsForValue().get(authentication.getName()) != null) { // refresh 토큰 삭제
            redisTemplate.delete(authentication.getName());
            refreshTokenRepository.deleteById(authentication.getName());
        }

        refreshTokenRepository.deleteById(authentication.getName());
        redisTemplate.opsForValue().set(token, "logout", Duration.ofMillis(expiration));
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @Transactional
    public TokenDto reissue(String freshToken) {
        Authentication authentication = jwtTokenProvider.getAuthenticationByRefreshToken(freshToken);
        String email = authentication.getName();

        String refreshTokenInRedis = redisTemplate.opsForValue().get(email);
        if (refreshTokenInRedis == null) {
            return null;
        }
        if (!jwtTokenProvider.validateToken(refreshTokenInRedis)) {
            redisTemplate.delete(refreshTokenInRedis);
            return null;
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        redisTemplate.delete(refreshTokenInRedis);
        refreshTokenRepository.deleteById(authentication.getName());
        TokenDto tokenDto = jwtTokenProvider.createTokens(authentication);
        redisTemplate.opsForValue().set(authentication.getName(),
                tokenDto.getRefreshToken(),
                jwtTokenProvider.getExpiration(tokenDto.getRefreshToken()),
                TimeUnit.MILLISECONDS);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setEmail(authentication.getName());
        refreshToken.setToken(tokenDto.getRefreshToken());
        refreshToken.setTime(jwtTokenProvider.getExpiration(tokenDto.getRefreshToken()).toString());

        refreshTokenRepository.save(refreshToken);

        return tokenDto;
    }

    @Transactional(readOnly = true)
    public Member findMember(String email) {
        return memberRepository.findByEmail(email).orElseThrow(()-> new IllegalArgumentException("사용자가 없습니다."));
    }
    @Transactional(readOnly = true)
    public Optional<Member> getMember(Long id) {
        return memberRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public Optional<Member> getMember(String email) {
        return memberRepository.findByEmail(email);
    }

    public void deleteMember(Long id) {
        memberRepository.deleteById(id);
    }

    private void validate(MemberLoginDto loginDto) {
        memberRepository.findByEmail(loginDto.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException(loginDto.getEmail() + "해당 유저를 찾을 수 없습니다."));

        if(!passwordEncoder.matches(
                loginDto.getPassword(),
                memberRepository.findByEmail(loginDto.getEmail())
                        .orElseThrow(()-> new BadCredentialsException("비밀번호가 맞지 않습니다.")).getPassword())
        ) {
          log.info("로그인 실패.");
        }
    }

    private String getAuthorities(Authentication authentication) {

        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }

    public void validateExpire(String header) {
        String accessToken = resolve(header);
        if (!jwtTokenProvider.validateAccessTokenByExpired(accessToken)) {
            throw new IllegalArgumentException("유효하지 않은 토큰입니다.");
        }
    }

    public String resolve(String header) {
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    public boolean validateEmail(String email) { // 이메일 중복검사
        if (!memberRepository.existsByEmail(email)) {
            return true;
        }
        return false;
    }

    public boolean validateNickName(String nickname) { // 닉네임 중복검사
        if (!memberRepository.existsByNickname(nickname)) {
            return true;
        }
        return false;
    }

}
