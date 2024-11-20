package military._km.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import military._km.domain.Member;
import military._km.dto.MemberLoginDto;
import military._km.dto.MemberSignupDto;
import military._km.dto.TokenDto;
import military._km.service.MemberService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@Valid @RequestBody MemberLoginDto memberLoginDto) {
        try {
            TokenDto tokenDto = memberService.login(memberLoginDto);
            log.info("로그인에 성공했습니다.");
            return new ResponseEntity<>(new TokenDto(tokenDto.getGrantType(), tokenDto.getAccessToken(), tokenDto.getRefreshToken()), HttpStatus.OK);
        } catch (AuthenticationException e) {
            log.info("로그인에 실패했습니다.");
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<HttpStatus> signup(@Valid @RequestBody MemberSignupDto memberSignupDto) {
        Member member = memberService.signup(memberSignupDto);
        if (member.getId() != null) {
            log.info("회원가입에 성공했습니다.");
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            log.info("회원가입에 실패하였습니다.");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/member/logout")
    public ResponseEntity<HttpStatus> logout(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        log.info("header={}", header);
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        log.info("email={}", email);
        return memberService.logout(header);
    }

    @GetMapping("/reissue")
    public ResponseEntity<?> reissue(@CookieValue(name = "refresh-token") String refreshToken) {
        log.info("refreshToken ={}", refreshToken);
        TokenDto reissueTokenDto = memberService.reissue(refreshToken);

        if (reissueTokenDto != null) { // 토큰 재발급 성공
            ResponseCookie responseCookie = ResponseCookie.from("refresh-token", reissueTokenDto.getRefreshToken())
                    .maxAge(Duration.ofDays(14))
                    .httpOnly(true)
                    .secure(true)
                    .build();
            return ResponseEntity
                    .status(HttpStatus.OK)
                    .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + reissueTokenDto.getAccessToken())
                    .build();
        } else {
            ResponseCookie responseCookie = ResponseCookie.from("refresh-token", "")
                    .maxAge(0)
                    .path("/")
                    .build();
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                    .build();
        }
    }

    @GetMapping("/check")
    public ResponseEntity<HttpStatus> checkEmail(@RequestParam(name = "email") String email) {
        boolean result = memberService.validateEmail(email);

        if(!result) {
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
}
