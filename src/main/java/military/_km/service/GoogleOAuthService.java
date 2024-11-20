package military._km.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import military._km.domain.Member;
import military._km.domain.social.SocialCode;
import military._km.dto.TokenDto;
import military._km.jwt.JwtTokenProvider;

@Service
@Slf4j
@RequiredArgsConstructor
public class GoogleOAuthService {
	private final ValidateUserService validateUserService;
	private final JwtTokenProvider jwtTokenProvider;
	private final MemberService memberService;

	@Transactional
	public TokenDto login(GoogleIdToken idToken) {
		GoogleIdToken.Payload payload = idToken.getPayload();

		Member member = validateUserService.validateRegister(
			payload.getEmail(), SocialCode.GOOGLE
		);

		if(member == null) {
			throw new IllegalArgumentException("가입되지 않은 사용자입니다.");
		}

		String accessToken = jwtTokenProvider.createAccessToken(member.getEmail(), member.getRole().toString());
		String refreshToken = jwtTokenProvider.createRefreshToken(member.getEmail(), member.getRole().toString());

		memberService.storeRefreshToken(member.getEmail(), refreshToken);

		return TokenDto.builder()
			.grantType("Bearer")
			.accessToken(accessToken)
			.refreshToken(refreshToken)
			.build();
	}
}
