package military._km.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import military._km.domain.Member;
import military._km.domain.social.KakaoUser;
import military._km.domain.social.SocialCode;
import military._km.dto.TokenDto;
import military._km.jwt.JwtTokenProvider;

@Service
@Slf4j
@RequiredArgsConstructor
public class KakaoOAuthService {

	@Value("${spring.security.oauth2.client.provider.kakao.user-info-uri}")
	private String KAKAO_USER_INFO_URL;
	private final ValidateUserService validateUserService;
	private final JwtTokenProvider jwtTokenProvider;
	private final MemberService memberService;

	@Transactional
	public TokenDto login(String kakaoAccessToken) {
		RestTemplate restTemplate = new RestTemplate();
		String url = UriComponentsBuilder.fromHttpUrl(KAKAO_USER_INFO_URL)
			.toUriString();
		try {
			HttpHeaders headers = new HttpHeaders();
			headers.setBearerAuth(kakaoAccessToken);
			HttpEntity<String> entity = new HttpEntity<>(headers);

			ResponseEntity<KakaoUser> response = restTemplate.exchange(url, HttpMethod.GET, entity, KakaoUser.class);
			KakaoUser kakaoUser = response.getBody();
			if(kakaoUser != null && kakaoUser.getKakaoAccount() != null) {
				String email = kakaoUser.getKakaoAccount().getEmail();
				Member member = validateUserService.validateRegister(
					email, SocialCode.KAKAO
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
			} else {
				throw new RuntimeException("Failed to extract user information");
			}
		} catch (HttpClientErrorException e) {
			throw new RuntimeException("Failed to fetch user info from Kakao", e);
		}
	}

}
