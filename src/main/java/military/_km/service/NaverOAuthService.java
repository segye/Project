package military._km.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.RequiredArgsConstructor;
import military._km.domain.Member;
import military._km.domain.social.NaverUserInfo;
import military._km.domain.social.NaverUserResponse;
import military._km.domain.social.SocialCode;
import military._km.dto.TokenDto;
import military._km.jwt.JwtTokenProvider;

@Service
@RequiredArgsConstructor
public class NaverOAuthService {

	@Value("${spring.security.oauth2.client.provider.naver.user-info-uri}")
	private String NAVER_USER_INFO_URL;

	private final ValidateUserService validateUserService;
	private final JwtTokenProvider jwtTokenProvider;
	private final MemberService memberService;

	public TokenDto login(String naverAccessToken) {
		RestTemplate restTemplate = new RestTemplate();
		String url = UriComponentsBuilder.fromHttpUrl(NAVER_USER_INFO_URL)
			.toUriString();
		try {
			HttpHeaders headers = new HttpHeaders();
			headers.setBearerAuth(naverAccessToken);
			HttpEntity<String> entity = new HttpEntity<>(headers);

			ResponseEntity<NaverUserResponse> response = restTemplate.exchange(url, HttpMethod.GET, entity, NaverUserResponse.class);
			NaverUserInfo naverUser = response.getBody().getResponse();

			if(naverUser != null) {
				String email = naverUser.getEmail();

				Member member = validateUserService.validateRegister(
					email, SocialCode.NAVER
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
		} catch (HttpClientErrorException e) {
			throw new RuntimeException("Failed to fetch user info from Kakao", e);
		}
		return null;
	}
}
