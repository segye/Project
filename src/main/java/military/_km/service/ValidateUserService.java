package military._km.service;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import military._km.domain.Member;
import military._km.domain.social.SocialCode;
import military._km.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class ValidateUserService {

	private final MemberRepository memberRepository;

	public Member validateRegister(String email, SocialCode socialCode) {
		return memberRepository.findByEmail(email).stream()
			.filter(member -> member.getSocialCode().equals(socialCode))
			.findFirst()
			.orElse(null);
	}
}
