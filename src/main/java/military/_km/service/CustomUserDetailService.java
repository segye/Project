package military._km.service;

import lombok.RequiredArgsConstructor;
import military._km.domain.Member;
import military._km.repository.MemberRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

	private final MemberRepository memberRepository;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		return memberRepository.findByEmail(email)
			.map(this::create)
			.orElseThrow(() -> new UsernameNotFoundException(email + "해당 유저를 찾을 수 없습니다."));
	}

	private UserDetails create(Member member) {
		GrantedAuthority authority = new SimpleGrantedAuthority(member.getRole().toString());
		return new User(
			member.getEmail(),
			member.getPassword(),
			Collections.singleton(authority)
		);
	}
}