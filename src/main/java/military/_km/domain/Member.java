package military._km.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.*;
import lombok.*;
import military._km.converter.MilitaryConverter;
import military._km.domain.social.SocialCode;

@Entity
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@AllArgsConstructor
public class Member extends BaseTimeEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "member_id")
	private Long id;

	@Column(nullable = false, name = "member_email")
	private String email;

    /**
     * oAuth2 로그인 경우 비밀번호 필드는 null
     */
	@JsonIgnore
	@Column(name = "member_password")
	private String password;

	@Column(nullable = false, name = "member_nickname")
	private String nickname;

	@Convert(converter = MilitaryConverter.class)
	@Column(name = "member_military")
	private Military military;

	@Enumerated(EnumType.STRING)
	@Column(name = "member_role")
	private Role role;

	@Column(name = "member_startdate")
	private String startdate;

	@Column(name = "member_finishdate")
	private String finishdate;

	/**
	 * 소셜 로그인 사용자의 경우 이 필드에는 제공자 ID(예: "google", "naver", "kakao")가 저장
	 * 이메일 인증 사용자의 경우 이 필드에는 제공자 ID("email")가 저장
	 */
	@Column(name = "socialCode")
	private SocialCode socialCode;

}
