package military._km.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MemberSignupDto {
	@NotEmpty
	@Pattern(regexp = "^[a-zA-Z0-9+-\\_.]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$",
		message = "이메일 형식을 맞춰야합니다.")
	private String email;


	@Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[~!@#$%^&*()+|=])[A-Za-z\\d~!@#$%^&*()+|=]{8,16}$",
		message = "비밀번호는 영문+숫자+특수문자를 포함한 8~16자여야 합니다.")
	private String password;

	@NotEmpty
	@Pattern(regexp = "^[a-zA-Z가-힣\\\\s]{2,15}",
		message = "이름은 영문자, 한글, 공백포함 2글자부터 15글자까지 가능합니다.")
	private String nickname;

	@NotEmpty
	private String military;

	@NotEmpty
	private String startdate;

	@NotEmpty
	private String finishdate;

    //@NotEmpty
    //private String socialCode;

}
