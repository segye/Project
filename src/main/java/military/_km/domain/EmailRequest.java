package military._km.domain;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class EmailRequest {

    @NotBlank(message = "이메일 입력은 필수입니다.")
    @Email(message = "이메일을 작성해주세요.")
    private String email;
}
