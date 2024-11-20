package military._km.domain.social;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

@Data
public class NaverUserResponse {
	@JsonProperty("response")
	private NaverUserInfo response;
}
