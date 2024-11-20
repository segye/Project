package military._km.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

@Getter @Setter
@RedisHash
@Table(name="refresh_token")
public class RefreshToken {

    @Id
    @Column(name = "refresh_email")
    private String email;

    @Indexed
    @Column(name = "refresh_token")
    private String token;

    @Column(name = "refresh_expire")
    private String time;

}
