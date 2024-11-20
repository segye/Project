package military._km.dao;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;

@Repository
@RequiredArgsConstructor
public class CertificationNumberDao {

    private final RedisTemplate<String, String> redisTemplate;

    public void saveCertificationNumber(String email, String certificationNumber) {
        redisTemplate.opsForValue().set(email, certificationNumber, Duration.ofSeconds(180)); //  3분
    }

    public String getCertificationNumber(String email) {
       return redisTemplate.opsForValue().get(email);
    }

    public void removeCertificationNumber(String email) {
        redisTemplate.delete(email);
    }

    public boolean isCertificationNumber(String email) {
        Boolean result = redisTemplate.hasKey(email);
        return result != null && result;
    }

}
