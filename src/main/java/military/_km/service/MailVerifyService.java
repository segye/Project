package military._km.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import military._km.dao.CertificationNumberDao;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class MailVerifyService {
    private final CertificationNumberDao numberDao;

    public boolean verifyEmail(String email, String certificationNumber) {
        if (!isVerify(email, certificationNumber)) {
            log.info("인증번호가 같지 않습니다. ={}", certificationNumber);
            return false;
        }
        log.info("인증에 성공했습니다.");
        numberDao.removeCertificationNumber(email); // 확인 후 redis에서 삭제
        return true;
    }

    private boolean isVerify(String email, String certificationNumber) {
        boolean verified = isEmailExist(email);
        if (!isEmailExist(email)) {
            log.info("email이 존재하지않습니다. ={}", email);
        }
        return (verified && numberDao.getCertificationNumber(email).equals(certificationNumber));
    }

    private boolean isEmailExist(String email) {
        return numberDao.isCertificationNumber(email);
    }
}
