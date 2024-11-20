package military._km.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import military._km.Generator.CertificationGenerator;
import military._km.dao.CertificationNumberDao;
import military._km.domain.EmailResponse;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMailMessage;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;

@Service
@RequiredArgsConstructor
public class MailSendService {

    private final JavaMailSender mailSender;
    private final CertificationNumberDao numberDao;
    private final CertificationGenerator generator;


    public EmailResponse sendForCertification(String email) throws NoSuchAlgorithmException, MessagingException {
        String certificationNumber = generator.createCertificationNumber();
        String content = "인증번호 " + certificationNumber + " 를 3분 안에 화면에 입력해주세요.";
        numberDao.saveCertificationNumber(email, certificationNumber); // redis에 저장
        send(email, content);
        return new EmailResponse(email, certificationNumber);
    }

    private void send(String email, String content) throws MessagingException {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper messageHelper =  new MimeMessageHelper(mimeMessage);
        messageHelper.setTo(email); // 보낼 메일 설정
        messageHelper.setSubject("인증메일입니다."); // 제목 설정
        messageHelper.setText(content); // 내용 설정
        mailSender.send(mimeMessage);
    }
}
