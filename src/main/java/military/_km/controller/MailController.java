package military._km.controller;

import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import military._km.domain.EmailRequest;
import military._km.domain.EmailResponse;
import military._km.service.MailSendService;
import military._km.service.MailVerifyService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/email")
public class MailController {

    private final MailSendService sendService;
    private final MailVerifyService verifyService;

    @PostMapping("/send")
    public ResponseEntity<EmailResponse> send(@Valid @RequestBody EmailRequest request) throws MessagingException, NoSuchAlgorithmException {
        EmailResponse emailResponse = sendService.sendForCertification(request.getEmail());
        log.info("send api가 호출되었습니다 ={}", request.getEmail());
        return new ResponseEntity<>(new EmailResponse(emailResponse.getEmail(), emailResponse.getCertificationNumber()),HttpStatus.OK);
    }

    @GetMapping("/verify")
    public ResponseEntity<HttpStatus> verify(@RequestParam(name = "email") String email, @RequestParam(name = "certificationNumber") String certificationNumber) {
        boolean result = verifyService.verifyEmail(email, certificationNumber);
        if(result){
            return new ResponseEntity<>(HttpStatus.OK);
        } else{
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
}
