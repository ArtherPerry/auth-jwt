package com.example.authjwt.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {

    private final JavaMailSender javaMailSender;

    private final String defaultFrontEndUrl;

    public MailService(JavaMailSender javaMailSender,@Value("${application.frontend.default-url}") String defaultFrontEndUrl) {
        this.javaMailSender = javaMailSender;
        this.defaultFrontEndUrl = defaultFrontEndUrl;
    }

    public void  sendForgotMessage(String email,String token,String baseUrl){
        var url = baseUrl != null ? baseUrl:defaultFrontEndUrl;
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setFrom("jhon.engineer@gmail.com");
        mailMessage.setTo(email);
        mailMessage.setSubject("Reset Your Password");
        mailMessage.setText(String.format("Click <a> href= \"%s/reset/%s\" here </a> to reset your Password",url,token));
        javaMailSender.send(mailMessage);

    }
}
