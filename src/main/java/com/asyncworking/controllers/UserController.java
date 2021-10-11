package com.asyncworking.controllers;

import com.asyncworking.dtos.*;
import com.asyncworking.services.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.net.URISyntaxException;

@Slf4j
@RestController
@RequiredArgsConstructor
@Validated
public class UserController {

    private final UserService userService;

    @GetMapping("/login")
    public ResponseEntity verifyStatus(@RequestParam(value = "email") String email) {
        log.info("email: {}", email);
        if (userService.ifUnverified(email)) {
            return new ResponseEntity<>("Unverified user", HttpStatus.NON_AUTHORITATIVE_INFORMATION);
        }
        return ResponseEntity.ok("success");
    }

    @GetMapping("/signup")
    public ResponseEntity<String> verifyEmailExists(@RequestParam(value = "email") String email) {
        if (userService.ifEmailExists(email)) {
            return new ResponseEntity<>("Email has taken", HttpStatus.CONFLICT);
        }
        return new ResponseEntity<>("Email does not exist", HttpStatus.OK);
    }

    @PostMapping("/signup")
    public ResponseEntity createUser(@Valid @RequestBody AccountDto accountDto) {
        log.info("email: {}, name: {}", accountDto.getEmail(), accountDto.getName());
        userService.createUserAndGenerateVerifyLink(accountDto);
        return ResponseEntity.ok("success");
    }

    @GetMapping("/invitations/companies")
    public ResponseEntity getInvitationLink(@RequestParam(value = "companyId") Long companyId,
                                                @RequestParam(value = "email") String email,
                                                @RequestParam(value = "name") String name,
                                                @RequestParam(value = "title") String title){
        return ResponseEntity.ok(userService.generateInvitationLink(companyId, email, name, title));
    }

    @PostMapping("/resend")
    public ResponseEntity resendActivationLink(@Valid @RequestBody UserInfoDto userInfoDto) {
        userService.generateVerifyLink(userInfoDto.getEmail());
        return ResponseEntity.ok("success");
    }

    @PostMapping("/verify")
    public ResponseEntity verifyActiveUser(@RequestParam(value = "code") String code) throws URISyntaxException {
        log.info(code);
        boolean isVerified = userService.isAccountActivated(code);
        if (isVerified) {
            return ResponseEntity.ok("success");
        }
        return new ResponseEntity<>("Inactivated", HttpStatus.NON_AUTHORITATIVE_INFORMATION);
    }
}
