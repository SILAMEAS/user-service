package com.lacy.user_service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProfileController {

    private static final Logger log = LoggerFactory.getLogger(ProfileController.class);

    @GetMapping("/profile")
    public String profile(@AuthenticationPrincipal OAuth2User user) {
        log.debug("user={}", user);
        return "Hello, " + user.getAttribute("name") + "!<br>Email: " + user.getAttribute("email");
    }
}