package org.emaginalabs.samples.demopreauth.rest;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * Rest service return principal user logged
 */
@RestController
@RequestMapping("/api")
public class UserInfoController {

    @GetMapping("user")
    public Authentication ping(Authentication authentication) {
        return authentication;
    }
}
