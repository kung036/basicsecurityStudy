package io.security.basicsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {
    @GetMapping
    public String index() {
        return "home";
    }

    // 사용자 정의 로그인 페이지
    @GetMapping("loginPage")
    public String loginPage() {
        return "loginPage";
    }
}
