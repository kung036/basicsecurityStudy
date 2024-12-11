package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity // 웹보안 활성화 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책 - 유저 권한 허락(접근 권한)
        http.authorizeRequests()
                .anyRequest()
                .authenticated();
        // 인증 정책 - 유저 검증(로그인)
        http.formLogin();
    }
}
