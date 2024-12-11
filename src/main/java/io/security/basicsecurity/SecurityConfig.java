package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity // 웹보안 활성화 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책 - 유저 권한 허락(접근 권한)
        http.authorizeRequests()
                .anyRequest()
                .authenticated(); // 인증을 받지 않으면 url 접근이 안됨
        // 인증 정책 - 유저 검증(로그인)
        http.formLogin()
                .loginPage("/loginPage")                        // 사용자 정의 로그인 페이지(항상 접근 가능해야함)
                .defaultSuccessUrl("/")                         // 로그인 성공 후 이동 페이지
                .failureUrl("/login")       // 로그인 실패 후 이동 페이지
                .usernameParameter("username")                  // 아이디 파라미터명 설정
                .passwordParameter("password")                  // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login")                   // 로그인 Form Action Url
                .successHandler(new AuthenticationSuccessHandler() { // 로그인 성공 후 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { // 로그인 실패 후 핸들러
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll(); // formLogin()의 로그인 페이지 접근 허용
    }
}
