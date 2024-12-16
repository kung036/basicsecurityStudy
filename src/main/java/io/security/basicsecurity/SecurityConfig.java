package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity // 웹보안 활성화 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책 - 유저 권한 허락(접근 권한)
        http.authorizeRequests()
            .anyRequest()
            .authenticated(); // 인증을 받지 않으면 url 접근이 안됨

        // 인증 정책 - 유저 검증(로그인)
        http.formLogin()
//                .loginPage("/loginPage")                        // 사용자 정의 로그인 페이지(항상 접근 가능해야함)
            .defaultSuccessUrl("/")                         // 로그인 성공 후 이동 페이지
            .failureUrl("/login")       // 로그인 실패 후 이동 페이지
            .usernameParameter("username")                  // 아이디 파라미터명 설정
            .passwordParameter("password")                  // 패스워드 파라미터명 설정
            .loginProcessingUrl("/login_proc")                   // 로그인 Form Action Url
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

        // 로그아웃
        http.logout()                                   // 로그아웃 처리
            .logoutUrl("/logout")                   // 로그아웃 처리 URL
            .logoutSuccessUrl("/login")             // 로그아웃 성공 후 이동페이지
            .deleteCookies("JSESSIONID", "remember-me")    // 로그아웃 후 쿠키 삭제(서버에서 자동으로 생성한 쿠키 삭제)
            .addLogoutHandler(new LogoutHandler() { // 로그아웃 핸들러
                @Override
                public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                    HttpSession session = request.getSession(false);
                    session.invalidate();
                }
            })
            .logoutSuccessHandler(new LogoutSuccessHandler() { // 로그아웃 성공 후 핸들러
                @Override
                public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                    response.sendRedirect("/login");
                }
            });

        // remember me
        http.rememberMe() // remember me 기능 활성화
            .rememberMeParameter("remember")    // 기본 파라미터명은 remember-me
            .tokenValiditySeconds(3600)          // 쿠키 만료 시간 : Default는 14일(3600초)
//            .alwaysRemember(true)                   // true : remember me 기능이 활성화되지 않아도 항상 실행(default : false)
            .userDetailsService(userDetailsService); // 사용자 계정 조회하는 클래스 설정

        // 동시성 제어
        http.sessionManagement()
            .maximumSessions(1)             // 최대 허용 가능 세션 수 , -1 : 무제한 로그인 세션 허용
            .maxSessionsPreventsLogin(false); // 동시 로그인 차단함(현재 사용자 인증 실패 전략),  false : 기존 세션 만료(default, 이전 사용자 세션 만료)
    }
}
