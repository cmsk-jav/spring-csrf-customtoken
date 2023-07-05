package dev.sk.csrf;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.*;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Optional;

@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class SpringCsrfCustomTokenRepositoryApplication {

    @Component
    static class CSRFLogger implements Filter {
        @Override
        public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

            Object csrf = servletRequest.getAttribute("_csrf");
//            CsrfToken csrfToken = (CsrfToken) csrf;
            if (csrf!=null)
                System.out.println("CSRF Token = "+csrf);
            filterChain.doFilter(servletRequest,servletResponse);
        }
    }

    @Component
    class CustomCSRFTokenRepository implements CsrfTokenRepository{
        @Autowired
        JPATokenRepository jpaTokenrepository;

        @Override
        public CsrfToken generateToken(HttpServletRequest request) {
            String token = KeyGenerators.string().generateKey();
            return new DefaultCsrfToken("X-CSRF-TOKEN","_csrf",token);
        }

        @Override
        public void saveToken(CsrfToken csrfToken, HttpServletRequest request, HttpServletResponse response) {
            String identifier = request.getHeader("x_id");
            Optional<Token> existingToken =
                    jpaTokenrepository.findTokenByIdentifier(identifier);
            if (existingToken.isPresent()) {
                Token token = existingToken.get();
                token.setToken(csrfToken.getToken());
                injectCsrfToken(request,token.getToken());
            } else {
                Token token = new Token();
                token.setToken(csrfToken.getToken());
                token.setIdentifier(identifier);
                jpaTokenrepository.save(token);
                injectCsrfToken(request,token.getToken());
            }
        }

        @Override
        public CsrfToken loadToken(HttpServletRequest request) {
            String identifier = request.getHeader("x_id");
            Optional<Token> existingToken =
                    jpaTokenrepository
                            .findTokenByIdentifier(identifier);
            if (existingToken.isPresent()) {
                Token token = existingToken.get();
                injectCsrfToken(request,token.getToken());
                return new DefaultCsrfToken(
                        "X-CSRF-TOKEN",
                        "_csrf",
                        token.getToken());
            }
            System.out.println("Token Not Represent");
            return null;
        }
        public void injectCsrfToken(HttpServletRequest httpServletRequest, String csrfToken){
            httpServletRequest.setAttribute("_csrf",csrfToken);
        }

    }

    @RestController
    static class MyController{
        @RequestMapping("/")
        public String main(){
            return "Hello CSRF Filter...";
        }
    }

    @Controller
    static class ViewController{
        @RequestMapping("/page")
        public String page(HttpServletRequest request, Model model){
            System.out.println("Requesting Page...");
            System.out.println(request.getAttribute("_csrf"));
            CsrfToken csrfToken = (CsrfToken)request.getAttribute("_csrf");
            System.out.println("Token::"+csrfToken.getToken());
            model.addAttribute("_csrf",request.getAttribute("_csrf"));
            return "Main";
        }
        @PostMapping("/verify")
        @ResponseBody
        public String verifyPostDataForCSRF(){
            return "<h1 style=\"color:green\">Valid User :)</h1>";
        }
    }
    @Configuration
    static class Config{
        @Autowired
        CSRFLogger csrfLogger;

        @Autowired
        CustomCSRFTokenRepository customCSRFTokenRepository;
        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity security)throws Exception{
            security.csrf(csrf->{
                csrf.csrfTokenRepository(customCSRFTokenRepository);
            });
            security.addFilterAfter(csrfLogger, CsrfFilter.class);
            security.authorizeRequests(e->e.anyRequest().permitAll());
            return security.build();
        }
    }
    public static void main(String[] args) {
        SpringApplication.run(SpringCsrfCustomTokenRepositoryApplication.class, args);
    }

}
