package com.lacy.user_service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final ClientRegistrationRepository clientRegistrationRepository;


    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Bean
    public OAuth2AuthorizedClientRepository repository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/public").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("http://localhost:4000?access_token=" + repository().loadAuthorizedClient("auth0", authentication, request).getAccessToken().getTokenValue());
                            }
                        })
                )
                .logout(logout -> {
                            LogoutHandler logoutHandler = new CookieClearingLogoutHandler("*");
                            SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();
                            CompositeLogoutHandler compositeLogoutHandler = new CompositeLogoutHandler(logoutHandler, securityContextLogoutHandler);

                            LogoutSuccessHandler logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
                            logout
                                    .addLogoutHandler(compositeLogoutHandler)
                                    .logoutSuccessHandler(logoutSuccessHandler);
                        }
                )
                .oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> httpSecurityOAuth2ResourceServerConfigurer.jwt(Customizer.withDefaults()))
        ;
        return http.build();
    }
}