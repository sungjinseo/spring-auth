package dev.greatseo.auth.config;

import dev.greatseo.auth.jwt.JwtAuthenticationFilter;
import dev.greatseo.auth.jwt.JwtTokenProvider;
import dev.greatseo.auth.oauth2.OAuth2AuthenticationFailureHandler;
import dev.greatseo.auth.oauth2.OAuth2AuthenticationSuccessHandler;
import dev.greatseo.auth.repository.CookieAuthorizationRequestRepository;
import dev.greatseo.auth.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfigure {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final JwtTokenProvider jwtTokenProvider;
    private final CookieAuthorizationRequestRepository cookieAuthorizationRequestRepository;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // AbstractHttpConfigurer는 애플리케이션의 보안 설정을 구성하는 데 사용
    // SecurityFilterChain은 이러한 보안 설정을 들어오는 요청에 적용하는 데 사용
    // 요약하면 AbstractHttpConfigurer는 보안 설정을 정의하는 HttpSecurity를 구성하는 데 사용됩니다.
    // SecurityFilterChain은 들어오는 요청을 필터링하고 HttpSecurity에 정의된 보안 설정을 적용하는 데 사용됩니다.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //httpBasic, csrf, formLogin, rememberMe, logout, session disable
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .rememberMe(AbstractHttpConfigurer::disable)
                //.requestCache(RequestCacheConfigurer::disable)
                //.addFilterBefore(authenticationJwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        //요청에 대한 권한 설정
        http.authorizeHttpRequests(
                request ->
                        request
                                // 페이지 접근제어를 설정하는 방법은 3가지로 세팅할 수 있음
                                .requestMatchers(HttpMethod.GET, "/", "/static/**", "/index.html", "/api/users/me").permitAll()
                                .requestMatchers(
                                        new AntPathRequestMatcher("/oauth2/**"),
                                        new AntPathRequestMatcher("/swagger-ui/**"),
                                        new AntPathRequestMatcher("/v3/api-docs/**")
                                ).permitAll()
                                //.requestMatchers(AUTH_WHITELIST).permitAll()
                                .anyRequest().authenticated()
        );

        http.oauth2Login(oAuth2LoginConfigurer ->
                oAuth2LoginConfigurer
                        .authorizationEndpoint(authorizationEndpointConfig ->
                                authorizationEndpointConfig
                                        .baseUri("/oauth2/authorize") // (1) 소셜 로그인 url
                                        .authorizationRequestRepository(cookieAuthorizationRequestRepository))
                        .redirectionEndpoint(redirectionEndpointConfig ->
                                redirectionEndpointConfig
                                        .baseUri("/oauth2/callback/*")) // (2)
                        .userInfoEndpoint(userInfoEndpointConfig ->
                                userInfoEndpointConfig
                                        .userService(customOAuth2UserService) // (3)
                        )
                        .successHandler(oAuth2AuthenticationSuccessHandler) // (4-1)
                        .failureHandler(oAuth2AuthenticationFailureHandler) // (4-2)
        );

        http.exceptionHandling(exceptionHandling ->
                exceptionHandling
                        .authenticationEntryPoint(
                                (httpServletRequest, httpServletResponse, e) -> httpServletResponse.sendError(401)
                        )
                        .accessDeniedHandler(
                                (httpServletRequest, httpServletResponse, e) -> httpServletResponse.sendError(403)
                        ));


        http.logout((logoutConfig) ->
                        logoutConfig.clearAuthentication(true)
                                //.deleteCookies("JE")
                                .logoutSuccessUrl("/"));

                //jwt filter 설정
        http.addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
