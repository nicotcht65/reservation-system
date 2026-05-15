/**
 * This file is part of alf.io.
 *
 * alf.io is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * alf.io is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with alf.io.  If not, see <http://www.gnu.org/licenses/>.
 */
package alfio.config.authentication;

import alfio.config.Initializer;
import alfio.config.authentication.support.*;
import alfio.manager.RecaptchaService;
import alfio.manager.openid.OpenIdAuthenticationManager;
import alfio.manager.openid.PublicOpenIdAuthenticationManager;
import alfio.manager.system.ConfigurationManager;
import alfio.manager.user.UserManager;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import static alfio.config.authentication.support.AuthenticationConstants.*;
import static alfio.config.authentication.support.OpenIdAuthenticationFilter.*;

@AllArgsConstructor(access = AccessLevel.PROTECTED)
abstract class AbstractFormBasedWebSecurity {
    public static final String AUTHENTICATE = "/authenticate";
    private final Environment environment;
    private final UserManager userManager;
    private final RecaptchaService recaptchaService;
    private final ConfigurationManager configurationManager;
    private final CsrfTokenRepository csrfTokenRepository;
    private final DataSource dataSource;
    private final PasswordEncoder passwordEncoder;
    private final PublicOpenIdAuthenticationManager publicOpenIdAuthenticationManager;
    private final SpringSessionBackedSessionRegistry<?> sessionRegistry;

    protected AuthenticationManager buildAuthenticationManager() {
        JdbcDaoImpl jdbcDao = new JdbcDaoImpl();
        jdbcDao.setDataSource(dataSource);
        jdbcDao.setUsersByUsernameQuery("select username, password, enabled from ba_user where username = ?");
        jdbcDao.setAuthoritiesByUsernameQuery("select username, role from authority where username = ?");

        DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
        daoProvider.setUserDetailsService(jdbcDao);
        daoProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(List.of(daoProvider, new OpenIdAuthenticationProvider()));
    }

    private static RequestMatcher[] ant(String... patterns) {
        return Arrays.stream(patterns).map(AntPathRequestMatcher::new).toArray(RequestMatcher[]::new);
    }

    private static RequestMatcher[] ant(HttpMethod method, String... patterns) {
        return Arrays.stream(patterns).map(p -> new AntPathRequestMatcher(p, method.name())).toArray(RequestMatcher[]::new);
    }

    protected SecurityFilterChain configureHttpSecurity(HttpSecurity http) throws Exception {

        AuthenticationManager authManager = buildAuthenticationManager();
        http.authenticationManager(authManager);

        if (environment.acceptsProfiles(Profiles.of("!" + Initializer.PROFILE_DEV))) {
            http.requiresChannel(channel -> channel
                .requestMatchers(ant("/healthz")).requiresInsecure()
                .requestMatchers(ant("/**")).requiresSecure()
            );
        }

        CsrfConfigurer<HttpSecurity> configurer =
            http.exceptionHandling(exception -> exception
                    .accessDeniedHandler((request, response, accessDeniedException) -> {
                        if (!response.isCommitted()) {
                            if ("XMLHttpRequest".equals(request.getHeader(AuthenticationConstants.X_REQUESTED_WITH))) {
                                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            } else if (!response.isCommitted()) {
                                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                                RequestDispatcher dispatcher = request.getRequestDispatcher("/session-expired");
                                dispatcher.forward(request, response);
                            }
                        }
                    })
                    .defaultAuthenticationEntryPointFor((request, response, ex) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED), new RequestHeaderRequestMatcher(AuthenticationConstants.X_REQUESTED_WITH, "XMLHttpRequest"))
                )
                .headers(headers -> headers.cacheControl(cache -> cache.disable()).frameOptions(frame -> frame.disable()))
                .csrf();

        Pattern pattern = Pattern.compile("^(GET|HEAD|TRACE|OPTIONS)$");
        Predicate<HttpServletRequest> csrfWhitelistPredicate = r -> r.getRequestURI().startsWith("/api/webhook/")
            || r.getRequestURI().startsWith("/api/payment/webhook/")
            || pattern.matcher(r.getMethod()).matches();
        csrfWhitelistPredicate = csrfWhitelistPredicate.or(r -> r.getRequestURI().equals("/report-csp-violation"));
        configurer.requireCsrfProtectionMatcher(new NegatedRequestMatcher(csrfWhitelistPredicate::test));

        String[] ownershipRequired = new String[]{
            ADMIN_API + "/overridable-template",
            ADMIN_API + "/additional-services",
            ADMIN_API + "/events/*/additional-field",
            ADMIN_API + "/event/*/additional-services/",
            ADMIN_API + "/overridable-template/",
            ADMIN_API + "/events/*/promo-code",
            ADMIN_API + "/reservation/event/*/reservations/list",
            ADMIN_API + "/event/*/email/",
            ADMIN_API + "/event/*/waiting-queue/load",
            ADMIN_API + "/events/*/pending-payments",
            ADMIN_API + "/events/*/export",
            ADMIN_API + "/events/*/sponsor-scan/export",
            ADMIN_API + "/events/*/invoices/**",
            ADMIN_API + "/reservation/*/*/*/audit",
            ADMIN_API + "/subscription/*/email/",
            ADMIN_API + "/organization/*/subscription/**",
            ADMIN_API + "/reservation/subscription/**"
        };

        configurer.csrfTokenRepository(csrfTokenRepository)
            .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler());

        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(ant(ADMIN_PUBLIC_API + "/**")).denyAll()
                .requestMatchers(ant(HttpMethod.GET, ADMIN_API + "/users/current")).hasAnyRole(ADMIN, OWNER, SUPERVISOR)
                .requestMatchers(ant(HttpMethod.POST, ADMIN_API + "/users/check", ADMIN_API + "/users/current/edit", ADMIN_API + "/users/current/update-password")).hasAnyRole(ADMIN, OWNER, SUPERVISOR)
                .requestMatchers(ant(ADMIN_API + "/configuration/**", ADMIN_API + "/users/**")).hasAnyRole(ADMIN, OWNER)
                .requestMatchers(ant(ADMIN_API + "/organizations/new", ADMIN_API + "/system/**")).hasRole(ADMIN)
                .requestMatchers(ant(ADMIN_API + "/check-in/**")).hasAnyRole(ADMIN, OWNER, SUPERVISOR)
                .requestMatchers(ant(HttpMethod.GET, ownershipRequired)).hasAnyRole(ADMIN, OWNER)
                .requestMatchers(ant(HttpMethod.GET, ADMIN_API + "/**")).hasAnyRole(ADMIN, OWNER, SUPERVISOR)
                .requestMatchers(ant(HttpMethod.POST, ADMIN_API + "/reservation/event/*/new", ADMIN_API + "/reservation/event/*/*")).hasAnyRole(ADMIN, OWNER, SUPERVISOR)
                .requestMatchers(ant(HttpMethod.PUT,
                    ADMIN_API + "/reservation/event/*/*/notify",
                    ADMIN_API + "/reservation/event/*/*/notify-attendees",
                    ADMIN_API + "/reservation/event/*/*/confirm"
                    )).hasAnyRole(ADMIN, OWNER, SUPERVISOR)
                .requestMatchers(ant(ADMIN_API + "/**")).hasAnyRole(ADMIN, OWNER)
                .requestMatchers(ant("/admin/**/export/**")).hasAnyRole(ADMIN, OWNER)
                .requestMatchers(ant("/admin/**")).hasAnyRole(ADMIN, OWNER, SUPERVISOR)
                .requestMatchers(ant("/api/attendees/**")).denyAll()
                .requestMatchers(ant("/callback")).permitAll()
                .requestMatchers(ant("/**")).permitAll()
            )
            .formLogin(form -> form
                .loginPage("/authentication")
                .loginProcessingUrl(AUTHENTICATE)
                .failureUrl("/authentication?failed")
            )
            .logout(logout -> logout.permitAll())
            .sessionManagement(session -> session.maximumSessions(-1).sessionRegistry(sessionRegistry));

        http.addFilterBefore(openIdPublicCallbackLoginFilter(publicOpenIdAuthenticationManager, authManager), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(openIdPublicAuthenticationFilter(publicOpenIdAuthenticationManager), AnonymousAuthenticationFilter.class);


        //
        http.addFilterBefore(new RecaptchaLoginFilter(recaptchaService, AUTHENTICATE, "/authentication?recaptchaFailed", configurationManager), UsernamePasswordAuthenticationFilter.class);

        // call implementation-specific logic
        addAdditionalFilters(http, authManager);

        //FIXME create session and set csrf cookie if we are getting a v2 public api, an admin api call , will switch to pure cookie based
        http.addFilterBefore((servletRequest, servletResponse, filterChain) -> {

            HttpServletRequest req = (HttpServletRequest) servletRequest;
            HttpServletResponse res = (HttpServletResponse) servletResponse;
            var reqUri = req.getRequestURI();

            if ((reqUri.startsWith("/api/v2/public/") || reqUri.startsWith("/admin/api/") || reqUri.startsWith("/api/v2/admin/")) && "GET".equalsIgnoreCase(req.getMethod())) {
                CsrfToken csrf = csrfTokenRepository.loadToken(req);
                if (csrf == null) {
                    csrf = csrfTokenRepository.generateToken(req);
                }
                Cookie cookie = new Cookie("XSRF-TOKEN", csrf.getToken());
                cookie.setPath("/");
                res.addCookie(cookie);
            }
            filterChain.doFilter(servletRequest, servletResponse);
        }, RecaptchaLoginFilter.class);

        if (environment.acceptsProfiles(Profiles.of(Initializer.PROFILE_DEMO))) {
            http.addFilterAfter(new UserCreatorBeforeLoginFilter(userManager, AUTHENTICATE), RecaptchaLoginFilter.class);
        }

        return http.build();
    }

    protected void addAdditionalFilters(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
    }

    private OpenIdAuthenticationFilter openIdPublicAuthenticationFilter(OpenIdAuthenticationManager openIdAuthenticationManager) {
        return new OpenIdAuthenticationFilter("/openid/authentication", openIdAuthenticationManager, "/", true);
    }

    private OpenIdCallbackLoginFilter openIdPublicCallbackLoginFilter(OpenIdAuthenticationManager openIdAuthenticationManager, AuthenticationManager authenticationManager) throws Exception {
        var filter = new OpenIdCallbackLoginFilter(openIdAuthenticationManager,
            new AntPathRequestMatcher("/openid/callback", "GET"),
            authenticationManager);
        filter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            var session = request.getSession();
            var reservationId = (String) session.getAttribute(RESERVATION_KEY);
            if(StringUtils.isNotBlank(reservationId)) {
                var contextTypeKey = session.getAttribute(CONTEXT_TYPE_KEY);
                var contextIdKey = session.getAttribute(CONTEXT_ID_KEY);
                session.removeAttribute(CONTEXT_TYPE_KEY);
                session.removeAttribute(CONTEXT_ID_KEY);
                session.removeAttribute(RESERVATION_KEY);
                response.sendRedirect("/"+contextTypeKey+"/"+ contextIdKey +"/reservation/"+reservationId+"/book");
            } else {
                response.sendRedirect("/");
            }
        });
        return filter;
    }
}
