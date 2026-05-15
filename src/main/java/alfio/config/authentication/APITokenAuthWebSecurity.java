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

import alfio.config.authentication.support.*;
import alfio.model.system.ConfigurationKeys;
import alfio.model.user.User;
import alfio.repository.system.ConfigurationRepository;
import alfio.repository.user.AuthorityRepository;
import alfio.repository.user.UserRepository;
import alfio.util.ClockProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.security.MessageDigest;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.stream.Collectors;

import static alfio.config.authentication.support.AuthenticationConstants.*;

@Configuration(proxyBeanMethods = false)
@Order(0)
public class APITokenAuthWebSecurity {

    public static final String API_KEY = "Api key ";
    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;
    private final ConfigurationRepository configurationRepository;

    public APITokenAuthWebSecurity(UserRepository userRepository,
                                   AuthorityRepository authorityRepository,
                                   ConfigurationRepository configurationRepository) {
        this.userRepository = userRepository;
        this.authorityRepository = authorityRepository;
        this.configurationRepository = configurationRepository;
    }

    @Bean
    @Order(0)
    public SecurityFilterChain apiTokenFilterChain(HttpSecurity http) throws Exception {

        APIKeyAuthFilter filter = new APIKeyAuthFilter();
        filter.setAuthenticationManager(authentication -> {
            String apiKey = (String) authentication.getPrincipal();

            var systemApiKeyOptional = configurationRepository.findOptionalByKey(ConfigurationKeys.SYSTEM_API_KEY.name());

            if (systemApiKeyOptional.isPresent() && apiKeyMatches(apiKey, systemApiKeyOptional.get())) {
                return new APITokenAuthentication(
                    authentication.getPrincipal(),
                    authentication.getCredentials(),
                    List.of(new SimpleGrantedAuthority("ROLE_" + SYSTEM_API_CLIENT)));
            }

            User user = userRepository.findByUsername(apiKey).orElseThrow(() -> new BadCredentialsException(API_KEY + apiKey + " don't exists"));
            if (!user.isEnabled()) {
                throw new DisabledException(API_KEY + apiKey + " is disabled");
            }
            if (User.Type.API_KEY != user.getType()) {
                throw new WrongAccountTypeException("Wrong account type for username " + apiKey);
            }
            if (!user.isCurrentlyValid(ZonedDateTime.now(ClockProvider.clock()))) {
                throw new DisabledException(API_KEY + apiKey + " is expired");
            }

            return new APITokenAuthentication(
                authentication.getPrincipal(),
                authentication.getCredentials(),
                authorityRepository.findRoles(apiKey).stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        });


        http.securityMatcher(RequestTypeMatchers::isTokenAuthentication)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(ant(ADMIN_PUBLIC_API + "/system/**")).hasRole(SYSTEM_API_CLIENT)
                .requestMatchers(ant(ADMIN_PUBLIC_API + "/**")).hasRole(API_CLIENT)
                .requestMatchers(ant(ADMIN_API + "/check-in/event/*/attendees")).hasRole(SUPERVISOR)
                .requestMatchers(ant(ADMIN_API + "/check-in/*/label-layout")).hasAnyRole(OPERATOR, SUPERVISOR, SPONSOR)
                .requestMatchers(ant(ADMIN_API + "/check-in/**")).hasAnyRole(OPERATOR, SUPERVISOR)
                .requestMatchers(ant(HttpMethod.GET, ADMIN_API + "/events")).hasAnyRole(OPERATOR, SUPERVISOR, SPONSOR)
                .requestMatchers(ant(HttpMethod.GET, ADMIN_API + "/user-type", ADMIN_API + "/user/details")).hasAnyRole(OPERATOR, SUPERVISOR, SPONSOR)
                .requestMatchers(ant(ADMIN_API + "/**")).denyAll()
                .requestMatchers(ant(HttpMethod.POST, "/api/attendees/sponsor-scan")).hasRole(SPONSOR)
                .requestMatchers(ant(HttpMethod.GET, "/api/attendees/*/ticket/*")).hasAnyRole(OPERATOR, SUPERVISOR, API_CLIENT)
                .requestMatchers(ant("/**")).authenticated()
            )
            .addFilter(filter);

        return http.build();
    }

    private static RequestMatcher[] ant(String... patterns) {
        return Arrays.stream(patterns).map(AntPathRequestMatcher::new).toArray(RequestMatcher[]::new);
    }

    private static RequestMatcher[] ant(HttpMethod method, String... patterns) {
        return Arrays.stream(patterns).map(p -> new AntPathRequestMatcher(p, method.name())).toArray(RequestMatcher[]::new);
    }

    private static boolean apiKeyMatches(String input, alfio.model.system.Configuration systemApiKeyConfiguration) {
        return MessageDigest.isEqual(input.getBytes(StandardCharsets.UTF_8),
            systemApiKeyConfiguration.getValue().getBytes(StandardCharsets.UTF_8));
    }
}
