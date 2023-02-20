package io.betweendata.RestApi.config;

import io.betweendata.RestApi.security.oauth2.KeycloakJwtRolesConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration {

  /**
   * Defines which authorization is needed to access a route. (As an alternative annotations could be used on the
   * methods of the {@link io.betweendata.RestApi.endpoint.ApiController} directly. see
   * <a href="https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html">Method Security</a>.
   */
  @Bean
  SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

    DelegatingJwtGrantedAuthoritiesConverter authoritiesConverter =
            // Using the delegating converter multiple converters can be combined
            new DelegatingJwtGrantedAuthoritiesConverter(
                    // First add the default converter
                    new JwtGrantedAuthoritiesConverter(),
                    // Second add our custom Keycloak specific converter
                    new KeycloakJwtRolesConverter());

    // Set up http security to use the JWT converter defined above
    httpSecurity.oauth2ResourceServer().jwt().jwtAuthenticationConverter(
            jwt -> new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt)));

    httpSecurity.authorizeHttpRequests(authorize -> authorize
            // Only users with the role "user" can access the endpoint /user.
            .requestMatchers("/user").hasAuthority(KeycloakJwtRolesConverter.PREFIX_RESOURCE_ROLE + "rest-api_user")
            // Only users with the role "admin" can access the endpoint /admin.
            .requestMatchers("/admin").hasAuthority(KeycloakJwtRolesConverter.PREFIX_RESOURCE_ROLE + "rest-api_admin")
            // All users, even once without an access token, can access the endpoint /public.
            .requestMatchers("/public").permitAll()
    );

    return httpSecurity.build();
  }
}
