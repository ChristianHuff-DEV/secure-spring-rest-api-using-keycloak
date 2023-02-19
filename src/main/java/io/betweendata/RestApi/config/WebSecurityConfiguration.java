package io.betweendata.RestApi.config;

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

  @Bean
  SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

    DelegatingJwtGrantedAuthoritiesConverter authoritiesConverter =
            new DelegatingJwtGrantedAuthoritiesConverter(new JwtGrantedAuthoritiesConverter());

    httpSecurity.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwt -> new JwtAuthenticationToken(jwt,
            authoritiesConverter.convert(jwt)));

    httpSecurity.authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/**")
            .hasAuthority("SCOPE_email")
            .anyRequest()
            .authenticated());

    return httpSecurity.build();
  }
}
