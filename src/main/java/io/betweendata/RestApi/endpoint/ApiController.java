package io.betweendata.RestApi.endpoint;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

  /**
   * Endpoint which should be accessible by anyone even without an access token. (see
   * {@link io.betweendata.RestApi.config.WebSecurityConfiguration#filterChain(HttpSecurity)} for the configuration.)
   */
  @RequestMapping(
          method = RequestMethod.GET,
          value = "/public",
          produces = {"text/plain"}
  )
  public ResponseEntity<String> publicEndpoint() {

    return new ResponseEntity<>("Public Endpoint", HttpStatus.CREATED);
  }

  /**
   * Endpoint which should be accessible only by users with the role "user"
   * {@link io.betweendata.RestApi.config.WebSecurityConfiguration#filterChain(HttpSecurity)} for the configuration.)
   */
  @RequestMapping(
          method = RequestMethod.GET,
          value = "/user",
          produces = {"text/plain"}
  )
  public ResponseEntity<String> userEndpoint() {

    return new ResponseEntity<>("User Endpoint", HttpStatus.CREATED);
  }

  /**
   * Endpoint which should be accessible only by users with the role "admin"
   * {@link io.betweendata.RestApi.config.WebSecurityConfiguration#filterChain(HttpSecurity)} for the configuration.)
   */
  @RequestMapping(
          method = RequestMethod.GET,
          value = "/admin",
          produces = {"text/plain"}
  )
  public ResponseEntity<String> adminEndpoint() {

    return new ResponseEntity<>("Admin Endpoint", HttpStatus.CREATED);
  }

}
