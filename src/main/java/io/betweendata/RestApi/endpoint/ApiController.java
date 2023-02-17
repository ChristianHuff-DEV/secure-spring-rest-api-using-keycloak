package io.betweendata.RestApi.endpoint;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

  @RequestMapping(
          method = RequestMethod.GET,
          value = "/public",
          produces = { "text/plain" }
  )
  public ResponseEntity<String> publicEndpoint(){

    return new ResponseEntity<>("Public Endpoint", HttpStatus.CREATED);
  }
}
