# secure-spring-rest-api-using-keycloak

This is the code for the blog post [Extract roles from access token issued by Keycloak using Spring Security](https://betweendata.io/posts/secure-spring-rest-api-using-keycloak//).

The problem: When parsing an access tokens issued by Keycloak using Spring Security the roles don’t get extracted from the token.

This post shows how to implement a custom converter for the token and combine it with the default JWT converter.