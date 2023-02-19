package io.betweendata.RestApi.security.oauth2;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakJwtRolesConverterTest {

  // Class under test
  private KeycloakJwtRolesConverter converter = null;

  @BeforeEach
  public void before() {
    converter = new KeycloakJwtRolesConverter();
  }

  /**
   * Given a token that contains no "realm_access" claim
   * <p>
   * When converting the token to authorities
   * <p>
   * Then no role authorities are extracted
   */
  @Test
  public void testNoRealmAccessClaim() {
    Jwt jwt = givenBaseToken().build();

    Collection<GrantedAuthority> authorities = converter.convert(jwt);

    assertThat(authorities).isEmpty();
  }

  /**
   * Given a token that contains an empty "realm_access" claim
   * <p>
   * When converting the token to authorities
   * <p>
   * Then no role authorities are extracted
   */
  @Test
  public void testEmptyRealmAccessClaim() {
    Map<String, Object> realmAccess = new HashMap<>();

    Jwt jwt = givenBaseToken().claim("realm_access", realmAccess).build();

    Collection<GrantedAuthority> authorities = converter.convert(jwt);

    assertThat(authorities).isEmpty();
  }

  /**
   * Given a token that contains an empty entry for the "resource_access.roles"
   * claim
   * <p>
   * When converting the token to authorities
   * <p>
   * Then no role authorities are extracted
   */
  @Test
  public void testEmptyRealmRoles() {
    Map<String, Object> realmAccess = new HashMap<>();
    Collection<String> roles = new ArrayList<>();
    realmAccess.put("roles", roles);

    Jwt jwt = givenBaseToken().claim("realm_access", realmAccess).build();

    Collection<GrantedAuthority> authorities = converter.convert(jwt);

    assertThat(authorities).isEmpty();
  }

  /**
   * Given a token that contains one realm role
   * <p>
   * When converting the token to authorities
   * <p>
   * Then the role is extracted to an authority
   */
  @Test
  public void testOneRealmRole() {
    Map<String, Object> realmAccess = new HashMap<>();
    Collection<String> roles = new ArrayList<>();
    roles.add("realm-role-1");
    realmAccess.put("roles", roles);

    Jwt jwt = givenBaseToken().claim("realm_access", realmAccess).build();

    Collection<GrantedAuthority> authorities = converter.convert(jwt);

    assertThat(authorities).hasSize(1);
    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_realm_realm-role-1"));
  }

  /**
   * Given a token that contains multiple realm role
   * <p>
   * When converting the token to authorities
   * <p>
   * Then the roles are extracted to authorities
   */
  @Test
  public void testMultipleRealmRole() {
    Map<String, Object> realmAccess = new HashMap<>();
    Collection<String> roles = new ArrayList<>();
    roles.add("realm-role-1");
    roles.add("realm-role-2");
    roles.add("realm-role-3");
    realmAccess.put("roles", roles);

    Jwt jwt = givenBaseToken().claim("realm_access", realmAccess).build();

    Collection<GrantedAuthority> authorities = converter.convert(jwt);

    assertThat(authorities).hasSize(3);
    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_realm_realm-role-1"));
    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_realm_realm-role-2"));
    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_realm_realm-role-3"));
  }

  /**
   * Given a token without a "resource_access" claim
   * <p>
   * When converting the token to authorities
   * <p>
   * Then no authorities are extracted
   */
  @Test
  public void testNoResourceAccessClaim() {
    Jwt jwt = givenBaseToken().build();

    Collection<GrantedAuthority> authorities = converter.convert(jwt);

    assertThat(authorities).isEmpty();
  }

  /**
   * Given a token that contains an empty "resource_access" claim
   * <p>
   * When converting to the token to authorities
   * <p>
   * Then no authorities are extracted
   */
  @Test
  public void testEmptyResourceAccessClaim() {
    Map<String, Object> resourceAccess = new HashMap<>();

    Jwt jwt = givenBaseToken().claim("resource_access", resourceAccess).build();

    Collection<GrantedAuthority> authorities = converter.convert(jwt);

    assertThat(authorities).isEmpty();
  }

  /**
   * Given a token that contains an empty "resource_access.rest-api.roles" claim
   * <p>
   * When converting the token to authorities
   * <p>
   * Then no role authorities are extracted
   */
  @Test
  public void testEmptyResourceAccessRolesClaim() {
    Map<String, Object> resourceAccess = new HashMap<>();
    Map<String, Object> restApiResource = new HashMap<>();
    Collection<String> roles = new ArrayList<>();
    restApiResource.put("roles", roles);
    resourceAccess.put("rest-api", restApiResource);

    Jwt jwt = givenBaseToken().claim("resource_access", resourceAccess).build();

    Collection<GrantedAuthority> authorities = converter.convert(jwt);

    assertThat(authorities).isEmpty();
  }

  /**
   * Given a token that contains one resource specific role
   * <p>
   * When converting the token to authorities
   * <p>
   * Then the role is converted to an authority
   */
  @Test
  public void testOneResourceWithOneRole() {
    Map<String, Object> resourceAccess = new HashMap<>();
    Map<String, Object> restApiResource = new HashMap<>();
    Collection<String> roles = new ArrayList<>();
    roles.add("user");
    restApiResource.put("roles", roles);
    resourceAccess.put("rest-api", restApiResource);

    Jwt jwt = givenBaseToken().claim("resource_access", resourceAccess).build();

    Collection<GrantedAuthority> authorities = converter.convert(jwt);

    assertThat(authorities).hasSize(1);
    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_rest-api_user"));
  }

  /**
   * Given a token that contains multiple realm roles and multiple resource containing roles
   * <p>
   * When converting the token to authorities
   * <p>
   * Then all realm and resource roles are extracted
   */
  @Test
  public void testRealmAndResourceRoles() {
    // Realm roles
    Map<String, Object> realmAccess = new HashMap<>();
    Collection<String> realmRoles = new ArrayList<>();
    realmRoles.add("realm-role-1");
    realmRoles.add("realm-role-2");
    realmRoles.add("realm-role-3");
    realmAccess.put("roles", realmRoles);

    // Resource roles
    Map<String, Object> resourceAccess = new HashMap<>();

    Map<String, Object> restApiResource = new HashMap<>();
    Collection<String> restApiRoles = new ArrayList<>();
     restApiRoles.add("user");
     restApiRoles.add("admin");
    restApiResource.put("roles",  restApiRoles);
    resourceAccess.put("rest-api", restApiResource);

    Map<String, Object> apiResource = new HashMap<>();
    Collection<String> apiRoles = new ArrayList<>();
    apiRoles.add("read");
    apiRoles.add("write");
    apiResource.put("roles", apiRoles);
    resourceAccess.put("api", apiResource);


    Jwt jwt = givenBaseToken()
            .claim("realm_access", realmAccess)
            .claim("resource_access", resourceAccess)
            .build();

    Collection<GrantedAuthority> authorities = converter.convert(jwt);

    assertThat(authorities).hasSize(7);

    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_realm_realm-role-1"));
    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_realm_realm-role-2"));
    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_realm_realm-role-3"));
    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_rest-api_user"));
    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_rest-api_admin"));
    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_api_read"));
    assertThat(authorities).contains(new SimpleGrantedAuthority("ROLE_api_write"));
  }

  /**
   * @return a JWT builder to build a valid token containing no claims
   */
  private Jwt.Builder givenBaseToken() {
    return Jwt.withTokenValue("tokenValue")
            .header("alg", "none")
            .audience(List.of("https://audience.example.org"))
            .expiresAt(Instant.MAX)
            .issuedAt(Instant.MIN)
            .issuer("https://issuer.example.org")
            .jti("jti")
            .notBefore(Instant.MIN)
            .subject("test-subject");
  }
}