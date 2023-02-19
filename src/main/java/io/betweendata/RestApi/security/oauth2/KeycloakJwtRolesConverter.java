package io.betweendata.RestApi.security.oauth2;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

public class KeycloakJwtRolesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
  @Override
  public Collection<GrantedAuthority> convert(Jwt jwt) {
    // Collection that will hold the extracted roles
    Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();

    // Realm roles
    // Get the part of the access token that holds the roles assigned on realm level
    Map<String, Collection<String>> realmAccess = jwt.getClaim("realm_access");

    // Verify that the claim exists and is not empty
    if (realmAccess != null && !realmAccess.isEmpty()) {
      // From the realm_access claim get the roles
      Collection<String> roles = realmAccess.get("roles");
      // Check if any roles are present
      if (roles != null && !roles.isEmpty()) {
        // Iterate of the roles and add them to the granted authorities
        Collection<GrantedAuthority> realmRoles = roles.stream()
                // Prefix all realm roles with "ROLE_realm_"
                .map(role -> new SimpleGrantedAuthority("ROLE_realm_" + role))
                .collect(Collectors.toList());
        grantedAuthorities.addAll(realmRoles);
      }
    }

    // Resource (client) roles
    // A user might have access to multiple resources all containing their own roles. Therefore, it is a map of
    // resource each possibly containing a "roles" property.
    Map<String, Map<String, Collection<String>>> resourceAccess = jwt.getClaim("resource_access");

    // Check if resources are assigned
    if (resourceAccess != null && !resourceAccess.isEmpty()) {
      // Iterate of all the resources
      resourceAccess.forEach((resource, resourceClaims) -> {
        // Iterate of the "roles" claim inside the resource claims
        resourceClaims.get("roles").forEach(
                // Add the role to the granted authority prefixed with ROLE_ and the name of the resource
                role -> grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + resource + "_" + role))
        );
      });
    }

    return grantedAuthorities;
  }
}
