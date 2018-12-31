package org.emaginalabs.samples.demopreauth.security.preauth;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;

/**
 * Custom implementation to fill security details (Roles for NUUMA) when
 * preauthentication is done in production environments.
 *
 * @author Arquitectura
 *
 */
@Data
@AllArgsConstructor
public class GrantedAuthoritiesWebAuthenticationDetails implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {

    private final LdapAuthoritiesPopulator authoritiesPopulator;
    private final LdapUserSearch userSearch;

    private final String headerName;

    public WebAuthenticationDetails buildDetails(HttpServletRequest context) {
        Collection<? extends GrantedAuthority> authorities;
        String header = context.getHeader(headerName);
        DirContextOperations searchForUser = userSearch.searchForUser(header);
        authorities = authoritiesPopulator.getGrantedAuthorities(searchForUser, header);
        return new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(context, authorities);
    }


}
