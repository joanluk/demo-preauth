package org.emaginalabs.samples.demopreauth.security;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.util.StringUtils;


/**
 * LDAP  authentication ldap provider with cache
 *
 * Caching is handled by storing the <code>UserDetails</code> object being placed in the
 * {@link UserCache}. This ensures that subsequent requests with the same username can be
 * validated without needing to query the {@link org.springframework.security.core.userdetails.UserDetailsService}.
 * It should be noted that if a user appears to present an incorrect password, the
 * {@link org.springframework.security.core.userdetails.UserDetailsService}
 * will be queried to confirm the most up-to-date password was used for comparison.
 * Caching is only likely to be required for stateless applications. In a normal web
 * application, for example, the <tt>SecurityContext</tt> is stored in the user's session
 * and the user isn't reauthenticated on each request. The default cache implementation is
 * therefore {@link NullUserCache}.
 *
 * @author Arquitectura
 */
@Data
@Slf4j
public final class CustomLdapAuthenticationProvider extends LdapAuthenticationProvider {


    private UserCache userCache = new NullUserCache();

    public CustomLdapAuthenticationProvider(LdapAuthenticator authenticator, LdapAuthoritiesPopulator authoritiesPopulator) {
        super(authenticator, authoritiesPopulator);
    }

    public CustomLdapAuthenticationProvider(LdapAuthenticator authenticator) {
        super(authenticator);
    }


    @Override
    public Authentication authenticate(Authentication authentication) {
        String userName = authentication.getName();
        UsernamePasswordAuthenticationToken userToken = (UsernamePasswordAuthenticationToken) authentication;
        UserDetails userDetailsFromCache = userCache.getUserFromCache(userName);
        if (userDetailsFromCache != null) {
            additionalAuthenticationChecks(userDetailsFromCache, userToken);
            return createSuccessfulAuthentication(userToken, userDetailsFromCache);
        } else {
            Authentication authenticationFromProvider = super.authenticate(authentication);
            userCache.putUserInCache((UserDetails) authenticationFromProvider.getPrincipal());
            return authenticationFromProvider;
        }

    }

    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken authentication) {
        if (StringUtils.isEmpty(authentication.getCredentials())) {
            logger.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }
        String presentedPassword = authentication.getCredentials().toString();
        if (!StringUtils.isEmpty(userDetails.getPassword()) && (!presentedPassword.equals(userDetails.getPassword()))) {
            log.debug("Authentication failed: password does not match stored value");
            throw new BadCredentialsException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }
    }

}
