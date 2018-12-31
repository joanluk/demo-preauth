package org.emaginalabs.samples.demopreauth.security;

import org.emaginalabs.samples.demopreauth.security.preauth.GrantedAuthoritiesWebAuthenticationDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

/**
 * Abstract preauth provider authentication configuration
 */
@Slf4j
public abstract class AbstractPreAuthLdapSecurity extends AbstractLdapSecurity {

    @Value("${app.env.preauth.header.name:iv-user}")
    private String headerName;

    @Bean
    @ConditionalOnMissingBean
    public PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider() {
        PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
        preAuthenticatedAuthenticationProvider
                .setPreAuthenticatedUserDetailsService(preAuthenticatedGrantedAuthoritiesUserDetailsService());
        return preAuthenticatedAuthenticationProvider;
    }

    @Bean
    @ConditionalOnMissingBean
    public PreAuthenticatedGrantedAuthoritiesUserDetailsService preAuthenticatedGrantedAuthoritiesUserDetailsService() {
        return new PreAuthenticatedGrantedAuthoritiesUserDetailsService();
    }


    @Bean
    @ConditionalOnMissingBean
    public GrantedAuthoritiesWebAuthenticationDetails preAuthenticatedGrantedAuthoritiesWebAuthenticationDetails() {
        return new GrantedAuthoritiesWebAuthenticationDetails(
                defaultLdapAuthoritiesPopulator(), userSearch(), headerName);

    }                   


    @Override
    public void configureAuthenticationManager(AuthenticationManagerBuilder auth)
            throws Exception {

        auth.authenticationProvider(preAuthenticatedAuthenticationProvider());
        log.debug("Configured preAuthenticatedAuthenticationProvider for authentication manager");

        super.configureAuthenticationManager(auth);
        log.debug("Configured all ldapAuthenticationProvider for authentication manager");

    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter = new RequestHeaderAuthenticationFilter();
        requestHeaderAuthenticationFilter.setPrincipalRequestHeader(headerName);
        requestHeaderAuthenticationFilter.setAuthenticationManager(authenticationManager());
        requestHeaderAuthenticationFilter.setAuthenticationDetailsSource(preAuthenticatedGrantedAuthoritiesWebAuthenticationDetails());
        requestHeaderAuthenticationFilter.setExceptionIfHeaderMissing(false);
        http.addFilterBefore(requestHeaderAuthenticationFilter,
                UsernamePasswordAuthenticationFilter.class);
    }
}
