package org.emaginalabs.samples.demopreauth.security;

import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.math.NumberUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.pool.factory.PoolingContextSource;
import org.springframework.ldap.pool.validation.DefaultDirContextValidator;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.cache.SpringCacheBasedUserCache;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.NullLdapAuthoritiesPopulator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;


/**
 * Provides a base class for creating a
 * {@link org.springframework.security.config.annotation.web.WebSecurityConfigurer}
 * instance based ldap. The implementation allows customization by overriding
 * methods.
 *
 * @author Arquitectura
 * @see org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
 */

@Slf4j
public abstract class AbstractLdapSecurity extends WebSecurityConfigurerAdapter {


    @Autowired
    private ApplicationContext context;


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth)
            throws Exception {
        configureAuthenticationManager(auth);
        configureAdditional(auth);
    }


    /**
     * Method for additional configuration for the auth manager builder.
     *
     * Applications can overwrite this method to add additional behavior
     *
     * @param auth auth manager builder
     */
    protected void configureAdditional(AuthenticationManagerBuilder auth) {
    }

    @Bean
    public LdapSettings ldapSettings() {
        return new LdapSettings();
    }

    public void configureAuthenticationManager(AuthenticationManagerBuilder auth)
            throws Exception {

        registerDirCorporate(auth);
    }


    private void registerDirCorporate(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(defineDirCorporateAuthenticator());

    }


    /**
     * Define bind authenticator for AD corporate.
     *
     * @return AuthenticationProvider authentication provider
     * @throws Exception exception
     */
    private AuthenticationProvider defineDirCorporateAuthenticator() throws Exception {
        BindAuthenticator bindAuthenticator = new BindAuthenticator(
                contextSourceTarget());
        bindAuthenticator.setUserSearch(userSearch());
        CustomLdapAuthenticationProvider ldapAuthenticationProvider = new CustomLdapAuthenticationProvider(
                bindAuthenticator, strategyLdapAuthoritiesPopulator());
        if (ldapSettings().isCacheAuthenticationActivated()) {
            log.debug("Authentication cache enabled");
            ldapAuthenticationProvider.setUserCache(basicAuthenticationUserCache());
        }
        return ldapAuthenticationProvider;
    }


    @Bean
    public FilterBasedLdapUserSearch userSearch() {
        FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(
                ldapSettings().getUserSearchBase(), ldapSettings().getUserSearchFilter(), contextSourceTarget());
        userSearch.setSearchSubtree(ldapSettings().isUserSearchSubTree());
        return userSearch;
    }


    @Bean(name = "defaultLdapAuthoritiesPopulator")
    public DefaultLdapAuthoritiesPopulator defaultLdapAuthoritiesPopulator() {
        log.debug("Defined default strategy for ldap authorities populator.");

        DefaultLdapAuthoritiesPopulator defaultLdapAuthoritiesPopulator = new DefaultLdapAuthoritiesPopulator(
                contextSource(), ldapSettings().getGroupSearchBase());
        defaultLdapAuthoritiesPopulator.setGroupSearchFilter(ldapSettings().getGroupSearchFilter());
        defaultLdapAuthoritiesPopulator
                .setGroupRoleAttribute(ldapSettings().getGroupRoleAttribute());
        defaultLdapAuthoritiesPopulator.setSearchSubtree(ldapSettings().isGroupSearchSubtree());
        defaultLdapAuthoritiesPopulator
                .setIgnorePartialResultException(ldapSettings().isIgnorePartialResultException());

        return defaultLdapAuthoritiesPopulator;

    }


    @Bean
    public PoolingContextSource contextSource() {
        PoolingContextSource contextSource = new PoolingContextSource();
        contextSource.setContextSource(contextSourceTarget());
        contextSource.setDirContextValidator(new DefaultDirContextValidator());
        contextSource
                .setTimeBetweenEvictionRunsMillis(ldapSettings().getTimeBetweenEvictionRunsMillis());
        contextSource.setMinEvictableIdleTimeMillis(ldapSettings().getMinEvictableIdleTimeMillis());
        contextSource.setMaxActive(ldapSettings().getMaxActive());
        contextSource.setMinIdle(ldapSettings().getMinIdle());
        contextSource.setMaxIdle(ldapSettings().getMaxIdle());
        contextSource.setMaxTotal(ldapSettings().getMaxTotal());
        contextSource.setMaxWait(ldapSettings().getMaxWait());
        contextSource.setTestOnBorrow(ldapSettings().isTestOnBorrow());
        contextSource.setTestWhileIdle(ldapSettings().isTestWhileIdle());
        return contextSource;
    }


    @Bean
    public LdapContextSource contextSourceTarget() {
        LdapContextSource contextSourceTarget = new LdapContextSource();
        contextSourceTarget.setUrl(ldapSettings().getUrl());
        contextSourceTarget.setUserDn(ldapSettings().getUserDn());
        contextSourceTarget.setPassword(ldapSettings().getPassword());
        contextSourceTarget
                .setBaseEnvironmentProperties(baseEnvironmentProperties());
        contextSourceTarget.setPooled(false);
        try {
            contextSourceTarget.afterPropertiesSet();
        } catch (Exception e) {
            log.error("There was an error in afterPropertiesSet "
                    + e.getMessage());
        }
        return contextSourceTarget;
    }


    @Bean
    public Map<String, Object> baseEnvironmentProperties() {
        Map<String, Object> baseEnvironmentProperties = new HashMap<>();
        baseEnvironmentProperties.put("java.naming.referral", ldapSettings().getJavaNamingRefal());
        if (StringUtils.hasText(ldapSettings().getLdapReadTimeout())
                && NumberUtils.isDigits(ldapSettings().getLdapReadTimeout())) {
            baseEnvironmentProperties.put("com.sun.jndi.ldap.read.timeout",
                    ldapSettings().getLdapReadTimeout());
        } else {
            log.info("The value for app.env.ldap.read.timeout/gaia.env.ldap.read.timeout is null or not number. "
                    + "No timeout for ldap read query is set.");
        }
        return baseEnvironmentProperties;
    }


    protected ApplicationContext getContext() {
        return context;
    }


    /**
     * Create basic authentication cache
     *
     * @return UserCache
     * @throws Exception
     * @see UserCache
     */
    private UserCache basicAuthenticationUserCache() throws Exception {

        CaffeineCache caffeineCache = new CaffeineCache("groupsldap",
                Caffeine.newBuilder().expireAfterWrite(5, TimeUnit.MINUTES).initialCapacity(1000).build());
        return new SpringCacheBasedUserCache(caffeineCache);

    }


    private LdapAuthoritiesPopulator strategyLdapAuthoritiesPopulator() {
        return (Boolean.valueOf(ldapSettings().getPopulatorAuthorizationActive()) ? defaultLdapAuthoritiesPopulator()
                : new NullLdapAuthoritiesPopulator());
    }



}
