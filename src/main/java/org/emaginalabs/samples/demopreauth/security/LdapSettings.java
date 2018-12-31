package org.emaginalabs.samples.demopreauth.security;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;

/**
 * Ldap settings class with all properties to config AD corporate and client
 *
 * @author Arquitectura
 */

@Data
public class LdapSettings {

    @Value("${app.env.ldap.groupSearch.base}")
    private String groupSearchBase;
    @Value("${app.env.ldap.groupSearch.filter}")
    private String groupSearchFilter;
    @Value("${app.env.ldap.groupSearch.roleAttribute}")
    private String groupRoleAttribute;
    @Value("${app.env.ldap.groupSearch.searchSubtree}")
    private boolean groupSearchSubtree;
    @Value("${app.env.ldap.groupSearch.ignorePartialResultException}")
    private boolean ignorePartialResultException;
    @Value("${app.env.ldap.catalog.url}")
    private String url;
    @Value("${app.env.ldap.catalog.user}")
    private String userDn;
    @Value("${app.env.ldap.catalog.pass}")
    private String password;
    @Value("${app.env.ldap.java.naming.referral}")
    private String javaNamingRefal;
    @Value("${app.env.ldap.pool.timeBetweenEvictionRunsMillis}")
    private long timeBetweenEvictionRunsMillis;
    @Value("${app.env.ldap.pool.minEvictableIdleTimeMillis}")
    private long minEvictableIdleTimeMillis;
    @Value("${app.env.ldap.pool.maxActive}")
    private int maxActive;
    @Value("${app.env.ldap.pool.minIdle}")
    private int minIdle;
    @Value("${app.env.ldap.pool.maxIdle}")
    private int maxIdle;
    @Value("${app.env.ldap.pool.maxTotal}")
    private int maxTotal;
    @Value("${app.env.ldap.pool.maxWait}")
    private int maxWait;
    @Value("${app.env.ldap.pool.testOnBorrow}")
    private boolean testOnBorrow;
    @Value("${app.env.ldap.pool.testWhileIdle}")
    private boolean testWhileIdle;
    @Value("${app.env.ldap.userSearch.base}")
    private String userSearchBase;
    @Value("${app.env.ldap.userSearch.filter}")
    private String userSearchFilter;
    @Value("${app.env.ldap.userSearch.searchSubtree}")
    private boolean userSearchSubTree;

    @Value("${app.env.security.authorization:false}")
    private String populatorAuthorizationActive;

    @Value("${app.env.ldap.read.timeout}")
    private String ldapReadTimeout;

    @Value("${app.env.ldap.authentication.cache.enabled}")
    private boolean cacheAuthenticationActivated;


}