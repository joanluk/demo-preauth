package org.emaginalabs.samples.demopreauth.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Class with security configuration
 *
 * @author Arquitectura
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends AbstractPreAuthLdapSecurity {

    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http
                .headers()
                .frameOptions().disable()
                //.addHeaderWriter(configureFrameOptions()).and()
                .and()

                .authorizeRequests()

                .antMatchers("/**").authenticated()
                .and()
                // Form authentication
                .formLogin()
                //.httpBasic() //to use httpBasic authentication uncomment this line and comment previous 3
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .invalidateHttpSession(true).clearAuthentication(true)
                .deleteCookies("JSESSIONID"); // JSESSIONID name may change between environments

    }
}
