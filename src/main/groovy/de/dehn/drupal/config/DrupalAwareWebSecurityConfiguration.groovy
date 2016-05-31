package de.dehn.drupal.config

import de.dehn.drupal.authentication.preauth.DrupalAuthenticationUserDetailsService
import de.dehn.drupal.filter.DrupalPreAuthenticationFilter
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.jdbc.datasource.DriverManagerDataSource
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider
import org.springframework.security.web.context.SecurityContextPersistenceFilter

import javax.sql.DataSource

/**
 * Drupal authentication configuration.
 *
 * Settings example:
 * <pre>
 * drupal.major-version=8
 * drupal.cookie-name-pattern=SESS.*
 * drupal.datasource.driver-class-name=com.mysql.jdbc.Driver
 * drupal.datasource.url=jdbc:mysql://localhost/drupal8?useUnicode=true&useJDBCCompliantTimezoneShift=true&useLegacyDatetimeCode=false&serverTimezone=UTC
 * drupal.datasource.username=root
 * </pre>
 *
 * @author Stephan Grundner
 */
@Configuration
@Order(99)
@EnableWebSecurity
@EnableConfigurationProperties
class DrupalAwareWebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    @ConfigurationProperties(prefix = 'drupal.datasource')
    @SuppressWarnings('all')
    protected DataSource drupalAuthenticationDataSource() {
        new DriverManagerDataSource()
    }

    @Bean
    @ConfigurationProperties(prefix = 'drupal')
    DrupalAuthenticationSettings drupalAuthenticationSettings() {
        def settings = new DrupalAuthenticationSettings()
        settings.dataSource = drupalAuthenticationDataSource()

        settings
    }

    @Bean
    DrupalAuthenticationUserDetailsService drupalAuthenticationUserDetailsService() {
        def settings = drupalAuthenticationSettings()
        def dataSource = settings.dataSource

        new DrupalAuthenticationUserDetailsService(dataSource, settings.majorVersion)
    }

    @Bean
    DrupalPreAuthenticationFilter drupalAuthenticationFilter() {
        def settings = drupalAuthenticationSettings()
        def dataSource = settings.dataSource
        def authenticationManager = authenticationManager()

        def filter = new DrupalPreAuthenticationFilter(settings.cookieNamePattern, dataSource)
        filter.authenticationManager = authenticationManager
        filter.invalidateSessionOnPrincipalChange = true
        filter.checkForPrincipalChanges = true
        filter.continueFilterChainOnUnsuccessfulAuthentication = true

        filter
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        def authenticationProvider = new PreAuthenticatedAuthenticationProvider()
        def authenticationUserDetailsService = drupalAuthenticationUserDetailsService()
        authenticationProvider.preAuthenticatedUserDetailsService = authenticationUserDetailsService
        auth.authenticationProvider(authenticationProvider)
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        def filter = drupalAuthenticationFilter()

        http.with {
            addFilterAfter(filter, SecurityContextPersistenceFilter)

            httpBasic().disable()
            formLogin().disable()
            logout().disable()
        }
    }
}
