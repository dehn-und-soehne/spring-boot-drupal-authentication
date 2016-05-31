package de.dehn.drupal.authentication.preauth

import de.dehn.drupal.userdetails.DrupalUser
import de.dehn.drupal.util.CryptUtils
import org.slf4j.LoggerFactory
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken

import javax.sql.DataSource
import java.sql.PreparedStatement

/**
 * Read user data from Drupal for an existing session cookie.
 *
 * @author Stephan Grundner
 */
class DrupalAuthenticationUserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private static final log = LoggerFactory.getLogger(DrupalAuthenticationUserDetailsService)

    final int majorVersion
    final DataSource dataSource

    DrupalAuthenticationUserDetailsService(DataSource dataSource, int majorVersion) {
        this.dataSource = dataSource

        assert majorVersion >= 7 && majorVersion <= 8, "Unsupported major version"

        this.majorVersion = majorVersion
    }

    Collection<GrantedAuthority> loadAuthorities(int uid) {
        def connection = dataSource.connection

        String sql
        PreparedStatement statement

        if (majorVersion > 7) {
            sql = """\
select ur.roles_target_id as name from user__roles as ur
where ur.entity_id = ? and ur.bundle = ?
"""
            statement = connection.prepareStatement(sql)
            statement.setInt(1, uid)
            statement.setString(2, 'user')
        } else {
            sql = """\
select r.name as name from users_roles as ur
join role as r on ur.rid = r.rid
where ur.uid = ?
"""
            statement = connection.prepareStatement(sql)
            statement.setInt(1, uid)
        }

        def authorities = []

        def rs = statement.executeQuery()
        if (rs.next()) {
            def name = rs.getString('name')
            authorities.add(new SimpleGrantedAuthority("ROLE_$name".toUpperCase()))
        }

        authorities
    }

    @Override
    UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException {
        def principal = token.principal
        if (principal instanceof DrupalAuthenticationCookiePrincipal) {
            def connection = dataSource.connection

            String sql

            if (majorVersion > 7) {
                sql = """\
select * from sessions as s
join users as u on u.uid = s.uid
join users_field_data as d on d.uid = s.uid
where s.sid = ? or s.sid = ?
"""
            } else {
                sql = """\
select * from sessions as s
join users as u on u.uid = s.uid
where s.sid = ? or s.sid = ?
"""
            }

            def cookie = principal.cookie
            def statement = connection.prepareStatement(sql)
            statement.setString(1, cookie.value)
            statement.setString(2, CryptUtils.hashBase64(cookie.value))
            log.info(statement.toString())
            def rs = statement.executeQuery()
            if (rs.next()) {

                def name = rs.getString('name')
                def pass = rs.getString('pass')

                // User's time zone.
                def timezoneId = rs.getString('timezone')
                def timeZone = TimeZone.getTimeZone(timezoneId)

                // Timestamp for user's last login.
                def login = rs.getLong('login')

                // User's default language.
                String languageTag = null
                if (majorVersion > 7) {
                    languageTag = rs.getString('langcode')
                } else {
                    languageTag = rs.getString('language')
                }

                // Whether the user is active(1) or blocked(0).
                def status = rs.getInt('status')
                def enabled = status != 0

                def lastLogin = new Date(login)

                def uid = rs.getInt('uid')
                def authorities = loadAuthorities(uid)

                return new DrupalUser(
                        name, pass, enabled, cookie,
                        languageTag, lastLogin, timeZone,
                        authorities)
            }
        }

        throw new UsernameNotFoundException("No authenticated user found")
    }
}
