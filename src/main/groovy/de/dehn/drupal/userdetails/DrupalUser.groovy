package de.dehn.drupal.userdetails

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User

import javax.servlet.http.Cookie

/**
 * Drupal user data.
 *
 * @author Stephan Grundner
 */
class DrupalUser extends User {

    final Cookie cookie
    final String languageTag
    final Date lastLogin
    final TimeZone timeZone

    DrupalUser(String username, String password, boolean enabled,
               final Cookie cookie,
               String languageTag,
               Date lastLogin,
               TimeZone timeZone,
               boolean accountNonExpired,
               boolean credentialsNonExpired,
               boolean accountNonLocked,
               Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities)
        this.cookie = cookie
        this.languageTag = languageTag
        this.lastLogin = lastLogin
        this.timeZone = timeZone
    }

    DrupalUser(String username, String password, boolean enabled,
               final Cookie cookie,
               String languageTag,
               Date lastLogin,
               TimeZone timeZone,
               Collection<? extends GrantedAuthority> authorities) {
        this(username, password, enabled, cookie, languageTag, lastLogin, timeZone, true, true, true, authorities)
    }
}
