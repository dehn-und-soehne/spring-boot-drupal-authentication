package de.dehn.drupal.authentication.preauth

import javax.servlet.http.Cookie

/**
 * A cookie based principal.
 *
 * @author Stephan Grundner
 */
class DrupalAuthenticationCookiePrincipal {

    final Cookie cookie

    DrupalAuthenticationCookiePrincipal(Cookie cookie) {
        this.cookie = cookie
    }
}
