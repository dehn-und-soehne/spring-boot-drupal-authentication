package de.dehn.drupal.config

import javax.sql.DataSource

/**
 * Drupal authentication settings.
 *
 * @author Stephan Grundner
 */
class DrupalAuthenticationSettings {

    static final DEFAULT_COOKIE_NAME_PATTERN = 'SESS.*'

    int majorVersion = 0
    String cookieNamePattern = DEFAULT_COOKIE_NAME_PATTERN
    DataSource dataSource
}
