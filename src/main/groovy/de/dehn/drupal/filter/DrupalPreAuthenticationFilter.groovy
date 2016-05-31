package de.dehn.drupal.filter

import de.dehn.drupal.userdetails.DrupalUser
import de.dehn.drupal.authentication.preauth.DrupalAuthenticationCookiePrincipal
import de.dehn.drupal.util.CryptUtils
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.sql.DataSource

/**
 * Use Drupal cookies for authentication.
 *
 * @author Stephan Grundner
 */
class DrupalPreAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    static final PRINCIPAL_ATTRIBUTE_NAME = DrupalPreAuthenticationFilter.name + '#principal'

    /**
     * Checks if two cookies are identical.
     *
     * String name;
     * String value;
     *
     * int version = 0; // ;Version=1 ... means RFC 2109 style
     * String comment; // ;Comment=VALUE ... describes cookie's use
     * String domain; // ;Domain=VALUE ... domain that sees cookie
     * int maxAge = -1; // ;Max-Age=VALUE ... cookies auto-expire
     * String path; // ;Path=VALUE ... URLs that see the cookie
     * boolean secure; // ;Secure ... e.g. use SSL
     * boolean httpOnly; // Not in cookie specs, but supported by browsers
     *
     * @param a
     * @param b
     * @return
     */
    private static boolean cookiesEquals(Cookie a, Cookie b) {
        if (a == b) {
            return true
        }

        if (a == null || b == null) {
            return false
        }

        def equals = true

        equals &= a.name == b.name
        equals &= a.value == b.value

        equals
    }

    private static boolean containsCookie(HttpServletRequest request, Cookie cookie) {
        request.cookies.find { cookiesEquals(it, cookie) }
    }

    final String cookieNamePattern
    final DataSource dataSource

    DrupalPreAuthenticationFilter(String cookieNamePattern, DataSource dataSource) {
        this.cookieNamePattern = cookieNamePattern
        this.dataSource = dataSource
    }

    private Collection<Cookie> findDrupalCookieCandidates(HttpServletRequest request) {
        request.cookies.findAll { it.name ==~ cookieNamePattern }
    }

    /**
     * Checks if the cookie used for authentication is still there.
     *
     * @param request
     * @param currentAuthentication
     * @return false if the cookie used for authentication is still there, otherwise true
     */
    @Override
    protected boolean principalChanged(HttpServletRequest request, Authentication currentAuthentication) {
        def principal = getPreAuthenticatedPrincipal(request)
        if (principal instanceof DrupalUser) {

            def cookie = principal.cookie
            return !containsCookie(request, cookie)
        }

        super.principalChanged(request, currentAuthentication)
    }

    /**
     * Checks each cookie candiate if it matches with an entry in the drupal database.
     *
     * @param request
     * @return An authenticated principal or null
     */
    DrupalAuthenticationCookiePrincipal findDrupalPrincipal(HttpServletRequest request) {
        def connection = dataSource.connection
        def sql = """\
select count(*) from sessions as s
where s.sid = ? or s.sid = ?
"""
        def cookieCandidates = findDrupalCookieCandidates(request)
        for (def cookie : cookieCandidates) {
            def statement = connection.prepareStatement(sql)
            statement.setString(1, cookie.value)
            statement.setString(2, CryptUtils.hashBase64(cookie.value))

            def rs = statement.executeQuery()
            if (rs.next() && rs.getInt(1) > 0) {
                return new DrupalAuthenticationCookiePrincipal(cookie)
            }
        }

        null
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) {
        super.successfulAuthentication(request, response, authResult)
//        Note: A session is created here if it doesn't exist yet!
        def session = request.getSession(true)
        session.setAttribute(PRINCIPAL_ATTRIBUTE_NAME, authResult.principal)
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        def session = request.getSession(false)
        def principal = session?.getAttribute(PRINCIPAL_ATTRIBUTE_NAME)
        if (principal == null) {
            principal = findDrupalPrincipal(request)
        }

        principal
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        ''
    }
}
