package de.dehn.drupal.util

import java.security.MessageDigest

/**
 * A Java implementation for the Drupal class <code>Crypt</code>: {https://api.drupal.org/api/drupal/core%21lib%21Drupal%21Component%21Utility%21Crypt.php/class/Crypt/8.2.x}.
 *
 * @author Stephan Grundner
 */
final class CryptUtils {

    /**
     * A Java implementation for the Drupal function <code>Crypt::hashBase64</code>: {https://api.drupal.org/api/drupal/core!lib!Drupal!Component!Utility!Crypt.php/function/Crypt%3A%3AhashBase64/8.2.x}.
     * Required for interacting with Drupal 8.
     *
     * @param base
     * @return
     */
    static String hashBase64(String base) {
        try {
            def digest = MessageDigest.getInstance("SHA-256")
            def hash = digest.digest(base.bytes)
            def result = Base64.encoder.encodeToString(hash)

            result = result.replaceAll(/[+]/, '-')
            result = result.replaceAll(/[\/]/, '_')
            result = result.replaceAll(/[=]/, '')

            return result
        } catch (e) {
            throw new RuntimeException(e)
        }
    }

    private CryptUtils() {}
}
