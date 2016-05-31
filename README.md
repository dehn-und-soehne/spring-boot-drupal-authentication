# Spring Boot Drupal authentication
## Usage

```gradle
compile 'de.dehn:spring-boot-drupal-authentication:1.0'
```

Extend the class `DrupalAwareWebSecurityConfiguration`:
```groovy
@Configuration
@EnableWebSecurity
class WebSecurityConfig extends DrupalAwareWebSecurityConfiguration {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
                .and()
    }
}
```

Settings:
```properties
drupal.major-version=8
drupal.cookie-name-pattern=SESS.*
drupal.datasource.driver-class-name=com.mysql.jdbc.Driver
drupal.datasource.url=jdbc:mysql://localhost/drupal8?useUnicode=true&useJDBCCompliantTimezoneShift=true&useLegacyDatetimeCode=false&serverTimezone=UTC
drupal.datasource.username=root
```
