package jwzp.security.spring_security_basic;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //Wywołanie post /books dla uwierzytelnionego użytkowanika z przypisaną rolą USER lub ADMIN
        //oraz delete /books/{id} dla uwierzytelnionego użytkowanika z przypisaną rolą ADMIN
        http.httpBasic().and().authorizeRequests()
                .antMatchers(HttpMethod.POST, "/books").hasAnyRole("USER", "ADMIN")
                .antMatchers(HttpMethod.DELETE, "/books").hasRole("ADMIN")
                .and()
                .formLogin().permitAll()
                .and()
                .logout().permitAll()
                .and()
                .csrf().disable();
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {

        //Sprawdzenie, czy dane logowania sie zgadzają
        //Połączenie z bazą danych w celu sprawdzenia zahashowanego hasła
        //Wpisuję ręcznie dwóch użytkowników
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("pass1"))
                .roles("USER");

        auth.inMemoryAuthentication()
                .withUser("admin")
                .password(passwordEncoder().encode("pass2"))
                .roles("ADMIN");
    }
}
