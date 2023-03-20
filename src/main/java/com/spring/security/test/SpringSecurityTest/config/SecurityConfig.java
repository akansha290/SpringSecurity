package com.spring.security.test.SpringSecurityTest.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    //This is a method in Java that returns an instance of a class that implements the PasswordEncoder interface.
    // Specifically, it returns an instance of the BCryptPasswordEncoder class, which is a widely used implementation
    // of the PasswordEncoder interface that is designed to securely hash passwords.
    //
    //In many applications, it is important to store passwords securely, so that if an attacker gains access to the
    // database of user credentials, they will not be able to easily determine the passwords for each user account.
    // One common technique for achieving this is to hash the passwords before storing them in the database. A hash
    // function takes an input (in this case, a password) and generates a fixed-length output that is unique to that
    // input. However, the hash function is one-way, meaning that it is very difficult (ideally, practically impossible)
    // to reverse-engineer the input from the output. Therefore, even if an attacker gains access to the database and
    // sees the hashed passwords, they will not be able to determine the original passwords.
    //
    //The BCryptPasswordEncoder class is a particular implementation of the PasswordEncoder interface that uses the
    // bcrypt algorithm to hash passwords. Bcrypt is a popular and secure hashing algorithm that is designed to be
    // difficult to crack using brute-force techniques. When a password is hashed using bcrypt, the resulting output
    // is a string of characters that can be stored in the database. When a user logs in, their entered password is
    // hashed using the same bcrypt algorithm and compared to the stored hash. If the two hashes match, the user is
    // authenticated and allowed to access the application.
    //So, in summary, the method creates a new instance of the BCryptPasswordEncoder class, which can be used to
    // securely hash passwords in a Java application.
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //The public UserDetailsService userDetailsService(){} method returns an instance of the UserDetailsService interface that can be used to retrieve user details. The implementation of this method may vary depending on the requirements of the application, but typically it involves creating an instance of a class that implements the UserDetailsService interface and configuring it to retrieve user information from a data source.
    //
    //Once the user details service is set up and configured, it can be used by Spring Security to authenticate users and grant access to the application. When a user attempts to log in, their credentials are passed to the user details service, which retrieves the user's details from the data source and checks the password against the stored hash. If the password matches, the user is authenticated and granted access to the application.
    //
    //In summary, the public UserDetailsService userDetailsService(){} method returns an instance of a class that implements the UserDetailsService interface, which is responsible for retrieving user details from a data source in a Spring Security-enabled application.

    @Bean
    public UserDetailsService userDetailsService(){
//        UserDetails normalUser = User.withUsername("akansha").
//                password(passwordEncoder().encode("password"))
//                .roles("NORMAL")
//                .build();
//
//        UserDetails adminUser = User.withUsername("Akansha1")
//                .password(passwordEncoder().encode("password"))
//                .roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(normalUser,adminUser);

//        To Use Databse for Authorization
            return new CustomUserDetailService();
    }

    //This is a method in Java that creates a new instance of the SecurityFilterChain interface and returns it. The SecurityFilterChain interface is a part of Spring Security framework and is responsible for filtering and securing HTTP requests.
    //
    //In this method, an instance of HttpSecurity is passed as a parameter. HttpSecurity is a configuration object in Spring Security that allows developers to define security policies for HTTP requests. By calling methods on the HttpSecurity object, developers can define access rules, authentication mechanisms, and other security-related settings.
    //
    //The first line in this method disables Cross-Site Request Forgery (CSRF) protection by calling the csrf().disable() method on the HttpSecurity object. CSRF protection is a security mechanism that prevents attackers from submitting malicious requests using the credentials of an authenticated user.
    //    The next line calls the authorizeHttpRequests() method to start configuring access rules for the HTTP requests. The commented-out code in this method shows examples of access rules that can be defined using Spring Security. The requestMatchers() method is used to match specific URL patterns and apply access rules to them. For example, the commented-out code defines access rules for URLs that start with /home/admin/, /home/normal, and /home/public.
    //
//  The .hasRole() method is used to restrict access to certain URLs based on the roles assigned to users. In this example, only users with the ADMIN role can access URLs that start with /home/admin/, and only users with the NORMAL role can access URLs that start with /home/normal. URLs that start with /home/public are accessible to all users because the .permitAll() method is called on them.
    //The anyRequest().authenticated() method is used to require authentication for all other URLs that are not explicitly matched by the previous access rules.
    //
    //Finally, the .formLogin() method is called to configure a form-based login mechanism for the application.
    //
    //The method returns an instance of SecurityFilterChain, which represents the security filter chain that should be applied to HTTP requests in the application. This filter chain contains a set of filters that enforce the security policies defined in the HttpSecurity configuration object.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable()
                .authorizeHttpRequests()
//                .requestMatchers("/home/admin/**")
//                .hasRole("ADMIN")
//                .requestMatchers("/home/normal")
//                .hasRole("NORMAL")
//                .requestMatchers("/home/public")
//                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin();

        return httpSecurity.build();

    }
}
