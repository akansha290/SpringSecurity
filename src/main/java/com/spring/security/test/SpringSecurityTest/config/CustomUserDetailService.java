package com.spring.security.test.SpringSecurityTest.config;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailService implements UserDetailsService {

    //This is a method in Java that returns an instance of the UserDetails interface. The UserDetails interface is a part of Spring Security framework and provides user information, such as username, password, and authorities, that can be used to authenticate and authorize users in a Spring Security-enabled application.
    //
    //The method takes a String parameter username, which is the username of the user whose details are being requested. If the user with the given username is not found, the method throws a UsernameNotFoundException.
    //
    //In the provided code, the method simply returns null. This means that it does not implement the functionality of retrieving user details from any data source, such as a database or LDAP server.
    //    Typically, the implementation of this method would involve retrieving the user details from a data source and returning an instance of the UserDetails interface that represents the user. The returned UserDetails object would contain information such as the user's password and authorities.
    //
    //    The implementation of the loadUserByUsername() method can vary depending on the requirements of the application. For example, if the application stores user information in a database, the implementation may use a JDBC connection to retrieve user details from the database.
    //
    //    Once the user details have been retrieved, they can be used by Spring Security to authenticate users and grant access to the application. When a user attempts to log in, their credentials are passed to the user details service, which retrieves the user's details from the data source and checks the password against the stored hash. If the password matches, the user is authenticated and granted access to the application.
    //In summary, the loadUserByUsername() method is responsible for retrieving user details from a data source and returning an instance of the UserDetails interface that represents the user. This method is typically implemented to retrieve user details from a database or LDAP server in a Spring Security-enabled application.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return null;
    }
}
