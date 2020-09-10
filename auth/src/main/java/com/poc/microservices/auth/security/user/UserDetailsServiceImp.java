package com.poc.microservices.auth.security.user;

import com.poc.microservices.curso.model.ApplicationUser;
import com.poc.microservices.curso.repository.ApplicationUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Objects;

@Service
public class UserDetailsServiceImp implements UserDetailsService {

    @Autowired
    private ApplicationUserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        ApplicationUser applicationUser = repository.findByuserName(userName);

        if (Objects.isNull(applicationUser)) {
            throw new UsernameNotFoundException("user nao existe");
        }

        return CustomUserDetails.of(applicationUser);
    }

    private static final class CustomUserDetails extends ApplicationUser implements UserDetails {

        private CustomUserDetails() {
        }

        public static CustomUserDetails of(ApplicationUser applicationUser) {
            CustomUserDetails details = new CustomUserDetails();
            details.setId(applicationUser.getId());
            details.setPassword(applicationUser.getPassword());
            details.setUserName(applicationUser.getUserName());
            details.setRole(applicationUser.getRole());
            return details;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_" + this.getRole());
        }

        @Override
        public String getUsername() {
            return null;
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}
