package com.atz.security.service.impl;

import com.atz.security.entities.UserEntity;
import com.atz.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userEntity = userRepository.findUserEntityByUsername(username).orElseThrow(()->
                new UsernameNotFoundException("El usuario no existe"));

        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        //Agregar roles al usuario
        userEntity.getRoles().forEach(role -> {
            authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name())));
        });

        //Agregar permisos al usuario
        userEntity.getRoles().stream().flatMap(role -> role.getPermissions().stream())
                .forEach(permission -> {
                    authorityList.add(new SimpleGrantedAuthority(permission.getName()));
                });

        return new User(userEntity.getUsername(),
                userEntity.getPassword(),
                userEntity.isEnable(),
                userEntity.isAccountNoExpired(),
                userEntity.isCredentialNoExpired(),
                userEntity.isAccountNoLocked(),
                authorityList);
    }
}
