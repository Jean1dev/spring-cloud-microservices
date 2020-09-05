package com.poc.microservices.curso.model;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class ApplicationUser implements AbstractEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    @NotNull(message = "o userName nao pode ser null")
    @Column(nullable = false)
    private String userName;

    @NotNull(message = "o password nao pode ser null")
    @Column(nullable = false)
    private String password;

    @NotNull(message = "o role nao pode ser null")
    @Column(nullable = false)
    private String role;

    @Override
    public Long getId() {
        return id;
    }

    public static ApplicationUser copy(ApplicationUser applicationUser) {
        return ApplicationUser.builder()
                .id(applicationUser.getId())
                .role(applicationUser.getRole())
                .userName(applicationUser.getUserName())
                .password(applicationUser.getPassword())
                .build();
    }
}
