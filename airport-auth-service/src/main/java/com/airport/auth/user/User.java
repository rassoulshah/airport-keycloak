package com.airport.auth.user;

import javax.persistence.*;
import lombok.*;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    private String roles; // e.g. ROLE_USER,ROLE_ADMIN

    @Builder.Default
    @Column(nullable = false)
    private boolean enabled = true; 
}
