package com.learnfromscratch.backend.controller;

import com.learnfromscratch.backend.model.User;
import com.learnfromscratch.backend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // ✅ Allow only logged-in user to update their own profile
    @PutMapping("/update")
    public ResponseEntity<?> updateUser(@RequestBody Map<String, String> request, Authentication auth) {
        // The authenticated username from JWT
        String loggedInUsername = auth != null ? auth.getName() : null;

        if (loggedInUsername == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized: please log in again"));
        }

        String oldUsername = request.get("oldUsername");
        String newUsername = request.get("username");
        String newEmail = request.get("email");
        String newPassword = request.get("password");

        if ((newEmail == null || newEmail.isBlank()) &&
                (newPassword == null || newPassword.isBlank()) &&
                (newUsername == null || newUsername.equals(oldUsername))) {
            return ResponseEntity.badRequest().body(Map.of("error", "No fields to update"));
        }

        // ✅ Ensure users can update only their own profiles
        if (!loggedInUsername.equals(oldUsername)) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied: cannot modify another user's profile"));
        }

        Optional<User> optionalUser = userRepository.findByUsername(oldUsername);
        if (optionalUser.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "User not found"));
        }

        User user = optionalUser.get();

        if (newUsername != null && !newUsername.equals(oldUsername)) {
            // Prevent duplicates
            if (userRepository.findByUsername(newUsername).isPresent()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Username already taken"));
            }
            user.setUsername(newUsername);
        }

        if (newEmail != null && !newEmail.isBlank()) {
            user.setEmail(newEmail);
        }

        if (newPassword != null && !newPassword.isBlank()) {
            user.setPassword(passwordEncoder.encode(newPassword));
        }

        userRepository.save(user);

        return ResponseEntity.ok(Map.of(
                "message", "Profile updated successfully!",
                "username", user.getUsername()
        ));
    }
}
