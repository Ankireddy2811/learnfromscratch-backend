package com.learnfromscratch.backend.service;

import com.learnfromscratch.backend.model.User;
import com.learnfromscratch.backend.repository.UserRepository;
import com.learnfromscratch.backend.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    // 🟢 Registration logic
    public String registerUser(User user) {
        Optional<User> existingUserWithName = userRepository.findByUsername(user.getUsername());
        if (existingUserWithName.isPresent()) {
            throw new RuntimeException("User Name already exists!");
        }

        Optional<User> existingUserWithEmail = userRepository.findByEmail(user.getEmail());
        if (existingUserWithEmail.isPresent()) {
            throw new RuntimeException("Email already exists!");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (user.getRole() == null) {
            user.setRole("USER");
        }
        userRepository.save(user);
        return "User registered successfully!";
    }

    // 🟢 Login logic (based on username)
    public String loginUser(String username, String password) {
        Optional<User> userOpt = userRepository.findByUsername(username); // ✅ changed to username
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            if (passwordEncoder.matches(password, user.getPassword())) {
                return "Login successful!";
            } else {
                return "Invalid password!";
            }
        } else {
            return "User not found!";
        }
    }

    public String updatePasswordByEmail(String email, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("No user found with that email"));
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        return "Password updated successfully!";
    }
}
