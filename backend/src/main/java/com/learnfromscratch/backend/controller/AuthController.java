package com.learnfromscratch.backend.controller;

import com.learnfromscratch.backend.model.User;
import com.learnfromscratch.backend.dto.AuthResponse;
import com.learnfromscratch.backend.service.AuthService;
import com.learnfromscratch.backend.security.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtUtil;

    // ✅ Register endpoint
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        try {
            authService.registerUser(user);
            return ResponseEntity.ok(Map.of("message", "User registered successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ✅ Login endpoint (sets refresh cookie)
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody User user, HttpServletResponse response) {
        String result = authService.loginUser(user.getUsername(), user.getPassword());

        if (result.equals("Login successful!")) {
            String accessToken = jwtUtil.generateToken(user.getUsername(), "USER");
            String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

            // ⬇️ Store refresh token in HttpOnly cookie (valid for 7 days)
            Cookie refreshCookie = new Cookie("jwt", refreshToken);
            refreshCookie.setHttpOnly(true);
            refreshCookie.setSecure(false); // ⚠️ set true in production (HTTPS)
            refreshCookie.setPath("/");
            refreshCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
            response.addCookie(refreshCookie);

            return ResponseEntity.ok(new AuthResponse(accessToken, user.getUsername(), "USER"));
        }

        return ResponseEntity.badRequest().body(Map.of("error", result));
    }

    // ✅ Refresh endpoint — issues new access token from cookie
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@CookieValue(value = "jwt", required = false) String refreshToken) {
        if (refreshToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "No refresh token"));
        }

        try {
            String username = jwtUtil.extractUsername(refreshToken);
            if (jwtUtil.validateToken(refreshToken)) {

                String newAccessToken = jwtUtil.generateToken(username, "USER");
                return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
            } else {
                return ResponseEntity.status(401).body(Map.of("error", "Invalid refresh token"));
            }
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid or expired refresh token"));
        }
    }

    // ✅ Forgot password (no email sending)
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String newPassword = request.get("newPassword");
        try {
            String message = authService.updatePasswordByEmail(email, newPassword);
            return ResponseEntity.ok(Map.of("message", message));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ✅ Logout endpoint (clears cookie)
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("jwt", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/api/auth/refresh");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}
