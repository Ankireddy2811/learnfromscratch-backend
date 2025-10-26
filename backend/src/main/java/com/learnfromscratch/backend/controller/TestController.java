package com.learnfromscratch.backend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/api/public/test")
    public String test() {
        return "Backend is running successfully";
    }
}
