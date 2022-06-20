package com.iam.controller;

import com.iam.model.User;
import com.iam.repo.UserRepository;
import com.iam.service.UserService;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@AllArgsConstructor
@RequestMapping("/api/user")
public class UserController {

    private final UserService service;

    @GetMapping
    public List<User> getUsers() {
        return service.findAll();
    }

    @PostMapping
    public User saveUser(@RequestBody User user) {
        return service.save(user);
    }
}
