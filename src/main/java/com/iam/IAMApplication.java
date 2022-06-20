package com.iam;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

@SpringBootApplication
@EnableMongoRepositories
public class IAMApplication {
	public static void main(String[] args) {
		SpringApplication.run(IAMApplication.class, args);
	}
}
