package com.airport.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan({ "com.airport.auth.controller", "com.airport.auth.service", "com.airport.auth.config"})
@EnableEurekaClient
public class AirportAuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AirportAuthServiceApplication.class, args);
	}
}