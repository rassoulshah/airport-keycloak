package com.airport.bookings.feignclients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.airport.bookings.config.FeignClientInterceptor;
import com.airport.bookings.response.FlightResponse;

@FeignClient(value = "api-gateway/airport-flight-service", configuration = FeignClientInterceptor.class)
public interface FlightFeignClient {

    @GetMapping("/api/v1/flights/{id}")
    public ResponseEntity<FlightResponse> getFlightById(@PathVariable Long id);
}