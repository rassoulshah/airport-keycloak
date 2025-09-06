package com.airport.bookings.config;

import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import feign.RequestInterceptor;
import feign.RequestTemplate;

@Component
public class FeignClientInterceptor implements RequestInterceptor {

    @Override
    public void apply(RequestTemplate requestTemplate) {
        ServletRequestAttributes requestAttributes = 
            (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        
        if (requestAttributes != null) {
            String authorization = requestAttributes.getRequest().getHeader("Authorization");
            if (authorization != null) {
                requestTemplate.header("Authorization", authorization);
            }
        }
    }
}