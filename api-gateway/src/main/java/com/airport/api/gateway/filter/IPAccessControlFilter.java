package com.airport.api.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

@Component
public class IPAccessControlFilter implements GlobalFilter, Ordered {

    private static final Logger logger = LoggerFactory.getLogger(IPAccessControlFilter.class);

    @Value("${gateway.security.allowed-ips:}")
    private String allowedIps;

    @Value("${gateway.security.blocked-ips:}")
    private String blockedIps;

    @Value("${gateway.security.ip-filter-enabled:true}")
    private boolean ipFilterEnabled;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!ipFilterEnabled) {
            return chain.filter(exchange);
        }

        String clientIp = getClientIP(exchange);
        logger.info("Processing request from IP: {}", clientIp);

        // Check if IP is blocked
        if (isBlocked(clientIp)) {
            logger.warn("Blocked request from IP: {}", clientIp);
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        // Check if IP is allowed (if allowlist is configured)
        if (!isAllowed(clientIp)) {
            logger.warn("Unauthorized request from IP: {}", clientIp);
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        logger.info("Allowing request from IP: {}", clientIp);
        return chain.filter(exchange);
    }

    private String getClientIP(ServerWebExchange exchange) {
        // Check X-Forwarded-For header first
        String xForwardedFor = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            String ip = xForwardedFor.split(",")[0].trim();
            logger.debug("IP from X-Forwarded-For: {}", ip);
            return ip;
        }

        // Check X-Real-IP header
        String xRealIP = exchange.getRequest().getHeaders().getFirst("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty()) {
            logger.debug("IP from X-Real-IP: {}", xRealIP);
            return xRealIP;
        }

        // Get remote address
        String remoteAddr = exchange.getRequest().getRemoteAddress() != null ?
                exchange.getRequest().getRemoteAddress().getAddress().getHostAddress() : "unknown";
        logger.debug("IP from RemoteAddress: {}", remoteAddr);
        return remoteAddr;
    }

    private boolean isBlocked(String ip) {
        if (blockedIps == null || blockedIps.isEmpty()) {
            return false;
        }

        List<String> blockedList = Arrays.asList(blockedIps.split(","));
        boolean blocked = blockedList.stream().anyMatch(blockedIp ->
                ip.equals(blockedIp.trim()) || isIPInRange(ip, blockedIp.trim()));

        if (blocked) {
            logger.info("IP {} is in blocked list", ip);
        }
        return blocked;
    }

    private boolean isAllowed(String ip) {
        if (allowedIps == null || allowedIps.isEmpty()) {
            logger.debug("No allowed IPs configured, allowing IP: {}", ip);
            return true; // If no allowlist is configured, allow all (except blocked)
        }

        List<String> allowedList = Arrays.asList(allowedIps.split(","));
        boolean allowed = allowedList.stream().anyMatch(allowedIp ->
                ip.equals(allowedIp.trim()) || isIPInRange(ip, allowedIp.trim()));

        logger.info("IP {} is {} in allowed list", ip, allowed ? "found" : "not found");
        return allowed;
    }

    private boolean isIPInRange(String ip, String range) {
        // Wildcard support (e.g., 192.168.1.*)
        if (range.contains("*")) {
            String pattern = range.replace(".", "\\.");
            pattern = pattern.replace("*", ".*");
            boolean matches = ip.matches(pattern);
            logger.debug("Checking IP {} against wildcard pattern {}: {}", ip, range, matches);
            return matches;
        }

        // CIDR notation support (e.g., 192.168.1.0/24)
        if (range.contains("/")) {
            try {
                String[] parts = range.split("/");
                String networkIP = parts[0];
                int prefixLength = Integer.parseInt(parts[1]);

                boolean inCIDR = isIPInCIDR(ip, networkIP, prefixLength);
                logger.debug("Checking IP {} against CIDR {}: {}", ip, range, inCIDR);
                return inCIDR;
            } catch (Exception e) {
                logger.error("Error parsing CIDR notation: {}", range, e);
                return false;
            }
        }

        // Exact match
        return ip.equals(range);
    }

    private boolean isIPInCIDR(String ip, String networkIP, int prefixLength) {
        try {
            long ipLong = ipToLong(ip);
            long networkLong = ipToLong(networkIP);
            long mask = (-1L << (32 - prefixLength)) & 0xFFFFFFFFL;

            return (ipLong & mask) == (networkLong & mask);
        } catch (Exception e) {
            logger.error("Error checking CIDR range", e);
            return false;
        }
    }

    private long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result += Long.parseLong(parts[i]) << (24 - (8 * i));
        }
        return result & 0xFFFFFFFFL;
    }

    @Override
    public int getOrder() {
        return -2; // Execute before method filter and other filters
    }
}