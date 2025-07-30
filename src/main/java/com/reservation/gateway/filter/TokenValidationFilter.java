package com.reservation.gateway.filter;

import com.reservation.gateway.jwt.JwtValidator;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenValidationFilter implements GlobalFilter, Ordered {

    private final JwtValidator jwtValidator;

    // 공개 경로 설정
    private final Set<String> publicPaths = Set.of(
            "/auth/api/v1/login",
            "/auth/api/v1/register",
            "/health",
            "/login",
            "/register",
            "/reserve/api/concerts"
    );

    // 보호된 경로 설정 (토큰 필수)
    private final Set<String> protectedPaths = Set.of(
            "/user",
            "/admin",
            "/auth/api/v1/logout",
            "/reserve/api/reservations"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        log.info("[TokenValidationFilter] 요청 경로: {}", path);

        // 토큰 추출 및 로그 출력
        String token = extractToken(exchange.getRequest());
        log.info("[TokenValidationFilter] 가져온 토큰: {}", token);

        // 1. 공개 경로 체크
        if (isPublicPath(path)) {
            log.info("Public path accessed: {}", path);
            return chain.filter(exchange);
        }

        // 2. 보호된 경로 체크
        if (isProtectedPath(path)) {
            log.info("Protected path accessed: {}", path);
            return handleProtectedPath(exchange, chain);
        }

        // 3. 조건부 경로 (토큰 있으면 검증, 없으면 게스트)
        log.info("Conditional path accessed: {}", path);
        return handleConditionalPath(exchange, chain);
    }

    // 토큰 추출 로직 개선 (쿠키 + 헤더 지원)
    private String extractToken(ServerHttpRequest request) {
        // 1. Authorization 헤더에서 토큰 추출
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        // 2. 쿠키에서 토큰 추출
        List<HttpCookie> cookies = request.getCookies().get("accessToken");
        if (cookies != null && !cookies.isEmpty()) {
            return cookies.get(0).getValue();
        }

        return null;
    }

    // 보호된 경로 처리 (토큰 필수)
    private Mono<Void> handleProtectedPath(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String token = extractToken(request);

        if (token == null) {
            return handleUnauthorized(exchange, "로그인이 필요합니다");
        }

        try {
            Claims claims = jwtValidator.validateToken(token);
            return addUserInfoAndContinue(exchange, chain, claims);
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return handleUnauthorized(exchange, "유효하지 않은 토큰입니다");
        }
    }

    // 조건부 경로 처리 (토큰 선택적)
    private Mono<Void> handleConditionalPath(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String token = extractToken(request);

        if (token == null) {
            // 토큰이 없으면 게스트로 처리
            return addGuestInfoAndContinue(exchange, chain);
        }

        try {
            Claims claims = jwtValidator.validateToken(token);
            return addUserInfoAndContinue(exchange, chain, claims);
        } catch (Exception e) {
            log.warn("Token validation failed, proceeding as guest: {}", e.getMessage());
            // 토큰이 유효하지 않으면 게스트로 처리
            return addGuestInfoAndContinue(exchange, chain);
        }
    }

    private boolean isPublicPath(String path) {
        return publicPaths.stream()
                .anyMatch(publicPath -> path.startsWith(publicPath));
    }

    private boolean isProtectedPath(String path) {
        return protectedPaths.stream()
                .anyMatch(protectedPath -> path.startsWith(protectedPath));
    }

    private Mono<Void> addUserInfoAndContinue(ServerWebExchange exchange, GatewayFilterChain chain, Claims claims) {
        String roles = extractRoles(claims);
        String token = extractToken(exchange.getRequest()); // 토큰 다시 추출

        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                .header("X-User-Id", claims.getSubject())
                .header("X-User-Roles", roles)
                .header("X-User-Status", "AUTHENTICATED")
                .headers(headers -> {
                    headers.remove("Cookie");
                    headers.add("Authorization", "Bearer " + token);
                })
                .build();

        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }



    private Mono<Void> addGuestInfoAndContinue(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                .header("X-User-Status", "GUEST")
                .build();

        log.debug("Processing as guest user");
        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    private String extractRoles(Claims claims) {
        Object rolesObj = claims.get("roles");

        if (rolesObj instanceof String) {
            return (String) rolesObj;
        } else if (rolesObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> rolesList = (List<String>) rolesObj;
            return String.join(",", rolesList);
        }

        return "USER"; // 기본값
    }

    private Mono<Void> handleUnauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add("Content-Type", "application/json; charset=utf-8");

        String body = String.format(
                "{\"error\":\"Unauthorized\",\"message\":\"%s\",\"timestamp\":%d}",
                message, System.currentTimeMillis()
        );

        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return 1;
    }
}
