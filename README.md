#  API Gateway

## 📖 프로젝트 소개

예약 시스템을 위한 API 게이트웨이입니다. Spring Cloud Gateway를 기반으로 구축되었으며, 마이크로서비스로 들어오는 요청을 적절한 서비스로 라우팅하는 역할을 담당합니다. 또한 모든 클라이언트의 단일 진입점(Single Point of Entry) 역할을 하며, 인증, 로깅, 속도 제한 등과 같은 공통 기능을 처리합니다.

이 게이트웨이는 JWT(JSON Web Token)를 사용하여 인증을 수행합니다. 토큰의 유효성을 검증하고, 다운스트림 서비스로 요청을 전달하기 전에 사용자 정보를 요청 헤더에 추가합니다.

## ✨ 주요 기능

- **✅ 서비스 라우팅:** 경로(Path) 기반으로 마이크로서비스에 대한 요청을 라우팅합니다.
- **🔐 인증:** JWT를 검증하여 엔드포인트를 보호합니다.
- **👤 사용자 컨텍스트:** 사용자 ID 및 역할을 요청 헤더(`X-User-Id`, `X-User-Roles`)에 추가합니다.
- **🌐 동적 라우팅:** Eureka와의 연동을 통해 서비스를 동적으로 탐색하고 라우팅합니다.
- **📊 모니터링:** Actuator 엔드포인트를 통해 상태 확인 및 모니터링 기능을 제공합니다.

## 🛠️ 기술 스택

- Java 17
- Spring Boot 3
- Spring Cloud Gateway
- Spring Security
- Netflix Eureka
- JJWT (Java JWT)
- Lombok
- Gradle

## ⚙️ 실행 전 요구사항

- Java 17 이상
- Gradle
- Eureka 서버 실행 중
- Redis 실행 중

## 🚀 시작하기

### 📦 프로젝트 빌드

터미널에서 다음 명령어를 실행하여 프로젝트를 빌드합니다.

```bash
./gradlew build
```

### ▶️ 프로젝트 실행

다음 명령어를 사용하여 프로젝트를 실행할 수 있습니다.

```bash
./gradlew bootRun
```

기본적으로 애플리케이션은 `8080` 포트에서 시작됩니다.

## 🔧 설정

주요 설정은 `src/main/resources/application.yml` 파일에서 관리합니다.

- **서버 포트:** `server.port`
- **Eureka:** `eureka.client.service-url.defaultZone`
- **JWT Secret Key:** `jwt.secret`
- **라우팅 정보:** `spring.cloud.gateway.routes`

## 🔐 인증 흐름

1.  게이트웨이는 모든 들어오는 요청을 가로챕니다.
2.  요청 경로가 **공개(Public)**, **보호(Protected)**, **조건부(Conditional)** 중 어디에 해당하는지 확인합니다.
    -   **Public Paths:** 토큰 없이 요청을 허용합니다.
    -   **Protected Paths:** 유효한 JWT가 필수입니다. 토큰이 없거나 유효하지 않으면 `401 Unauthorized` 오류를 반환합니다.
    -   **Conditional Paths:** 토큰이 있고 유효하면 사용자 정보를 요청에 추가합니다. 토큰이 없거나 유효하지 않으면 게스트 요청으로 처리합니다.
3.  인증된 사용자의 경우, `TokenValidationFilter`가 다운스트림 서비스로 요청을 전달하기 전에 다음 헤더를 추가합니다.
    -   `X-User-Id`: JWT의 `subject`에서 추출한 사용자 ID
    -   `X-User-Roles`: JWT의 `claims`에서 추출한 사용자 역할
    -   `X-User-Status`: `AUTHENTICATED`
