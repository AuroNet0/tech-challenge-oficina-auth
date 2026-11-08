FROM maven:3.9.9-eclipse-temurin-21@sha256:3a4ab3276a087bf276f79cae96b1af04f53731bec53fb2e651aca79e4b10211e AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B -ntp dependency:go-offline
COPY src/main src/main
RUN mvn -B -ntp -Dmaven.test.skip=true package

FROM eclipse-temurin:21-jre-jammy@sha256:1eac8b8fee11ca7d6725a48bc5d41992ed1561504ebae25490d2d062847e8269
WORKDIR /app
RUN groupadd --gid 10001 auth && useradd --uid 10001 --gid auth --no-create-home auth
COPY --from=build --chown=10001:10001 /build/target/tech-challenge-oficina-auth.jar /app/app.jar
USER 10001:10001
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=60 -XX:ActiveProcessorCount=2 -XX:+ExitOnOutOfMemoryError"
EXPOSE 8443
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=8s --start-period=30s --retries=3 CMD ["java", "-cp", "/app/app.jar", "br.com.fiap.oficina.auth.infrastructure.internal.InternalHealthProbe"]
ENTRYPOINT ["java", "-cp", "/app/app.jar", "br.com.fiap.oficina.auth.infrastructure.internal.InternalAuthMain"]
