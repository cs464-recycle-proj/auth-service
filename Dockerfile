FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /app

COPY pom.xml . 
COPY src ./src
COPY mvnw . 
COPY .mvn ./.mvn

RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

ARG JAR_FILE=target/auth-service-0.0.1-SNAPSHOT.jar
COPY --from=builder /app/${JAR_FILE} app.jar

EXPOSE 8081

CMD ["java", "-jar", "app.jar"]
