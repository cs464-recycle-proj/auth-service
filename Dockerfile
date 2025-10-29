# ===== Stage 1: Build =====
# Use Eclipse Temurin JDK 21 for building the application
FROM eclipse-temurin:21-jdk-alpine AS builder

# Set working directory for the build stage
WORKDIR /app

# Copy Maven configuration and wrapper files
COPY pom.xml .
COPY mvnw .
COPY .mvn ./.mvn
COPY src ./src

# Make mvnw executable
RUN chmod +x mvnw

# Build the application (skip tests for faster build times in Docker)
RUN ./mvnw clean package -DskipTests

# ===== Stage 2: Run =====
# Use Eclipse Temurin JRE 21 for running the application (smaller image)
FROM eclipse-temurin:21-jre-alpine

# Set working directory for runtime
WORKDIR /app

# Create a non-root user for security
RUN addgroup -S spring && adduser -S spring -G spring

# Copy the built JAR from the builder stage
COPY --from=builder /app/target/*.jar app.jar

# Change ownership to non-root user
RUN chown -R spring:spring /app

# Switch to non-root user
USER spring:spring

# Expose the port used by the Auth Service
EXPOSE 8081

# Add container health check for monitoring
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8081/actuator/health || exit 1

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]