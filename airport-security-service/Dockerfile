# Multi-stage build
# Stage 1: Build the application
FROM openjdk:11-jdk-slim as builder

# Install Maven
RUN apt-get update && \
    apt-get install -y maven && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy pom.xml first for better Docker layer caching
COPY pom.xml .

# Download dependencies (this layer will be cached if pom.xml doesn't change)
RUN mvn dependency:go-offline -B

# Copy source code
COPY src src

# Build the application
RUN mvn clean package -DskipTests

# Stage 2: Create the runtime image
FROM openjdk:11-jre-slim

# Set working directory
WORKDIR /app

# Expose the port
EXPOSE 8084

# Copy the jar file from builder stage
COPY --from=builder /app/target/airport-security-service-0.0.1-SNAPSHOT.jar airport-security-service-0.0.1-SNAPSHOT.jar

# Set the entry point
ENTRYPOINT ["java", "-jar", "airport-security-service-0.0.1-SNAPSHOT.jar"]