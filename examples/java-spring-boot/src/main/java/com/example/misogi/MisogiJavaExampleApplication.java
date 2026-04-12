package com.example.misogi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Misogi Java Spring Boot gRPC Client — Entry Point.
 *
 * <p>This application demonstrates how to integrate with the Misogi CDR engine
 * via gRPC from a Spring Boot 3.x environment. It exposes both a programmatic
 * client API ({@link com.example.misogi.client.MisogiGrpcClient}) and an
 * optional REST controller ({@link com.example.misogi.controller.DemoController})
 * that bridges HTTP requests to gRPC calls.</p>
 *
 * <h2>Startup Sequence</h2>
 * <ol>
 *   <li>Spring context loads {@code application.yml}</li>
 *   <li>{@link com.example.misogi.service.FileUploadService} initialises the
 *       gRPC {@code ManagedChannel} in {@code @PostConstruct}</li>
 *   <li>REST endpoints become available on port 8080</li>
 * </ol>
 *
 * @see com.example.misogi.client.MisogiGrpcClient
 * @see com.example.misogi.service.FileUploadService
 */
@SpringBootApplication
public class MisogiJavaExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(MisogiJavaExampleApplication.class, args);
    }
}
