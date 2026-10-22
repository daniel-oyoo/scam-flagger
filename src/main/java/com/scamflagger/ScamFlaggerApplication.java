package com.scamflagger;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class ScamFlaggerApplication {
    public static void main(String[] args) {
        boolean migration = java.util.Arrays.stream(args)
                .anyMatch(argument -> argument.startsWith("--app.migrate-sqlite-from="));
        SpringApplication application = new SpringApplication(ScamFlaggerApplication.class);
        if (migration) {
            application.setWebApplicationType(WebApplicationType.NONE);
        }
        ConfigurableApplicationContext context = application.run(args);
        if (migration) {
            System.exit(SpringApplication.exit(context));
        }
    }
}
