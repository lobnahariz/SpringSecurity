package com.lobna.security.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo-controller")
public class DemoController {

    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello World");
    }
}
