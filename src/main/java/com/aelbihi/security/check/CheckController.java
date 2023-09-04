package com.aelbihi.security.check;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/check/")
public class CheckController {

    @GetMapping()
    public ResponseEntity<String> sayHello(){
        return ResponseEntity.ok("hello the jwt concept");
    }
}
