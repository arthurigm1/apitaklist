package com.logintodolist.logintodolist.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UsuarioController {

    @GetMapping("")
    public ResponseEntity<String> getUsuario() {

        return ResponseEntity.ok("Usuario");
    }
}
