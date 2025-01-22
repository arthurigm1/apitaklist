package com.logintodolist.logintodolist.Controller;

import com.logintodolist.logintodolist.Infra.Security.TokenService;
import com.logintodolist.logintodolist.Model.Usuario;
import com.logintodolist.logintodolist.Repository.UsuarioRepository;
import com.logintodolist.logintodolist.dto.LoginRequestdto;
import com.logintodolist.logintodolist.dto.RegisterRequesrdto;
import com.logintodolist.logintodolist.dto.ResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private final UsuarioRepository usuarioRepository;
    @Autowired
    private final PasswordEncoder passwordEncoder;
    @Autowired
    private final TokenService tokenService;

    @Autowired
    public AuthController(
            UsuarioRepository usuarioRepository,
            PasswordEncoder passwordEncoder,
            TokenService tokenService
    ) {
        this.usuarioRepository = usuarioRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestdto loginRequestdto) {
        Usuario usuario = this.usuarioRepository.findByEmail(loginRequestdto.email()).orElseThrow(() -> new RuntimeException("Usuario nao encontrado"));
        if (passwordEncoder.matches(loginRequestdto.password(), usuario.getSenha())) {
            String token = tokenService.generateToken(usuario);
            return ResponseEntity.ok(new ResponseDto(usuario.getNome(), token));
        }
        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequesrdto registerbody) {
        Optional<Usuario> usuario = this.usuarioRepository.findByEmail(registerbody.email());
        if (usuario.isPresent()) {
            return ResponseEntity.badRequest().body("Usuário já existe com este e-mail");
        }

        Usuario usuario1 = new Usuario();
        usuario1.setSenha(passwordEncoder.encode(registerbody.password()));
        usuario1.setEmail(registerbody.email());
        usuario1.setNome(registerbody.name());
        this.usuarioRepository.save(usuario1);

        String token = tokenService.generateToken(usuario1);
        return ResponseEntity.ok(new ResponseDto(usuario1.getNome(), token));
    }
}
