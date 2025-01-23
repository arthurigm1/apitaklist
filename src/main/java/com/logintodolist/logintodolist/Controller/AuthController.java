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
    public ResponseEntity<?> login(@RequestBody LoginRequestdto loginRequestdto) {
        // Buscar o usuário pelo e-mail
        Optional<Usuario> usuarioOptional = this.usuarioRepository.findByEmail(loginRequestdto.email());
        // Verifica se o usuário foi encontrado
        if (usuarioOptional.isEmpty()) {
            // Caso o e-mail não exista, retorna erro
            return ResponseEntity.badRequest().body("Usuário não encontrado.");
        }
        Usuario user = usuarioOptional.get();  // Obtém o usuário encontrado
        // Verifica se a senha está correta
        if (!passwordEncoder.matches(loginRequestdto.password(), user.getSenha())) {
            // Se a senha não for válida, retorna erro
            return ResponseEntity.badRequest().body("Senha incorreta.");
        }
        // Gera o token se o usuário e a senha estiverem corretos
        String token = tokenService.generateToken(user);
        // Retorna a resposta com o token e o nome do usuário
        return ResponseEntity.ok(new ResponseDto(user.getNome(), token));
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
