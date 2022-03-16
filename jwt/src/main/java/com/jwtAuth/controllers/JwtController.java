package com.jwtAuth.controllers;

import com.jwtAuth.helper.JwtUtil;
import com.jwtAuth.models.JwtReq;
import com.jwtAuth.models.JwtRes;
import com.jwtAuth.services.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin
public class JwtController {
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @PostMapping("/token")
    public ResponseEntity<?> generateToken(@RequestBody JwtReq jwtReq) throws Exception {
        System.out.println(jwtReq);
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jwtReq.getUsername(),jwtReq.getPassword()));
        }
        catch (UsernameNotFoundException e) {
            throw new Exception("Bad Credential");
        }
        UserDetails userDetails= customUserDetailsService.loadUserByUsername(jwtReq.getUsername());
        String token=this.jwtUtil.generateToken(userDetails);
        System.out.println(token);

        return ResponseEntity.ok(new JwtRes(token));
    }
    @GetMapping("/data")
    public String welcome() {
        String text="This is private page";
        return text;

    }

}
