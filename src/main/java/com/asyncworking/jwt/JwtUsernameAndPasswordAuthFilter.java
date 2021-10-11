package com.asyncworking.jwt;

import com.asyncworking.dtos.UserInfoDto;
import com.asyncworking.models.UserEntity;
import com.asyncworking.repositories.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDate;
import java.util.Date;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class JwtUsernameAndPasswordAuthFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final SecretKey secretKey;
    private final UserRepository userRepository;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        ServletInputStream inputStream = null;
        AuthenticationRequest authenticationRequest = null;

        try {
            inputStream = request.getInputStream();
            authenticationRequest = new ObjectMapper().readValue(inputStream, AuthenticationRequest.class);
        } catch (Exception e){
            log.error("request inputStream error !!");
        }finally {
            try {
                assert inputStream != null;
                inputStream.close();
            } catch (IOException e) {
                log.error("failed close input stream");
            }
        }

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authenticationRequest.getEmail(),
                authenticationRequest.getPassword()
        );

        return authenticationManager.authenticate(authentication);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) {

        Optional<UserEntity> foundUserEntity = userRepository.findUserEntityByEmail(authResult.getName());
        String name = foundUserEntity.get().getName();
        Long id = foundUserEntity.get().getId();
        String jwtToken = Jwts.builder()
                .setSubject(authResult.getName())
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(1)))
                .signWith(secretKey)
                .compact();

        UserInfoDto userInfoDto = UserInfoDto.builder()
                .id(id)
                .email(authResult.getName())
                .name(name)
                .accessToken(jwtToken)
                .build();
        
        String userInfoDtoString = new Gson().toJson(userInfoDto);
        PrintWriter out = null;
        try{
            out = response.getWriter();
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            out.print(userInfoDtoString);
            out.flush();
        } catch (Exception e){
            log.error("user info io error!!");
        } finally {
            assert out != null;
            out.close();
        }


    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) {
        String message = "Wrong password or user email";
        PrintWriter out = null;
        try {
            out = response.getWriter();
            response.setStatus(401);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            out.print(message);
            out.flush();
        }catch (Exception e){
            log.error("unsuccessfulAuthentication response io error!!");
        }finally {
            assert out != null;
            out.close();
        }


    }
}
