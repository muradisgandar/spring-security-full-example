package murad.service;

import javax.servlet.http.HttpServletRequest;

import murad.dto.LoginRequest;
import murad.dto.TokenPair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import murad.exception.CustomException;
import murad.model.User;
import murad.repository.UserRepository;
import murad.security.JwtTokenProvider;

import java.util.stream.Collectors;

@Service
public class UserService {

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Autowired
  private JwtTokenProvider jwtTokenProvider;

  @Autowired
  private AuthenticationManager authenticationManager;

  public TokenPair login(LoginRequest loginRequest) {
    try {
      Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

      return jwtTokenProvider.createTokenPair(authenticate);

    } catch (AuthenticationException e) {
      throw new CustomException("Invalid username/password supplied", HttpStatus.UNPROCESSABLE_ENTITY);
    }
  }

  public TokenPair register(User user) {
    if (!userRepository.existsByUsername(user.getUsername())) {
      user.setPassword(passwordEncoder.encode(user.getPassword()));
      User savedUser = userRepository.save(user);

      UserDetails userDetails = org.springframework.security.core.userdetails.User//
              .withUsername(savedUser.getUsername())//
              .password(savedUser.getPassword())//
              .authorities(savedUser.getRoles())//
              .accountExpired(false)//
              .accountLocked(false)//
              .credentialsExpired(false)//
              .disabled(false)//
              .build();

      Authentication usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());

      TokenPair tokenPair = jwtTokenProvider.createTokenPair(usernamePasswordAuthenticationToken);

      SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

      return tokenPair;
    } else {
      throw new CustomException("Username is already in use", HttpStatus.UNPROCESSABLE_ENTITY);
    }
  }

  public void delete(String username) {
    userRepository.deleteByUsername(username);
  }

  public User search(String username) {
    User user = userRepository.findByUsername(username);
    if (user == null) {
      throw new CustomException("The user doesn't exist", HttpStatus.NOT_FOUND);
    }
    return user;
  }

  public User whoami(HttpServletRequest req) {
    return userRepository.findByUsername(jwtTokenProvider.getUsername(jwtTokenProvider.resolveToken(req)));
  }

  public TokenPair refresh(String refreshToken) {

    if(jwtTokenProvider.validateToken(refreshToken)){
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      return jwtTokenProvider.createTokenPair(authentication);
    }
    else{
      throw new RuntimeException("Token is not valid");
    }
  }

}
