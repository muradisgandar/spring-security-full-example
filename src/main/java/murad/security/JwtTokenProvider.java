package murad.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClock;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import murad.dto.TokenPair;
import murad.dto.TokenType;
import murad.exception.CustomException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {

    /**
     * THIS IS NOT A SECURE PRACTICE! For simplicity, we are storing a static key here. Ideally, in a
     * microservices environment, this key would be kept on a config-server.
     */
    @Value("${security.jwt.token.secret-key}")
    private String secret;

    private final Clock clock = DefaultClock.INSTANCE;

    private Key key;

    @Value("${security.jwt.token.access-expire-length}")
    private long accessValidityInMilliseconds;

    @Value("${security.jwt.token.refresh-expire-length}")
    private long refreshValidityInMilliseconds;

    @Autowired
    private UserDetailServiceImpl userDetailServiceImpl;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    private String createToken(Authentication authentication, TokenType tokenType) {

        org.springframework.security.core.userdetails.User principal = (org.springframework.security.core.userdetails.User) authentication.getPrincipal();

        long expirationDate = TokenType.ACCESS.equals(tokenType) ? accessValidityInMilliseconds : refreshValidityInMilliseconds;

        Claims claims = Jwts.claims().setSubject(principal.getUsername());
        claims.put("auth", principal.getAuthorities());
        claims.put("token type", tokenType.toString());
        Date now = new Date();
        Date validity = new Date(now.getTime() + expirationDate);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public TokenPair createTokenPair(Authentication authentication){
        return TokenPair.builder()
                .access(createToken(authentication, TokenType.ACCESS))
                .refresh(createToken(authentication, TokenType.REFRESH))
                .build();
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailServiceImpl.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody().getSubject();
    }

    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(key).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            throw new CustomException("Expired or invalid JWT token", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
