package com.wissen.springsecurity.services;

import com.wissen.springsecurity.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {
    private final String SECRET_KEY = "51b8c07e7bf73adba136762d51acae4863d5988969bc3b584edf0998ef409f37";
    public String generateToken(User user){
        return Jwts.builder()
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+24*60*60*1000))
                .signWith(getSignedKey())
                .compact();
    }

    public boolean isValid(String token, UserDetails user){
        String username = extractUserName(token);
        return (user.getUsername().equals(username)&&!isTokenExpired(token));

    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String extractUserName(String token){
        return extractClaim(token, Claims::getSubject);
    }
    private  <T> T extractClaim(String token, Function<Claims, T> resolver){
        Claims claims = extactAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extactAllClaims(String token){
        return Jwts.parser()
                .verifyWith(getSignedKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignedKey(){
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);

    }


}
