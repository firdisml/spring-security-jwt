package com.rolex.security.config;


import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.Key;

@Component
@RequiredArgsConstructor
public class JwtSigningKey {
    public Key getSigningKey(){
        byte[] keyBytes = Decoders.BASE64.decode("D+5++C1HWFblN4+usXHShGPBKJGZJr3kFNCAK2usTu862SfES/wE6mV43U5FR+2x1");
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
