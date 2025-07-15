package com.auth.be.authBe.auth.dto;

import java.time.ZonedDateTime;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GenSignatureReqDTO {
    private String channelId;
    private String authType;;
    private ZonedDateTime timestamp;
}
