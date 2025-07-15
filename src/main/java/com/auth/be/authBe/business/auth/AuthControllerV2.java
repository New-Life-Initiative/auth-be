package com.auth.be.authBe.business.auth;

import com.auth.be.authBe.auth.dto.*;
import com.auth.be.authBe.business.auth.model.*;
import com.auth.be.authBe.business.auth.service.AuthServiceV2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v2/auth")
@CrossOrigin(origins = "*")
public class AuthControllerV2 {
    @Autowired
    private AuthServiceV2 authServiceV2;

    @PostMapping("/generate/signature-access-token")
    public SignatureRes generateSignatureAccessToken(@RequestBody GenSignatureAccReq input) {
        return authServiceV2.generateSignatureAccessToken(input);
    }

    @PostMapping("/generate/signature-transaction")
    public SignatureRes generateSignatureTransaction(@RequestBody GenSignatureTrxReq input) {
        return authServiceV2.generateSignatureTransaction(input);
    }

    @PostMapping("/verify/signature-access-token")
    public String verifySignatureAccessToken(@RequestBody VerifSignatureAccReq input) {
        return authServiceV2.verifyAccSignature(input);
    }

    @PostMapping("/verify/signature-transaction")
    public String verifySignatureTransaction(@RequestBody VerifSignatureTrxReq input) {
        return authServiceV2.verifyTrxSignature(input);
    }
}
