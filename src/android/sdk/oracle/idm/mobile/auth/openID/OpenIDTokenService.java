/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.openID;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.Key;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

import oracle.idm.mobile.logging.OMLog;

/**
 * Created by ajulka on 5/2/2016.
 */
public class OpenIDTokenService {

    enum TokenType {
        JWT
    }

    private static final String TAG = OpenIDTokenService.class.getSimpleName();
    private TokenType mType = TokenType.JWT;//for now default


    public OpenIDToken generate(String raw, boolean signed) throws ParseException {
        if (raw != null) {
            if (signed) {
                SignedJWT signedJWT;
                JWTClaimsSet claims;
                JWSHeader headers;
                return new OpenIDToken(SignedJWT.parse(raw));
            }
        }
        return null;
    }

    public OpenIDToken validateAndGenerate(String raw, Key key) {

        return null;
    }


    public OpenIDUserInfo generateUserInfo(OpenIDToken token) {
        if (token != null) {
            return new OpenIDUserInfo(token.getAllClaims());
        }
        return null;
    }


    /**
     * Validates the claim values passed are matching the claims of the token.
     * utility to validate the following claims ,@<code>azp</code>,@<code>nonce</code>,@<code>iss</code>  claims etc.
     * eg:
     * <p/>
     * <p>For @<code>aud</code>, its checked that the token audience claim contains value passed for key <code>aud</code> in reference claims </p>
     * <p>For @<code>iss</code>, its checked that the token issuer claim matches the value passed for key <code>iss</code> in reference claims</p>
     * <p>For @<code>nonce</code>, its checked that the token nonce claim matches the value passed for key <code>nonce</code> in reference claims</p>
     *
     * @param token
     * @param referenceClaims
     * @return
     **/
    public boolean validateClaims(OpenIDToken token, Map<String, String> referenceClaims) {
        if (token == null) {
            return false;
        }
        boolean result = true;
        if (referenceClaims != null) {
            for (Map.Entry<String, String> entry : referenceClaims.entrySet()) {
                String claimName = entry.getKey();
                String claimValue = entry.getValue();
                Object tokenClaimValue = token.getAllClaims().get(claimName);
                if (tokenClaimValue == null && claimValue != null) {//fail fast
                    result = false;
                    break;
                }
                if (tokenClaimValue instanceof List<?>) {
                    result = ((List<?>) tokenClaimValue).contains(claimValue);
                } else if (tokenClaimValue instanceof String) {
                    if (claimValue != null) {
                        result = claimValue.equalsIgnoreCase((String) tokenClaimValue);
                    } else {
                        if (tokenClaimValue != null) {
                            result = false;
                        }
                    }
                }
                OMLog.debug(TAG, "Claim: " + claimName + " Validation status : " + result);
                if (!result)
                    break;
            }
        }
        OMLog.debug(TAG, "validateClaims : " + result);
        return result;
    }


    /**
     * validates the string claim only if it exists in the id token,  other wise returns true.
     *
     * @param token
     * @param claim
     * @param expected
     * @return
     */
    public boolean ifExistsThenValidate(OpenIDToken token, OpenIDToken.TokenClaims claim, String expected) {
        OMLog.debug(TAG, "ifExistsThenValidate");
        if (token == null) {
            OMLog.debug(TAG, "Source token is null, return false!");
            return false;
        }
        if (expected != null) {
            if (token.getAllClaims().containsKey(claim.getName())) {
                boolean result = expected.equalsIgnoreCase((String) token.getAllClaims().get(claim.getName()));
                OMLog.debug(TAG, "Claim: " + claim.name() + " validate : " + result);
                return result;
            } else {
                OMLog.debug(TAG, "Claim: " + claim.name() + " Does not exist");
            }
        }
        return true;
    }

}
