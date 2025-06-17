package com.sogeti.passkey_backend_yubico.utils;

import com.yubico.webauthn.data.ByteArray;

import java.security.SecureRandom;

public class ByteUtils {

    public static ByteArray generateRandom(int length) {
        SecureRandom random = new SecureRandom();

        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }
}
