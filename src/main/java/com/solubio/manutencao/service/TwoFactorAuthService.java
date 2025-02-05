//src/main/java/com/solubio/manutencao/service/TwoFactorAuthService.java
package com.solubio.manutencao.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

@Service
public class TwoFactorAuthService {

    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();
    private final Dotenv dotenv = Dotenv.load();
    private final String encryptionKey = dotenv.get("AES_SECRET_KEY");

    public String generateSecretKey() {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }

    public String generateQrCode(String email, String secret) throws Exception {
        String issuer = "Solubio Manutencao";
        String qrCodeData = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, email, secret, issuer);

        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(qrCodeData, BarcodeFormat.QR_CODE, 200, 200);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);

        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
    }

    public boolean verifyCode(String encryptedSecret, int code) {
        try {
            String secret = decrypt(encryptedSecret);
            return gAuth.authorize(secret, code);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public String encrypt(String secret) throws Exception {
        SecretKeySpec key = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(secret.getBytes()));
    }

    public String decrypt(String encryptedSecret) throws Exception {
        SecretKeySpec key = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedSecret)));
    }
}
