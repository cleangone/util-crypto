package xyz.cleangone.util;

import org.apache.commons.codec.binary.Base64;
import xyz.cleangone.util.env.EnvManager;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto
{
    private static Crypto CRYPTO = null;

    private IvParameterSpec ivParameterSpec;
    private SecretKeySpec secretKeySpec;
    private Cipher cipher;

    public static String encrypt(String toBeEncrypt)
    {
        if (CRYPTO == null) { CRYPTO = new Crypto(); }

        try
        {
            CRYPTO.cipher.init(Cipher.ENCRYPT_MODE, CRYPTO.secretKeySpec, CRYPTO.ivParameterSpec);
            byte[] encrypted = CRYPTO.cipher.doFinal(toBeEncrypt.getBytes());
            return Base64.encodeBase64String(encrypted);
        }
        catch (Exception e)
        {
            throw new RuntimeException("Error encrypting", e);
        }
    }

    public static String decrypt(String encryptedText)
    {
        if (CRYPTO == null) { CRYPTO = new Crypto(); }

        try
        {
            CRYPTO.cipher.init(Cipher.DECRYPT_MODE, CRYPTO.secretKeySpec, CRYPTO.ivParameterSpec);

            byte[] decoded = Base64.decodeBase64(encryptedText.getBytes());
            byte[] decrypted = CRYPTO.cipher.doFinal(decoded);
            return new String(decrypted);
        }
        catch (Exception e)
        {
            throw new RuntimeException("Error decrypting", e);
        }
    }

    private Crypto()
    {
        try
        {
            ivParameterSpec = new IvParameterSpec(EnvManager.getEnv().getIvParamKey().getBytes("UTF-8"));
            secretKeySpec = new SecretKeySpec(EnvManager.getEnv().getSecretKey().getBytes("UTF-8"), "AES");
            cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        }
        catch (Exception e)
        {
            throw new RuntimeException("Error creating Crypto", e);
        }
    }

}