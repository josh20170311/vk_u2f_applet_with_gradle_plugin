package com.josh.vku2f;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;
import jdk.nashorn.internal.ir.Block;

public class PinUvAuthProtocolOne extends PinUvAuthProtocol{

    private KeyPair ecDhKeyPair;
    private boolean[] ecDhSet;
    private AESKey aesKey;
    private Cipher aesEncrypt;
    private Cipher aesDecrypt;
    private MessageDigest sha256;
    private final byte[] IV_ZERO_AES = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    @Override
    public void initialize() {
        ECPublicKey ecDhPub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PUBLIC,
                JCSystem.MEMORY_TYPE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
        ECPrivateKey ecDhPriv = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
                JCSystem.MEMORY_TYPE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
        ecDhKeyPair = new KeyPair(ecDhPub, ecDhPriv);
        ecDhSet = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_RESET);

        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);

        aesEncrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesDecrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }

    @Override
    public void regenerate() {

    }

    @Override
    public void resetPinUvAuthToken() {

    }

    @Override
    public byte[] getPublicKey() {
        byte[] w;
        try {
            w = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            w = new byte[65];
        }

        if (!ecDhSet[0]) {
            // Grab the public key and set it's parameters
            KeyParams.sec256r1params((ECKey) ecDhKeyPair.getPublic());
            // Generate a new key-pair
            ecDhKeyPair.genKeyPair();
            ecDhSet[0] = true;
        }

        ((ECPublicKey) ecDhKeyPair.getPublic()).getW(w, (short) 0);

        // Return the data requested
        return w;
    }

    public byte[] encapsulate(COSEKey peerCOSEKey){
        return null;
    }

    @Override
    public byte[] decapsulate(COSEKey peerCOSEKey) {
        return null;
    }


    /**
     *
     * @param key shared key from kdf()
     * @param plaintext pinToken
     * @return encrypted pinToken
     */
    public byte[] encrypt(byte[] key, byte[] plaintext){
        byte[] cipherText = new byte[32];
        aesKey.setKey(key, (short)0);
        aesEncrypt.init(aesKey, Cipher.MODE_ENCRYPT, IV_ZERO_AES, (short)0, (short)IV_ZERO_AES.length);
        aesEncrypt.update(plaintext, (short)0, (short)16, cipherText, (short)0);
        aesEncrypt.doFinal(plaintext, (short)16, (short)16, cipherText, (short)16);
        return cipherText;
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] cipherText) {
        byte[] plainText = new byte[64];
        aesKey.setKey(key, (short)0);
        aesDecrypt.init(aesKey, Cipher.MODE_DECRYPT, IV_ZERO_AES, (short)0, (short)IV_ZERO_AES.length);
        aesDecrypt.update(cipherText, (short)0, (short)32, plainText, (short)0);
        aesDecrypt.doFinal(cipherText, (short)32, (short)32, plainText, (short)32);
        return plainText;
    }

    /**
     *
     * @param key the key output from kdf()
     * @param cipherText encrypted hashedPin
     * @return hashed pin
     */
    public byte[] decryptHashedPin(byte[] key, byte[] cipherText) {
        byte[] hashedPin = new byte[16];
        aesKey.setKey(key, (short)0);
        aesDecrypt.init(aesKey, Cipher.MODE_DECRYPT, IV_ZERO_AES, (short)0, (short)IV_ZERO_AES.length);
        aesDecrypt.doFinal(cipherText, (short)0, (short)16, hashedPin, (short)0);
        return hashedPin;
    }

    /**
     *
     * @param key pinToken : 32 bytes
     * @param message clientDataHash : 32 bytes
     * @return signature
     */
    public byte[] authenticate(byte[] key, byte[] message){
        return hmac256(key, message);
    }

    /**
     *
     * @param key pinToken 32 bytes
     * @param message clientDataHash 32 bytes
     * @param signature pinUvAuthToken 16 bytes : LEFT(hmac-sha-256(pinToken, clientDataHash), 16)
     * @return boolean result
     */
    @Override
    public boolean verify(byte[] key, byte[] message, byte[] signature) {
        byte[] authenticate = authenticate(key, message);
        for(short i = 0; i < (short)signature.length; i++){
            if(authenticate[i] != signature[i])
                return false;
        }
        return true;
    }

    public byte[] ecdh(byte[] peerKey){
        byte[] sharedKey = new byte[65];
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        keyAgreement.init(ecDhKeyPair.getPrivate());
        keyAgreement.generateSecret(peerKey, (short)0, (short)65, sharedKey, (short)0);
        return kdf(sharedKey, (short)1);
    }

    /**
     *
     * @param Z shared key from ecdh
     * @param offset where the x-coordinate begin
     * @return derivative key
     */
    public byte[] kdf(byte[] Z, short offset){
        byte[] hashed = new byte[32];
        sha256.reset();
        sha256.doFinal(Z, offset, (short)32, hashed, (short)0);
        return hashed;
    }

    /**
     *
     * @param pin pin
     * @return hashed pin
     */
    public byte[] hashPin(byte[] pin){
        byte[] hashedPin = new byte[32];
        sha256.reset();
        sha256.doFinal(pin, (short)0, (short)pin.length, hashedPin, (short)0);
        return hashedPin;
    }

    /**
     *
     * @param key key must <= 64 bytes
     * @param message message must <= 32 bytes
     * @return hmac
     */
    public byte[] hmac256(byte[] key, byte[] message){
        short BLOCKSIZE=64; // 512 bits
        short HASHSIZE=32; // 256 bits

        byte[] hashed = new byte[HASHSIZE];
        byte[] hmacBuffer = new byte[(short)(BLOCKSIZE + hashed.length)];


        for (short i=0; i < (short)key.length; i++){
            hmacBuffer[i]= (byte) (key[i] ^ (0x36));
        }
        Util.arrayFillNonAtomic(hmacBuffer, (short)key.length, (short)(BLOCKSIZE-key.length), (byte)0x36); // ipad

        Util.arrayCopyNonAtomic(message, (short)0, hmacBuffer, BLOCKSIZE, (short)message.length);


        sha256.update(hmacBuffer, (short)0, HASHSIZE);
        sha256.update(hmacBuffer, (short)32, HASHSIZE);
        sha256.doFinal(hmacBuffer, BLOCKSIZE, (short)(message.length), hashed, (short)0);

        for (short i=0; i< (short)key.length; i++){
            hmacBuffer[i]= (byte) (key[i] ^ (0x5c));
        }

        Util.arrayFillNonAtomic(hmacBuffer, (short)key.length, (short)(BLOCKSIZE - key.length), (byte)0x5c); // opad


        Util.arrayCopy(hashed, (short)0, hmacBuffer, BLOCKSIZE, (short)hashed.length);

        sha256.update(hmacBuffer, (short)0, HASHSIZE);
        sha256.update(hmacBuffer, (short)32, HASHSIZE);
        sha256.doFinal(hmacBuffer, BLOCKSIZE, (short)(hashed.length), hashed, (short)0);

        return hashed;
    }
}
