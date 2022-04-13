package com.josh.vku2f;

import javacard.framework.JCSystem;
import javacard.security.*;

public class PinUvAuthProtocolOne extends PinUvAuthProtocol{

    private KeyPair ecDhKeyPair;
    private boolean[] ecDhSet;

    @Override
    public void initialize() {
        ECPublicKey ecDhPub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PUBLIC,
                JCSystem.MEMORY_TYPE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
        ECPrivateKey ecDhPriv = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
                JCSystem.MEMORY_TYPE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
        ecDhKeyPair = new KeyPair(ecDhPub, ecDhPriv);
        ecDhSet = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_RESET);
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

    public byte[] encrypt(byte[] key, byte[] plaintext){
        return null;
    }

    @Override
    public void decrypt(byte[] sharedSecret, byte[] cipherText) {

    }

    public byte[] authenticate(byte[] key, byte[] message){
        return null;
    }

    @Override
    public void verify(byte[] key, byte[] message, byte[] signature) {

    }
    private byte[] ecdh(COSEKey peerCoseKey){
        return null;
    }
    private byte[] kdf(byte[] Z){
        return null;
    }
}
