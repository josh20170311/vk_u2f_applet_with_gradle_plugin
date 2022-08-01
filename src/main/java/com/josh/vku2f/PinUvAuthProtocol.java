package com.josh.vku2f;

public abstract class PinUvAuthProtocol {

    private PinUvAuthToken pinUvAuthToken;

    public abstract void initialize();
    public abstract void regenerate();
    public abstract void resetPinUvAuthToken();
    public abstract byte[] getPublicKey();
    public abstract byte[] decapsulate(COSEKey peerCoseKey);
    public abstract byte[] decrypt(byte[] sharedSecret, byte[] cipherText);
    public abstract boolean verify(byte[] key, byte[] message, byte[] signature);
}
