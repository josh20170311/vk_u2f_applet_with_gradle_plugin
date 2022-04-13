package com.josh.vku2f;

import javacard.framework.UserException;

public class ClientPINCommand {
    public static final byte PARAMETER_PROTOCOL = 0x01;
    public static final byte PARAMETER_SUBCOMMAND = 0x02;
    public static final byte PARAMETER_KEY_AGREEMENT = 0x03;
    public static final byte PARAMETER_PIN_UV_AUTH_PARAM = 0x04;
    public static final byte PARAMETER_NEW_PIN_ENC = 0x05;
    public static final byte PARAMETER_PIN_HASH_ENC = 0x06;
    public static final byte PARAMETER_PERMISSIONS = 0x09;
    public static final byte PARAMETER_RP_ID = 0x0A;

    private byte protocol; // unsigned int
    private byte subCommandCode; // unsigned int
    private byte[] keyAgreement; // COSE object
    private byte[] pinUvAuthParam; // byte string
    private byte[] newPinEnc; // byte string
    private byte[] pinHashEnc; // byte string
    private byte permissions; // unsigned int
    private byte[] rpId; // text string

    public void decodeCommand(CBORDecoder cborDecoder) throws UserException {
        short commandLength = cborDecoder.readMajorType(CBORBase.TYPE_MAP);
        do {
            byte commandKey = cborDecoder.readInt8();
            short valueLength;
            switch (commandKey) {
                case PARAMETER_PROTOCOL:
                    protocol = cborDecoder.readInt8();
                    break;
                case PARAMETER_SUBCOMMAND:
                    subCommandCode = cborDecoder.readInt8();
                    break;
                case PARAMETER_KEY_AGREEMENT:
                    valueLength = cborDecoder.readLength();
                    keyAgreement = new byte[valueLength];
                    cborDecoder.readRawByteArray(keyAgreement, (short) 0, valueLength);
                    break;
                case PARAMETER_PIN_UV_AUTH_PARAM:
                    valueLength = cborDecoder.readLength();
                    pinUvAuthParam = new byte[valueLength];
                    cborDecoder.readRawByteArray(pinUvAuthParam, (short) 0, valueLength);
                    break;
                case PARAMETER_NEW_PIN_ENC:
                    valueLength = cborDecoder.readLength();
                    newPinEnc = new byte[valueLength];
                    cborDecoder.readRawByteArray(newPinEnc, (short) 0, valueLength);
                    break;
                case PARAMETER_PIN_HASH_ENC:
                    valueLength = cborDecoder.readLength();
                    pinHashEnc = new byte[valueLength];
                    cborDecoder.readRawByteArray(pinHashEnc, (short) 0, valueLength);
                    break;
                case PARAMETER_PERMISSIONS:
                    permissions = cborDecoder.readInt8();
                    break;
                case PARAMETER_RP_ID:
                    valueLength = cborDecoder.readLength();
                    rpId = new byte[valueLength];
                    cborDecoder.readRawByteArray(rpId, (short) 0, valueLength);
                    break;
            }
            commandLength--;
        } while (commandLength >= 1);
    }

    public byte getProtocol() {
        return protocol;
    }

    public byte getSubCommandCode() {
        return subCommandCode;
    }

    public byte[] getKeyAgreement() {
        return keyAgreement;
    }

    public byte[] getPinUvAuthParam() {
        return pinUvAuthParam;
    }

    public byte[] getNewPinEnc() {
        return newPinEnc;
    }

    public byte[] getPinHashEnc() {
        return pinHashEnc;
    }

    public byte getPermissions() {
        return permissions;
    }

    public byte[] getRpId() {
        return rpId;
    }
}
