package com.josh.vku2f;

import javacard.framework.JCSystem;
import javacard.framework.UserException;
import javacard.framework.Util;

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
    private byte[] keyAgreement = new byte[65]; // COSE object or 0x04||x||y
    private byte[] x = new byte[32]; // x-coordinate
    private byte[] y = new byte[32]; // y-coordinate
    private byte[] pinUvAuthParam = new byte[64]; // byte string
    private byte[] newPinEnc = new byte[64]; // byte string
    private byte[] pinHashEnc = new byte[16]; // byte string, aes256
    private byte permissions; // unsigned int
    private byte[] rpId = new byte[64]; // text string
    byte[] scratch = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_RESET);

    public void decodeCommand(CBORDecoder cborDecoder) throws UserException {
        short commandLength = cborDecoder.readMajorType(CBORBase.TYPE_MAP);

        while(commandLength > (short)0) {
            short valueLength;
            switch (cborDecoder.readInt8()) {
                case PARAMETER_PROTOCOL:
                    protocol = cborDecoder.readInt8();
                    break;
                case PARAMETER_SUBCOMMAND:
                    subCommandCode = cborDecoder.readInt8();
                    break;
                case PARAMETER_KEY_AGREEMENT:
                    cborDecoder.readMajorType(CBORBase.TYPE_MAP);

                    cborDecoder.skipEntry();
                    cborDecoder.skipEntry();

                    cborDecoder.skipEntry();
                    cborDecoder.skipEntry();

                    cborDecoder.skipEntry();
                    cborDecoder.skipEntry();

                    cborDecoder.skipEntry();
//                    cborDecoder.skipEntry();
                    cborDecoder.readByteString(x, (short)0);

                    cborDecoder.skipEntry();
//                    cborDecoder.skipEntry();
                    cborDecoder.readByteString(y, (short)0);


                    break;
                case PARAMETER_PIN_UV_AUTH_PARAM:
                    cborDecoder.readByteString(pinUvAuthParam, (short) 0);
//                    cborDecoder.skipEntry();
                    break;
                case PARAMETER_NEW_PIN_ENC:
                    cborDecoder.readByteString(newPinEnc, (short) 0);
                    break;
                case PARAMETER_PIN_HASH_ENC:
                    cborDecoder.readByteString(pinHashEnc, (short) 0);
//                    cborDecoder.skipEntry();
                    break;
                case PARAMETER_PERMISSIONS:
//                    permissions = cborDecoder.readInt8();
                    cborDecoder.skipEntry();
                    break;
                case PARAMETER_RP_ID:
//                    cborDecoder.readByteString(rpId, (short) 0);
                    cborDecoder.skipEntry();
                    break;
            }
            commandLength--;
        }

    }

    public byte getProtocol() {
        return protocol;
    }

    public byte getSubCommandCode() {
        return subCommandCode;
    }

    /**
     *
     * @return 0x04 || x-coordinate || y-coordinate
     */
    public byte[] getKeyAgreement() {
        keyAgreement[0] = 0x04;
        Util.arrayCopy(x, (short)0, keyAgreement, (short)1, (short)x.length);
        Util.arrayCopy(y, (short)0, keyAgreement, (short)33, (short)y.length);
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
