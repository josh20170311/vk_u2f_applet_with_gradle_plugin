package com.josh.vku2f;

public class ClientPINSubCommand {
    public static final byte SUBCOMMAND_GET_PIN_RETRIES =               (byte) 0x01;
    public static final byte SUBCOMMAND_GET_KEY_AGREEMENT =             (byte) 0x02;
    public static final byte SUBCOMMAND_SET_PIN =                       (byte) 0x03;
    public static final byte SUBCOMMAND_CHANGE_PIN =                    (byte) 0x04;
    public static final byte SUBCOMMAND_GET_PIN_TOKEN =                 (byte) 0x05;
    public static final byte SUBCOMMAND_GET_PIN_UV_AUTH_TOKEN_UV =      (byte) 0x06;
    public static final byte SUBCOMMAND_GET_UV_RETRIES =                (byte) 0x07;
    // no 0x08
    public static final byte SUBCOMMAND_GET_PIN_UV_AUTH_TOKEN_PIN =    (byte) 0x09;
}
