package com.josh.vku2f;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;

import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;

/**
 *  Hold some params about the identification binding framework
 */
public class IDSecret {

	public DomString IDx;
	public final byte[] Rx = new byte[4];
	public final byte[] Rp = new byte[4];
	private final byte[] RxRp = new byte[4];
	public final byte[] PuKp = new byte[65];
	public  final byte[] sharedSecret = new byte[20];
	public final byte[] hashedSharedSecret = new byte[32];
	public final byte[] Cx = new byte[16];
	public final byte[] encryptedCx = new byte[16];
	public final byte[] hmac = new byte[32];
	private AESKey aesKey;
	private Cipher aesEncrypt;
	private Cipher aesDecrypt;
	private final byte[] IV_ZERO_AES = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	private MessageDigest sha256;
	private byte[] scratch;
	private final short SCRATCH_LENGTH = (short)128 ;
	private CBOREncoder encoder = new CBOREncoder();
	public final byte[] tempBuffer = new byte[100];
	public short tempBufferLength = (short)0;

	public IDSecret(){
		IDx = new DomString(Utf8Strings.UTF8_NULL, (short)Utf8Strings.UTF8_NULL.length);
		Random.getInstance().nextBytes(Rx, (short)0, (short)Rx.length);
		Util.arrayFill(Rp, (short)0, (short)4, (byte)Rp.length);
		Util.arrayFill(RxRp, (short)0, (short)4, (byte)RxRp.length);

		PuKp[(byte)0] = (byte)0x04;
		Util.arrayFill(PuKp, (short)1, (byte)(PuKp.length-1), (byte)0);

		Util.arrayFill(sharedSecret, (short)0, (byte)sharedSecret.length, (byte)0);
		Util.arrayFill(hashedSharedSecret, (short)0, (byte) hashedSharedSecret.length, (byte)0);
		Random.getInstance().nextBytes(Cx, (short)0, (short)Cx.length);
		Util.arrayFill(encryptedCx, (short)0, (byte)encryptedCx.length, (byte)0);
		Util.arrayFill(hmac, (short)0, (byte)hmac.length, (byte)0);
		Util.arrayFill(tempBuffer, (short)0, (byte)tempBuffer.length, (byte)0);

		aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);

		aesEncrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		aesDecrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
//
		sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		scratch = JCSystem.makeTransientByteArray(SCRATCH_LENGTH, JCSystem.CLEAR_ON_DESELECT);
	}
	private byte i = (short)0;
	public byte[] getRxRp(){
		for(i = (short)0; i < (short)4; i++){
			RxRp[i] = (byte) (Rx[i] ^ Rp[i]);
		}
		return RxRp;
	}

	public void initAesKey(){
		sha256.doFinal(sharedSecret, (short)0, (short)20, hashedSharedSecret, (short)0);
		aesKey.setKey(hashedSharedSecret, (short)0);
		aesEncrypt.init(aesKey, Cipher.MODE_ENCRYPT, IV_ZERO_AES, (short)0, (short)IV_ZERO_AES.length);
		aesDecrypt.init(aesKey, Cipher.MODE_DECRYPT, IV_ZERO_AES, (short)0, (short)IV_ZERO_AES.length);
	}

	public void encryptCx(){
		aesEncrypt.doFinal(Cx, (short)0, (short)Cx.length, encryptedCx, (short)0);
	}

	/**
	 *  AES(aesRawKey, SHA256(IDx||Cx))
	 */
	public void getHMAC(byte[] outputBuffer, short outputOffset){
		Util.arrayCopy(IDx.str, (short)0, scratch, (short)0, (short)IDx.str.length);
		Util.arrayCopy(Cx, (short)0, scratch, (short)IDx.str.length, (short)Cx.length);
		short scratchLength = (short)(IDx.str.length + Cx.length);
		short updateOffset = (short)0;
		while(scratchLength > (byte)32){
			sha256.update(scratch, updateOffset, (byte)32);
			scratchLength -= (byte)32;
			updateOffset += (byte)32;
		}
		sha256.doFinal(scratch, updateOffset, scratchLength, scratch, (short)0);
		aesEncrypt.update(scratch, (short)0, (short)16, outputBuffer, outputOffset);
		aesEncrypt.doFinal(scratch, (short)16, (short)16 , outputBuffer, (short)(outputOffset+16) );

		Util.arrayCopy(outputBuffer, (short)0, hmac, (short)0, (short)32 );
	}

	private short generateExtensions(){
		// 69byte <- EXTENSIONS:10 + PRLAB:5 + HMAC:4 + hmac:32 + CX:2 + cx:16
		encoder.init(tempBuffer, (short)0, (short) tempBuffer.length);
		encoder.startMap((short)1);
		encoder.encodeTextString(Utf8Strings.UTF8_PRLab, (short)0, (short)Utf8Strings.UTF8_PRLab.length);
		encoder.startMap((short)2);
		encoder.encodeTextString(Utf8Strings.UTF8_HMAC, (short)0, (short)Utf8Strings.UTF8_HMAC.length);
		encoder.encodeByteString(hmac, (short)0, (short)hmac.length );
		encoder.encodeTextString(Utf8Strings.UTF8_Cx, (short)0, (short)Utf8Strings.UTF8_Cx.length);
		encoder.encodeByteString(encryptedCx, (short)0, (short)encryptedCx.length);

		return encoder.getCurrentOffset();
	}

	public short getExtensionsLength(){
		tempBufferLength =  generateExtensions();
		return tempBufferLength;
	}

	public short getExtensionsByteString(byte[] outputBuffer, short outputOffset){
		Util.arrayCopy(tempBuffer, (short)0, outputBuffer, outputOffset, tempBufferLength);
		return tempBufferLength;
	}

	/**
	 *
	 * @param inputBuffer the buffer copy from
	 * @param offset output offset
	 */
	public void writeTempBuffer(byte[] inputBuffer, short offset){
		if((short)(inputBuffer.length + offset) > (short)tempBuffer.length){
			tempBuffer[0] = 'T'; // too
			tempBuffer[1] = 'L'; // long
			Util.setShort(tempBuffer, (short)2, (short)inputBuffer.length); // input length
			return;
		}
		Util.arrayCopy(inputBuffer, (short)0, tempBuffer, offset, (short)inputBuffer.length);
	}

	/**
	 * put IDSecret data with CBOR form in dataBuffer
	 * return data length
	*/
	public short dump(byte[] dataBuffer, CBOREncoder encoder){
		encoder.init(dataBuffer, (short)0, (short)1200);
		encoder.startMap((short)1);

//		encoder.encodeTextString(Utf8Strings.UTF8_IDx, (short)0, (short)Utf8Strings.UTF8_IDx.length);
//		encoder.encodeTextString(IDx.str, (short)0, IDx.len);
//
//		encoder.encodeTextString(Utf8Strings.UTF8_Rx, (short)0, (short)Utf8Strings.UTF8_Rx.length);
//		encoder.encodeByteString(Rx, (short)0, (short)Rx.length);
//
//		encoder.encodeTextString(Utf8Strings.UTF8_Rp, (short)0, (short)Utf8Strings.UTF8_Rp.length);
//		encoder.encodeByteString(Rp, (short)0, (short)Rp.length);
//
//		encoder.encodeTextString(Utf8Strings.UTF8_RxRp, (short)0, (short)Utf8Strings.UTF8_RxRp.length);
//		encoder.encodeByteString(getRxRp(), (short)0, (short)RxRp.length);
//
//		encoder.encodeTextString(Utf8Strings.UTF8_PuKp, (short)0, (short)Utf8Strings.UTF8_PuKp.length);
//		encoder.encodeByteString(PuKp, (short)0, (short)PuKp.length);
//
//		encoder.encodeTextString(Utf8Strings.UTF8_SHARED_SECRET, (short)0, (short)Utf8Strings.UTF8_SHARED_SECRET.length);
//		encoder.encodeByteString(sharedSecret, (short)0, (short)sharedSecret.length);
//
//		encoder.encodeTextString(Utf8Strings.UTF8_HASHED_SHARED_SECRET, (short)0, (short)Utf8Strings.UTF8_HASHED_SHARED_SECRET.length);
//		encoder.encodeByteString(hashedSharedSecret, (short)0 , (short) hashedSharedSecret.length);
//
//		encoder.encodeTextString(Utf8Strings.UTF8_Cx, (short)0, (short)Utf8Strings.UTF8_Cx.length);
//		encoder.encodeByteString(Cx, (short)0, (short)Cx.length);
//
//		encoder.encodeTextString(Utf8Strings.UTF8_ENCRYPTED_CX, (short)0, (short)Utf8Strings.UTF8_ENCRYPTED_CX.length);
//		encoder.encodeByteString(encryptedCx, (short)0, (short)encryptedCx.length);
//
//		encoder.encodeTextString(Utf8Strings.UTF8_HMAC, (short)0, (short)Utf8Strings.UTF8_HMAC.length);
//		encoder.encodeByteString(hmac, (short)0, (short)hmac.length );

//		tempBufferLength = generateExtensions();
		encoder.encodeTextString(Utf8Strings.UTF8_TEMP, (short)0, (short)Utf8Strings.UTF8_TEMP.length);
		encoder.encodeByteString(tempBuffer, (short)0, (short)tempBuffer.length);

		return encoder.getCurrentOffset();
	}
}
