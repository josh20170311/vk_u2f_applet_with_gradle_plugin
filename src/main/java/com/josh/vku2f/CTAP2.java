/*
 **
 ** Copyright 2021, VivoKey Technologies
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package com.josh.vku2f;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.UserException;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;

import static com.josh.vku2f.CTAP2ErrorCode.*;
import static com.josh.vku2f.ClientPINSubCommand.*;

public class CTAP2 extends Applet implements ExtendedLength {

	// transient memory, clear on deselect
	private byte[] dataBuffer;
	private byte[] scratch;
	private final short[] tempVars;
	private final short[] chainRam;
	private final short[] outChainRam;
	private final boolean[] isChaining;
	private final boolean[] isOutChaining;

	//transient memory, clear on reset(power off)
	private final short[] nextAssertion;

	private byte[] fidoInfo;
	private final CBORDecoder cborDecoder;
	private final CBOREncoder cborEncoder;
	private final MessageDigest sha256MessageDigest;
	private final AttestationKeyPair attestationKeyPair;
	private boolean personalizeComplete;

	private CredentialArray credentialArray;
	private AuthenticatorMakeCredential authenticatorMakeCredential;
	private AuthenticatorGetAssertion authenticatorGetAssertion;
	private StoredCredential tempCredential;
	private StoredCredential[] assertionCredentials;

	private final ClientPINCommand clientPINCommand;
	private boolean isClientPinSet = false;
	private final byte MAX_PIN_RETRIES = (byte) 0x08;
	private final byte MAX_UV_RETRIES = (byte) 0x08;
	private byte pinRetries = MAX_PIN_RETRIES;
	private byte uvRetries = MAX_UV_RETRIES;
	//    private final KeyPair ecDhKeyPair;
//    private final boolean[] ecDhSet;
	private PinUvAuthProtocolOne pinUvAuthProtocolOne;
	private short pinLength = 0;
	private byte[] pin;
	private final byte[] currentStoredPIN = new byte[16]; // LEFT(SHA-256(pin), 16)
	private final byte[] pinToken = new byte[32];


	// INS
	public static final byte ISO_INS_GET_DATA = (byte) 0xC0;
	public static final byte FIDO2_INS_NFCCTAP_MSG = (byte) 0x10;
	public static final byte FIDO2_INS_DESELECT = (byte) 0x12;

	// FIDO Command
	public static final byte FIDO2_AUTHENTICATOR_MAKE_CREDENTIAL = (byte) 0x01;
	public static final byte FIDO2_AUTHENTICATOR_GET_ASSERTION = (byte) 0x02;
	public static final byte FIDO2_AUTHENTICATOR_GET_NEXT_ASSERTION = (byte) 0x08;
	public static final byte FIDO2_AUTHENTICATOR_GET_INFO = (byte) 0x04;
	public static final byte FIDO2_AUTHENTICATOR_CLIENT_PIN = (byte) 0x06;
	public static final byte FIDO2_AUTHENTICATOR_RESET = (byte) 0x07;

	// Vendor specific - for attestation cert loading.
	public static final byte FIDO2_VENDOR_ATTEST_SIGN = (byte) 0x41;
	public static final byte FIDO2_VENDOR_ATTEST_LOADCERT = (byte) 0x42;
	public static final byte FIDO2_VENDOR_PERSO_COMPLETE = (byte) 0x43;
	public static final byte FIDO2_VENDOR_ATTEST_GETPUB = (byte) 0x44;
	public static final byte FIDO2_VENDOR_GET_CREDENTIAL_COUNT = (byte) 0x45;
	public static final byte FIDO2_VENDOR_ATTEST_GETCERT = (byte) 0x4A;

	//IDSecret
	public final IDSecret idSecret;
	public static final byte ID_SECRET_GET_PUKX_RX = (byte) 0x50;
	public static final byte ID_SECRET_GET_CX = (byte) 0x51;
	public static final byte ID_SECRET_GET_PUKX_CX = (byte) 0x52;
	public static final byte ID_SECRET_DUMP_ALL = (byte) 0x5F;


	// AAGUID - Authenticator Attestation Global Unique Identifier
	// this uniquely identifies the type of authenticator we have built.
	// If you're reusing this code, please generate your own GUID and put it here -
	// this is unique to manufacturer and device model.
	public static final byte[] aaguid = {
			(byte) 't', (byte) 'e', (byte) 's', (byte) 't', (byte) 'a', (byte) 'a', (byte) 'g', (byte) 'u',
			(byte) 'i', (byte) 'd', (byte) 'p', (byte) 'r', (byte) 'l', (byte) 'a', (byte) 'b', (byte) '_',};

	private CTAP2() {

		// 1210 bytes of a transient buffer for read-in and out
		// We advertise 1200 bytes supported, but 10 bytes for protocol nonsense
		try {
			dataBuffer = JCSystem.makeTransientByteArray((short) 1210, JCSystem.CLEAR_ON_DESELECT);
		} catch (Exception e) {
			dataBuffer = new byte[1210];
		}
		try {
			scratch = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
		} catch (Exception e) {
			scratch = new byte[512];
		}
		tempVars = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
		// Create the CBOR decoder
		cborDecoder = new CBORDecoder();
		cborEncoder = new CBOREncoder();
		credentialArray = new CredentialArray((short) 5);
		sha256MessageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		attestationKeyPair = new AttestationKeyPair();
		nextAssertion = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
		personalizeComplete = false;
		isChaining = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
		chainRam = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
		outChainRam = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
		isOutChaining = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
//        ECPublicKey ecDhPub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PUBLIC,
//                JCSystem.MEMORY_TYPE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
//        ECPrivateKey ecDhPriv = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
//                JCSystem.MEMORY_TYPE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
		clientPINCommand = new ClientPINCommand();
//        ecDhKeyPair = new KeyPair(ecDhPub, ecDhPriv);
//        ecDhSet = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_RESET);
		pinUvAuthProtocolOne = new PinUvAuthProtocolOne();
		pinUvAuthProtocolOne.initialize();
		idSecret = new IDSecret();

	}

	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		short offset = bOffset;
		offset += (short) (bArray[offset] + 1); // instance
		offset += (short) (bArray[offset] + 1); // privileges
		final CTAP2 applet = new CTAP2();
		try {
			applet.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
		} catch (Exception e) {
			applet.register();
		}

	}

	// main entry point
	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();

		// return version String when selecting
		if (selectingApplet()) {
			Util.arrayCopyNonAtomic(Utf8Strings.UTF8_FIDO_2_0, (short) 0, buffer, (short) 0,
					(short) Utf8Strings.UTF8_FIDO_2_0.length);
			apdu.setOutgoingAndSend((short) 0, (short) Utf8Strings.UTF8_FIDO_2_0.length);
			return;
		}

		// Check CLA
		if (!apdu.isCommandChainingCLA() && apdu.isISOInterindustryCLA()) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		JCSystem.requestObjectDeletion();
		switch (buffer[ISO7816.OFFSET_INS]) {
			case ISO_INS_GET_DATA: // 0xC0
				if (isOutChaining[0]) {
					getData(apdu);
				} else {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
				break;
			case FIDO2_INS_NFCCTAP_MSG: // 0x10
				handle(apdu);
				break;
			case FIDO2_INS_DESELECT:  // 0x12
				// Appears to be a reset function in the FIDO2 spec, but never referenced
				// anywhere
				ISOException.throwIt(ISO7816.SW_NO_ERROR);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	/**
	 * Handle the command chaining or extended APDU logic.
	 * <p>
	 * Due to the FIDO2 spec requiring support for both extended APDUs and command
	 * chaining, we need to implement chaining here.
	 * <p>
	 * I didn't want to pollute the logic over in the process function, and it makes
	 * sense to do both here.
	 *
	 * @param apdu apdu buffer
	 * @return length of data to be processed. 0 if command chaining is not finished.
	 */
	private short doApduIngestion(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// Receive the APDU
		tempVars[4] = apdu.setIncomingAndReceive();
		// Get true incoming data length
		tempVars[3] = apdu.getIncomingLength();
		// Check if the APDU is too big, we only handle 1200 byte
		if (tempVars[3] > 1200) {
			returnError(apdu, CTAP2_ERR_REQUEST_TOO_LARGE);
			return 0;
		}
		// Check what we need to do re APDU buffer, is it full (special case for 1 len)

		// If this is a command chaining APDU, swap to that logic
		if (isCommandChainingCLA(apdu)) {
			// In the chaining
			if (!isChaining[0]) {
				// Must be first chaining APDU
				isChaining[0] = true;
				// Prep the variables
				chainRam[0] = 0;
			}
			// Copy buffer
			chainRam[1] = tempVars[4];
			// chainRam[0] is the current point in the buffer we start from
			chainRam[0] = Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), dataBuffer, chainRam[0], chainRam[1]);
			return 0x00;
		} else if (isChaining[0]) {
			// Must be the last of the chaining - make the copy and return the length.
			chainRam[1] = tempVars[4];
			chainRam[0] = Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), dataBuffer, chainRam[0], chainRam[1]);
			isChaining[0] = false;
			isChaining[1] = true;
			return chainRam[0];
		} else if (tempVars[3] == 0x01) {
			dataBuffer[0] = buffer[apdu.getOffsetCdata()];
			return 0x01;
		} else if (apdu.getCurrentState() == APDU.STATE_FULL_INCOMING) {
			// We need to do no more
			// Read the entirety of the buffer into the inBuf
			Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), dataBuffer, (short) 0, tempVars[3]);
			return tempVars[4];
		} else {
			// The APDU needs a multi-stage copy
			// First, copy the current data buffer in
			// Get the number of bytes in the data buffer that are the Lc, vars[5] will do
			tempVars[5] = tempVars[4];
			// Make the copy, vars[3] is bytes remaining to get
			tempVars[4] = 0;
			while (tempVars[3] > 0) {
				// Copy data
				tempVars[4] = Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), dataBuffer, tempVars[4], tempVars[5]);
				// Decrement vars[3] by the bytes copied
				tempVars[3] -= tempVars[5];
				// Pull more bytes
				tempVars[5] = apdu.receiveBytes(apdu.getOffsetCdata());
			}
			// Now we're at the end, here, and the commands expect us to give them a data
			// length. Turns out Le bytes aren't anywhere to be found here.
			// The commands use vars[3], so vars[4] will be fine to copy to vars[3].
			return tempVars[4];
		}

	}

	private void handle(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		tempCredential = null;
		authenticatorMakeCredential = null;
		tempVars[3] = doApduIngestion(apdu);
		if (tempVars[3] == 0) {
			// If zero, we had no ISO error, but there might be a CTAP error to return.
			// Throw either way.
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
			return;
		}
		// Need to grab the CTAP command byte
		switch (dataBuffer[0]) {
			case FIDO2_AUTHENTICATOR_MAKE_CREDENTIAL: //0x01
				authMakeCredential(apdu, tempVars[3]);
				break;
			case FIDO2_AUTHENTICATOR_GET_ASSERTION: // 0x02
				authGetAssertion(apdu, tempVars[3]);
				break;
			case FIDO2_AUTHENTICATOR_GET_INFO: // x0x04
				authGetInfo(apdu);
				break;
			case FIDO2_AUTHENTICATOR_CLIENT_PIN: // 0x06
				clientPin(apdu, tempVars[3]);
				break;
			case FIDO2_AUTHENTICATOR_RESET: //0x07
				// Need to finish doing this, we can, I mean, but I don't like it
				doReset(apdu);
				break;
			case FIDO2_AUTHENTICATOR_GET_NEXT_ASSERTION: // 0x08
				authGetNextAssertion(apdu, buffer);
				break;
			case FIDO2_VENDOR_ATTEST_SIGN: //0x41
				attestSignRaw(apdu, tempVars[3]);
				break;
			case FIDO2_VENDOR_ATTEST_LOADCERT: //0x42
				attestSetCert(apdu, tempVars[3]);
				break;
			case FIDO2_VENDOR_PERSO_COMPLETE: //0x43
				personalizationComplete(apdu);
				break;
			case FIDO2_VENDOR_ATTEST_GETPUB: //0x44
				getAttestPublic(apdu);
				break;
			case FIDO2_VENDOR_GET_CREDENTIAL_COUNT: //0x45
				getCredentialCount(apdu);
				break;
			case ID_SECRET_GET_PUKX_RX: // 0x50
				getPuKxRx(apdu, tempVars[3]);
				break;
			case ID_SECRET_GET_CX: // 0x51
				getCx(apdu, tempVars[3]);
				break;
			case ID_SECRET_GET_PUKX_CX:
				getPuKxCx(apdu, tempVars[3]);
				break;
			case ID_SECRET_DUMP_ALL: // 0x5F
				dumpIDSecret(apdu);
				break;
			case FIDO2_VENDOR_ATTEST_GETCERT: //0x4a
				getCert(apdu);
				break;
			default:
				returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
		}

	}

	private void personalizationComplete(APDU apdu) {
		if (attestationKeyPair.isCertSet() && !personalizeComplete) {
			personalizeComplete = true;
			returnError(apdu, CTAP1_ERR_SUCCESS);
		} else {
			returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
		}
	}

	/**
	 * Gets the attestation public key.
	 *
	 * @param apdu apdu buffer
	 */
	private void getAttestPublic(APDU apdu) {
		if (personalizeComplete) {
			returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
			return;
		}
		dataBuffer[0] = 0x00;
		tempVars[0] = (short) (attestationKeyPair.getPubkey(dataBuffer, (short) 1) + 1);
		apdu.setOutgoing();
		apdu.setOutgoingLength(tempVars[0]);
		apdu.sendBytesLong(dataBuffer, (short) 0, tempVars[0]);
	}

	/**
	 * get counter's value
	 */
	private void getCredentialCount(APDU apdu) {
		Util.setShort(apdu.getBuffer(), (short) 0x00, credentialArray.getCount());
		apdu.setOutgoingAndSend((short) 0x00, (short) 2);
	}

	/**
	 * for original framework purpose
	 * <p>
	 * input: IDx String
	 * return: PuKx and Rx in CBOR form
	 */
	private void getPuKxRx(APDU apdu, short dataLength) {
		// Done IDx have to get data from dataBuffer at index 1
		Util.arrayCopy(dataBuffer, (short) 1, scratch, (short) 0, (short) (dataLength - 1));
		idSecret.IDx = new DomString(scratch, (short) (dataLength - 1));
		cborEncoder.init(dataBuffer, (short) 0, (short) 1200);
		cborEncoder.startArray((short) 2);
		cborEncoder.encodeUInt32(idSecret.Rx, (short) 0);
		tempVars[0] = attestationKeyPair.getPubkey(scratch, (short) 0);
		cborEncoder.encodeByteString(scratch, (short) 0, tempVars[0]);
		apdu.setOutgoing();
		apdu.setOutgoingLength(cborEncoder.getCurrentOffset());
		apdu.sendBytesLong(dataBuffer, (short) 0, cborEncoder.getCurrentOffset());
	}

	/**
	 * pending
	 */
	private void getCx(APDU apdu, short dataLength) {

	}

	/**
	 * for alternative framework purpose
	 * <p>
	 * input: IDx , PuKp in CBOR form
	 * return: PuKx, encryptedCx in CBOR form
	 */
	private void getPuKxCx(APDU apdu, short dataLength) {
		cborDecoder.init(dataBuffer, (short) 1, dataLength);
		try {
			cborDecoder.readMajorType(CBORBase.TYPE_ARRAY);
			short length = cborDecoder.readTextString(scratch, (short) 0);
			idSecret.IDx = new DomString(scratch, length);
			cborDecoder.readByteString(scratch, (short) 0);
			Util.arrayCopy(scratch, (short) 8, idSecret.PuKp, (short) 1, (short) 64);
		} catch (UserException e) {
			returnError(apdu, e.getReason());
		}
		KeyAgreement keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
		keyAgreement.init(attestationKeyPair.getPrivate());
		keyAgreement.generateSecret(idSecret.PuKp, (short) 0, (short) 65, idSecret.sharedSecret, (short) 0);

		idSecret.initAesKey();
		idSecret.encryptCx();

		cborEncoder.init(dataBuffer, (short) 0, (short) 1200);
		cborEncoder.startArray((short) 2);
		short length = attestationKeyPair.getPubkey(scratch, (short) 0);
		cborEncoder.encodeByteString(scratch, (short) 0, length);
		cborEncoder.encodeByteString(idSecret.encryptedCx, (short) 0, (short) idSecret.encryptedCx.length);

		//for test
		idSecret.getHMAC(scratch, (short) 0);

		apdu.setOutgoing();
		apdu.setOutgoingLength(cborEncoder.getCurrentOffset());
		apdu.sendBytesLong(dataBuffer, (short) 0, cborEncoder.getCurrentOffset());
	}

	/**
	 * dump secrets
	 */
	private void dumpIDSecret(APDU apdu) {
		tempVars[0] = idSecret.dump(dataBuffer, cborEncoder);
//        apdu.setOutgoing();
//        apdu.setOutgoingLength(tempVars[0]);
//        apdu.sendBytesLong(dataBuffer, (short)0, tempVars[0]);
		sendLongChaining(apdu, tempVars[0]);
	}

	/**
	 * Performs raw signatures, may only occur when personalisation is not complete.
	 *
	 * @param apdu   apdu buffer
	 * @param bufLen buffer length
	 */
	public void attestSignRaw(APDU apdu, short bufLen) {
		if (personalizeComplete) {
			returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
			return;
		}
		Util.arrayCopy(dataBuffer, (short) 1, scratch, (short) 0, (short) (bufLen - 1));
		dataBuffer[0] = 0x00;
		tempVars[2] = attestationKeyPair.sign(scratch, (short) 0, tempVars[1], dataBuffer, (short) 1);
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) (tempVars[2] + 1));
		apdu.sendBytesLong(dataBuffer, (short) 0, (short) (tempVars[2] + 1));
	}

	public void attestSetCert(APDU apdu, short bufLen) {
		if (personalizeComplete) {
			returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
			return;
		}
		// We don't actually use any CBOR here, simplify copying
		attestationKeyPair.setCert(dataBuffer, (short) 1, (short) (bufLen - 1));
		MessageDigest dig = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		short len = (short) (dig.doFinal(attestationKeyPair.x509cert, (short) 0, attestationKeyPair.x509len, dataBuffer, (short) 3) + 3);
		dataBuffer[0] = 0x00;
		Util.setShort(dataBuffer, (short) 1, attestationKeyPair.x509len);
		apdu.setOutgoing();
		apdu.setOutgoingLength(len);
		apdu.sendBytesLong(dataBuffer, (short) 0, len);
	}

	public void authMakeCredential(APDU apdu, short bufLen) {
		if (pinRetries < (short) 1) {
			returnError(apdu, CTAP2_ERR_PIN_AUTH_BLOCKED);
			return;
		}

		// Init the decoder
		cborDecoder.init(dataBuffer, (short) 1, bufLen);
		// create a credential object
		try {
			authenticatorMakeCredential = new AuthenticatorMakeCredential(cborDecoder);
		} catch (UserException e) {
			returnError(apdu, e.getReason());
			return;
		}

		// Create the actual credential
		switch (authenticatorMakeCredential.getAlgorithm()) {
			case Signature.ALG_ECDSA_SHA_256:
				tempCredential = new StoredES256Credential(authenticatorMakeCredential);
				break;
			case Signature.ALG_RSA_SHA_256_PKCS1:
				tempCredential = new StoredRS256Credential(authenticatorMakeCredential);
				break;
			case Signature.ALG_RSA_SHA_256_PKCS1_PSS:
				tempCredential = new StoredPS256Credential(authenticatorMakeCredential);
				break;
			default:
				returnError(apdu, CTAP2_ERR_UNSUPPORTED_ALGORITHM);
				return;
		}
		if (authenticatorMakeCredential.isResident()) {
			idSecret.writeTempBuffer(pinUvAuthProtocolOne.authenticate(pinToken, authenticatorMakeCredential.getDataHash()), (short) 0);
			idSecret.writeTempBuffer(authenticatorMakeCredential.getPinUvAuthParam(), (short) 64);

			// verify the pin UV Auth token
			if (pinUvAuthProtocolOne.verify(
					pinToken,
					authenticatorMakeCredential.getDataHash(),
					authenticatorMakeCredential.getPinUvAuthParam()
			)
			) {
				pinRetries = MAX_PIN_RETRIES;
			} else {
				pinRetries--;
				returnError(apdu, CTAP2_ERR_PIN_AUTH_INVALID);
				return;
			}


			// Check if a credential exists on the excluded list
			if (authenticatorMakeCredential.isExclude() && isPresent(authenticatorMakeCredential.exclude)) {
				// Throw the error
				returnError(apdu, CTAP2_ERR_CREDENTIAL_EXCLUDED);
				return;
			}

			// Add the credential to the resident storage, overwriting if necessary
			addResident(apdu, tempCredential);

			// Initialise the output buffer, for CBOR writing.
			// output buffer needs 0x00 as first byte as status code
			dataBuffer[0] = 0x00;
			cborEncoder.init(dataBuffer, (short) 1, (short) 1199);
			// Create a map in the buffer
			tempVars[0] = cborEncoder.startMap((short) 3); // current offset

			// Attestation stuff
			// Attestation statement format : 0x01
			cborEncoder.writeRawByte((byte) 0x01);
			cborEncoder.encodeTextString(Utf8Strings.UTF8_PACKED, (short) 0, (short) 6);

			// Put the authenticatorData identifier(0x02) there
			// Authenticator Data : 0x02
			cborEncoder.writeRawByte((byte) 0x02);
			// Allocate some space for the byte string
			/**
			 * add extensions byte string length
			 */
			// TODO fix the bug on extension byte string
//            tempVars[0] = cborEncoder.startByteString((short) (37 + tempCredential.getAttestedLen() + idSecret.getExtensionsLength() ));
//            tempVars[0] = cborEncoder.startByteString((short) (37 + tempCredential.getAttestedLen() + Utf8Strings.UTF8_PRLab.length ));
			tempVars[0] = cborEncoder.startByteString((short) (37 + tempCredential.getAttestedLen()));
			/**
			 * end
			 */
			// Stash where it begins
			tempVars[7] = tempVars[0];
			// Create the SHA256 hash of the RP ID
			tempCredential.rpEntity.getRp(scratch, (short) 0);
			tempVars[0] += sha256MessageDigest.doFinal(scratch, (short) 0, tempCredential.rpEntity.getRpLen(), dataBuffer, tempVars[0]);

			// Set flags - User presence, user verified, attestation present
			dataBuffer[tempVars[0]++] = (byte) 0x45;

			// Set the signature counter
			tempVars[0] += tempCredential.readCounter(dataBuffer, tempVars[0]);

			// Read the credential details in
			// Just note down where this starts for future ref
			tempVars[0] += tempCredential.getAttestedData(dataBuffer, tempVars[0]);

			/**
			 *  put extensions here
			 */
			// TODO fix the bug on this
//            tempVars[0] += idSecret.getExtensionsByteString(dataBuffer, tempVars[0]);
//            Util.arrayCopy(Utf8Strings.UTF8_PRLab, (short)0, dataBuffer, tempVars[0], (short)Utf8Strings.UTF8_PRLab.length);

			/**
			 *  end extensions
			 */


			// Generate and then attach the attestation.
			// Attestation Statement : 0x03
			cborEncoder.writeRawByte((byte) 0x03);
			// Start to build into the cbor array manually, to avoid arrayCopy

			// Create a map with 3 things
//            cborEncoder.startMap((short) 3);
			cborEncoder.startMap((short) 4);
			// Add the alg label
			cborEncoder.encodeTextString(Utf8Strings.UTF8_ALG, (short) 0, (short) 3);
			// Add the actual algorithm - -7 is 6 as a negative
			cborEncoder.encodeNegativeUInt8((byte) 0x06);
			// Add the actual signature, we should generate this
			cborEncoder.encodeTextString(Utf8Strings.UTF8_SIG, (short) 0, (short) 3);

			// Generate the signature, can't do this directly unfortunately.
			// We sign over the client data hash and the attested data.
			// AuthenticatorData is first. We noted down where it begins and know how long
			// it is.
			attestationKeyPair.update(dataBuffer, tempVars[7], (short) (tempCredential.getAttestedLen() + 37));
			// The client data hash is next, which we use to finish off the signature.
			tempVars[4] = attestationKeyPair.sign(authenticatorMakeCredential.dataHash, (short) 0, (short) authenticatorMakeCredential.dataHash.length, scratch, (short) 0);
			// Create the byte string for the signature
			cborEncoder.encodeByteString(scratch, (short) 0, tempVars[4]);
			// Set the x509 cert now
			cborEncoder.encodeTextString(Utf8Strings.UTF8_X5C, (short) 0, (short) 3);
			// Supposedly we need an array here
			cborEncoder.startArray((short) 1);
			cborEncoder.encodeByteString(attestationKeyPair.x509cert, (short) 0, attestationKeyPair.x509len);

			/**
			 *     extension
			 */
			// add extension label
			cborEncoder.encodeTextString(Utf8Strings.UTF8_EXTENSIONS, (short) 0, (short) Utf8Strings.UTF8_EXTENSIONS.length);

			// add extension element
			cborEncoder.startArray((short) 2);
			// add HMAC
//            cborEncoder.encodeTextString(Utf8Strings.UTF8_HMAC, (short)0, (short)Utf8Strings.UTF8_HMAC.length );
			cborEncoder.encodeByteString(idSecret.hmac, (short) 0, (short) idSecret.hmac.length);
//            // add Cx
//            cborEncoder.encodeTextString(Utf8Strings.UTF8_Cx, (short)0, (short)Utf8Strings.UTF8_Cx.length);
			cborEncoder.encodeByteString(idSecret.encryptedCx, (short) 0, (short) idSecret.encryptedCx.length);


			/**
			 *      end extension
			 */


			// We're actually done, send this out
			sendLongChaining(apdu, cborEncoder.getCurrentOffset());

		} else {
			// Non-resident credential
			// TODO - we currently force resident credentials
			returnError(apdu, CTAP2_ERR_UNSUPPORTED_OPTION);
		}

	}

	public void authGetAssertion(APDU apdu, short bufLen) {
		nextAssertion[0] = (short) 0;
		// Decode the CBOR array for the assertion
		cborDecoder.init(dataBuffer, (short) 1, bufLen);
		try {
			authenticatorGetAssertion = new AuthenticatorGetAssertion(cborDecoder);
		} catch (UserException e) {
			returnError(apdu, e.getReason());
			return;
		}
		// Match the assertion to the credential
		// Get a list of matching credentials
		assertionCredentials = findCredentials(apdu, authenticatorGetAssertion);
		// Use the first one; this complies with both ideas - use the most recent match
		// if no allow list, use any if an allowing list existed
		if (assertionCredentials.length == 0 || assertionCredentials[0] == null) {
			returnError(apdu, CTAP2_ERR_NO_CREDENTIALS);
			return;
		}
		// Create the authenticatorData to sign
		sha256MessageDigest.doFinal(authenticatorGetAssertion.rpId, (short) 0, (short) authenticatorGetAssertion.rpId.length, scratch, (short) 0);
		if (authenticatorGetAssertion.options[1]) {
			scratch[32] = 0x05;
		} else {
			scratch[32] = 0x01;
		}

		assertionCredentials[0].readCounter(scratch, (short) 33);
		// Copy the hash in
		authenticatorGetAssertion.getHash(scratch, (short) 37);
		// Create the output

		// Status flags first
		dataBuffer[0] = 0x00;
		// Create the encoder
		cborEncoder.init(dataBuffer, (short) 1, (short) 1199);
		// Determine if we need 4 or 5 in the array
		if (assertionCredentials.length > 1) {
			doAssertionCommon(cborEncoder, (short) 5);
		} else {
			doAssertionCommon(cborEncoder, (short) 4);
		}
		nextAssertion[0] = (short) 1;
		// Emit this as a response
		sendLongChaining(apdu, cborEncoder.getCurrentOffset());
	}

	/**
	 * Get the next assertion in a list of multiple.
	 *
	 * @param apdu   apdu buffer
	 * @param buffer buffer
	 */
	private void authGetNextAssertion(APDU apdu, byte[] buffer) {
		// Confirm that we have more assertions to do
		if (nextAssertion[0] != (short) 0 && nextAssertion[0] < assertionCredentials.length) {
			// Create the authenticatorData to sign
			sha256MessageDigest.doFinal(authenticatorGetAssertion.rpId, (short) 0, (short) authenticatorGetAssertion.rpId.length, scratch, (short) 0);
			if (authenticatorGetAssertion.options[1]) {
				scratch[32] = 0x05;
			} else {
				scratch[32] = 0x01;
			}
			assertionCredentials[nextAssertion[0]].readCounter(scratch, (short) 33);
			// Copy the hash in
			authenticatorGetAssertion.getHash(scratch, (short) 37);
			// Create the output

			// Status flags first
			dataBuffer[0] = 0x00;
			// Create the encoder
			cborEncoder.init(dataBuffer, (short) 1, (short) 1199);
			doAssertionCommon(cborEncoder, (short) 4);

			nextAssertion[0]++;
			// Emit this as a response
			sendLongChaining(apdu, cborEncoder.getCurrentOffset());
		}
	}

	// Process the AuthenticatorClientPin feature
	// Note: we only implement the keyAgreement bit
	public void clientPin(APDU apdu, short bufferLength) {
		try {
			cborDecoder.init(dataBuffer, (short) 1, bufferLength);
			// Start reading
			clientPINCommand.decodeCommand(cborDecoder);

			switch (clientPINCommand.getSubCommandCode()) {
				case SUBCOMMAND_GET_PIN_RETRIES:
					dataBuffer[0] = CTAP1_ERR_SUCCESS; // 0x00 : response success code
					cborEncoder.init(dataBuffer, (short) 1, (short) (1199));
					cborEncoder.startMap((short) 1);
					cborEncoder.encodeUInt8(ClientPINResponse.PIN_RETRIES);
					cborEncoder.encodeUInt8(pinRetries);
					sendLongChaining(apdu, cborEncoder.getCurrentOffset());
					break;
				case SUBCOMMAND_GET_KEY_AGREEMENT:
					dataBuffer[0] = CTAP1_ERR_SUCCESS; // 0x00 : response success code
					cborEncoder.init(dataBuffer, (short) 1, (short) 1199);
					// Start a map
					cborEncoder.startMap((short) 1);
					// Encode the COSE key identifier
					cborEncoder.encodeUInt8((byte) 0x01);
					// Start the COSE map
					cborEncoder.startMap((short) 5);
					// Kty tag
					cborEncoder.encodeUInt8((byte) 0x01);
					// Kty value - EC2
					cborEncoder.encodeUInt8((byte) 0x02);
					// Alg tag
					cborEncoder.encodeUInt8((byte) 0x03);
					// Alg value - ES256 (-7, 6 in negative format)
					// Alg value - ECDH (-25, 24 in negative format)
					cborEncoder.encodeNegativeUInt8((byte) 0x18);
					// Crv tag - negative
					cborEncoder.encodeNegativeUInt8((byte) 0x00);
					// Crv value - P-256
					cborEncoder.encodeUInt8((byte) 0x01);
					// X-coord tag
					cborEncoder.encodeNegativeUInt8((byte) 0x01);
					// X-coord value
					cborEncoder.encodeByteString(pinUvAuthProtocolOne.getPublicKey(), (short) 1, (short) 32);  // the first byte is 0x04, it means the key is uncompressed
					// Y-coord tag
					cborEncoder.encodeNegativeUInt8((byte) 0x02);
					// Y-coord value
					cborEncoder.encodeByteString(pinUvAuthProtocolOne.getPublicKey(), (short) 33, (short) 32);
					// That's it
					sendLongChaining(apdu, cborEncoder.getCurrentOffset());
					break;
				case SUBCOMMAND_SET_PIN:
					byte[] paddedPin = pinUvAuthProtocolOne.decrypt(
							pinUvAuthProtocolOne.ecdh(clientPINCommand.getKeyAgreement()),
							clientPINCommand.getNewPinEnc()
					);

					for (short i = 0; i < (short) paddedPin.length; i++) {
						if (paddedPin[i] == 0x00) {
							pinLength = i;
							break;
						}
					}

					pin = new byte[pinLength];

					Util.arrayCopy(paddedPin, (short) 0, pin, (short) 0, (short) pin.length);

//                    idSecret.writeTempBuffer(pin, (short)0);

					byte[] hashedPin = pinUvAuthProtocolOne.hashPin(pin);
					Util.arrayCopy(hashedPin, (short) 0, currentStoredPIN, (short) 0, (short) 16);

//                    idSecret.writeTempBuffer(currentStoredPIN, (short)10);

					isClientPinSet = true;
					fidoInfo = null;
					pinRetries = MAX_PIN_RETRIES;
					JCSystem.requestObjectDeletion();
					break;
				case SUBCOMMAND_CHANGE_PIN:
					break;
				case SUBCOMMAND_GET_PIN_TOKEN:
					byte[] hashedPin_leftHalf;
					byte[] sharedSecret = pinUvAuthProtocolOne.ecdh(clientPINCommand.getKeyAgreement());
					hashedPin_leftHalf = pinUvAuthProtocolOne.decryptHashedPin(
							sharedSecret, clientPINCommand.getPinHashEnc()
					);
//                    idSecret.writeTempBuffer(hashedPin_leftHalf, (short)36);

					for (short i = 0; i < (short) hashedPin_leftHalf.length; i++) {
						if (hashedPin_leftHalf[i] != currentStoredPIN[i]) {
							pinRetries--;
							UserException.throwIt(CTAP2_ERR_PIN_INVALID);
							break;
						}
					}


					RandomData r = Random.getInstance();
					r.nextBytes(pinToken, (short) 0, (short) pinToken.length);

//                    idSecret.writeTempBuffer(pinToken, (short) 0);

					byte[] pinTokenEnc = pinUvAuthProtocolOne.encrypt(sharedSecret, pinToken);

					dataBuffer[0] = CTAP1_ERR_SUCCESS;
					cborEncoder.init(dataBuffer, (short) 1, (short) 1199);
					cborEncoder.startMap((short) 1);
					cborEncoder.encodeUInt8((byte) 0x02);
					cborEncoder.encodeByteString(pinTokenEnc, (short) 0, (short) 32);
					sendLongChaining(apdu, cborEncoder.getCurrentOffset());
					break;
				case SUBCOMMAND_GET_PIN_UV_AUTH_TOKEN_UV:
					break;
				case SUBCOMMAND_GET_UV_RETRIES:
					break;
				case SUBCOMMAND_GET_PIN_UV_AUTH_TOKEN_PIN:
					break;
			}
		} catch (UserException e) {
			returnError(apdu, e.getReason());
		}
	}

	private void addResident(APDU apdu, StoredCredential cred) {
		// Add a Discoverable Credential (resident)
		try {
			credentialArray.addCredential(cred);
		} catch (UserException e) {
			returnError(apdu, e.getReason());
		}
	}


	/**
	 * Finds all credentials scoped to the RpId, and optionally the allowList, in
	 * assertion
	 *
	 * @param apdu      the APDU to send through for errors
	 * @param assertion the assertion CTAP object
	 * @return an array of StoredCredential objects, null if none matched.
	 */
	private StoredCredential[] findCredentials(APDU apdu, AuthenticatorGetAssertion assertion) {
		StoredCredential[] list;
		StoredCredential temp;
		if (assertion.hasAllow()) {
			// Our list can be no bigger than the allowList
			list = new StoredCredential[(short) assertion.allow.length];

			tempVars[6] = 0;
			for (tempVars[7] = (short) (credentialArray.getLength() - 1); tempVars[7] >= 0; tempVars[7]--) {
				temp = credentialArray.get(tempVars[7]);
				// Check if null or doesn't match rpId
				if (temp != null && temp.rpEntity.checkId(assertion.rpId, (short) 0, (short) assertion.rpId.length)) {
					for (tempVars[5] = 0; tempVars[5] < (short) assertion.allow.length; tempVars[5]++) {
						// Check the list
						// Does length match?
						if ((short) assertion.allow[tempVars[5]].id.length != (short) temp.credentialId.length) {
							continue;
						}
						if (Util.arrayCompare(assertion.allow[tempVars[5]].id, (short) 0, temp.credentialId, (short) 0,
								(short) temp.credentialId.length) == 0) {
							// Add it to the list
							list[tempVars[6]++] = temp;
						}

					}
				}

			}

		} else {
			// Old code path, works fine for me
			list = new StoredCredential[credentialArray.getLength()];
			tempVars[6] = 0;
			for (tempVars[7] = (short) (credentialArray.getLength() - 1); tempVars[7] >= 0; tempVars[7]--) {
				temp = credentialArray.get(tempVars[7]);
				// Check for null or doesn't match rpId
				if (temp != null && temp.rpEntity.checkId(assertion.rpId, (short) 0, (short) assertion.rpId.length)) {
					// Then valid
					list[tempVars[6]++] = temp;
				}
			}
		}

		// Trim the list
		StoredCredential[] ret = new StoredCredential[tempVars[6]];
		// Trim
		for (tempVars[7] = 0; tempVars[7] < tempVars[6]; tempVars[7]++) {
			ret[tempVars[7]] = list[tempVars[7]];
		}
		// Null out the unused stuff
		JCSystem.requestObjectDeletion();
		return ret;

	}

	/**
	 * Check if anything in the list is present
	 *
	 * @param list list
	 * @return if is present
	 */
	private boolean isPresent(PublicKeyCredentialDescriptor[] list) {
		StoredCredential temp;
		for (tempVars[7] = (short) 0; tempVars[7] < credentialArray.getLength(); tempVars[7]++) {
			temp = credentialArray.get(tempVars[7]);
			if (temp == null) {
				continue;
			}
			for (tempVars[6] = (short) 0; tempVars[6] < (short) list.length; tempVars[6]++) {
				if (temp.checkId(list[tempVars[6]].id, (short) 0, (short) list[tempVars[6]].id.length)) {
					return true;
				}
			}

		}
		return false;
	}

	/**
	 * Reset the authenticator. This doesn't actually take much.
	 * checking. This is just so testing doesn't crap out.
	 */
	private void doReset(APDU apdu) {
		// TODO: Implement Resetting
		credentialArray = new CredentialArray((short) 5);
		JCSystem.requestObjectDeletion();
		returnError(apdu, CTAP1_ERR_SUCCESS);
	}

	/**
	 * Return an error via APDU - an error on the FIDO2 side is considered a success
	 * in APDU-land ,so we send a response.
	 *
	 * @param apdu shared APDU object
	 * @param err  error code
	 */
	public void returnError(APDU apdu, byte err) {
		byte[] buffer = apdu.getBuffer();
		buffer[0] = err;
		apdu.setOutgoingAndSend((short) 0, (short) 1);
	}

	/**
	 * Return an error via APDU - an error on the FIDO2 side is considered a success
	 * in APDU-land ,so we send a response.
	 *
	 * @param apdu shared APDU object
	 * @param err  error code
	 */
	public void returnError(APDU apdu, short err) {
		byte[] buffer = apdu.getBuffer();
		// Get the low byte of the error.
		Util.setShort(buffer, (short) 0, err);
		apdu.setOutgoingAndSend((short) 1, (short) 1);
	}

	/**
	 * Get authenticator-specific information, and return it to the platform.
	 *
	 * @param apdu apdu buffer
	 */
	private void authGetInfo(APDU apdu) {
		// Create the authenticator info if not present.
		if (fidoInfo == null) {
			// Create the authGetInfo - 0x00 is success
			dataBuffer[0] = 0x00;
			cborEncoder.init(dataBuffer, (short) 1, (short) 1199);
			cborEncoder.startMap((short) 7);
			// 0x01, versions
			cborEncoder.encodeUInt8((byte) 0x01);
			// Value is an array of strings
			cborEncoder.startArray((short) 1);
			// Type 1, FIDO2
			cborEncoder.encodeTextString(Utf8Strings.UTF8_FIDO_2_0, (short) 0, (short) Utf8Strings.UTF8_FIDO_2_0.length);
//            cborEncoder.encodeTextString(Utf8Strings.UTF8_FIDO_2_1_PRE, (short) 0, (short) Utf8Strings.UTF8_FIDO_2_1_PRE.length);
			// 0x02, Extensions
//            cborEncoder.encodeUInt8((byte) 0x02);
//            cborEncoder.startArray((short) 2);
//            cborEncoder.encodeTextString(Utf8Strings.UTF8_credProtect, (short)0, (short)Utf8Strings.UTF8_credProtect.length);
//            cborEncoder.encodeTextString(Utf8Strings.UTF8_hmac_secret, (short)0, (short)Utf8Strings.UTF8_hmac_secret.length);
//            cborEncoder.encodeTextString(Utf8Strings.UTF8_PRLab, (short)0, (short)Utf8Strings.UTF8_PRLab.length);
			// 0x03, AAGUID,
			cborEncoder.encodeUInt8((byte) 0x03);
			cborEncoder.encodeByteString(aaguid, (short) 0, (short) 16);
			// 0x04, Options,
			cborEncoder.encodeUInt8((byte) 0x04);
			// Map of 3
			cborEncoder.startMap((short) 4);
			// Rk
			cborEncoder.encodeTextString(Utf8Strings.UTF8_RK, (short) 0, (short) Utf8Strings.UTF8_RK.length);
			cborEncoder.encodeBoolean(true);
			// UP
			cborEncoder.encodeTextString(Utf8Strings.UTF8_UP, (short) 0, (short) Utf8Strings.UTF8_UP.length);
			cborEncoder.encodeBoolean(true);
//            // UV
//            cborEncoder.encodeTextString(Utf8Strings.UTF8_UV, (short) 0, (short)Utf8Strings.UTF8_UV.length);
//            cborEncoder.encodeBoolean(true);
			// plat
			cborEncoder.encodeTextString(Utf8Strings.UTF8_plat, (short) 0, (short) Utf8Strings.UTF8_plat.length);
			cborEncoder.encodeBoolean(false);
			// clientPin
			cborEncoder.encodeTextString(Utf8Strings.UTF8_CLIENT_PIN, (short) 0, (short) Utf8Strings.UTF8_CLIENT_PIN.length);
			cborEncoder.encodeBoolean(isClientPinSet);
			// credentialMgmtPreview
//            cborEncoder.encodeTextString(Utf8Strings.UTF8_CREDENTIAL_MGMT_PREVIEW, (short) 0, (short)Utf8Strings.UTF8_CREDENTIAL_MGMT_PREVIEW.length);
//            cborEncoder.encodeBoolean(true);
			// Max msg size, 0x05
			cborEncoder.encodeUInt8((byte) 0x05);
			cborEncoder.encodeUInt16((short) 1200);
			// pin Protocols, 0x06
			cborEncoder.encodeUInt8((byte) 0x06);
			cborEncoder.startArray((short) 0x01);
			cborEncoder.encodeUInt8((byte) 0x01);
			// transports, 0x09
			cborEncoder.encodeUInt8((byte) 0x09);
			cborEncoder.startArray((short) 0x01);
			cborEncoder.encodeTextString(Utf8Strings.UTF8_nfc, (short) 0, (short) Utf8Strings.UTF8_nfc.length);
//            cborEncoder.encodeTextString(Utf8Strings.UTF8_usb, (short) 0, (short)Utf8Strings.UTF8_usb.length);
			// minPINLength, 0x0D
			cborEncoder.encodeUInt8((byte) 0x0D);
			cborEncoder.encodeUInt8((byte) 0x04);
			// Done
			JCSystem.beginTransaction();
			fidoInfo = new byte[cborEncoder.getCurrentOffset()];
			Util.arrayCopy(dataBuffer, (short) 0, fidoInfo, (short) 0, cborEncoder.getCurrentOffset());
			JCSystem.commitTransaction();
		}
		// Send it
		Util.arrayCopyNonAtomic(fidoInfo, (short) 0, dataBuffer, (short) 0, (short) fidoInfo.length);
		sendLongChaining(apdu, (short) fidoInfo.length);
	}

	/**
	 * Covers the common assertion building process.
	 *
	 * @param encoder   CBOR Encoder
	 * @param mapLength Map Length
	 */
	private void doAssertionCommon(CBOREncoder encoder, short mapLength) {

		// Determine if we need 4 or 5 in the array
		if (mapLength == 4) {
			encoder.startMap((short) 4);
		} else {
			encoder.startMap((short) 5);
		}

		// Tag 1, credential data
		encoder.encodeUInt8((byte) 0x01);
		// Start a map, which is all the PublicKeyCredentialDescriptor is
		encoder.startMap((short) 2);
		// Put the id key
		cborEncoder.encodeTextString(Utf8Strings.UTF8_ID, (short) 0, (short) 2);
		// Put the value, which is a byte array
		cborEncoder.encodeByteString(assertionCredentials[nextAssertion[0]].credentialId, (short) 0,
				(short) assertionCredentials[nextAssertion[0]].credentialId.length);
		// Put the key for the type
		cborEncoder.encodeTextString(Utf8Strings.UTF8_TYPE, (short) 0, (short) 4);
		// Put the value
		cborEncoder.encodeTextString(Utf8Strings.UTF8_PUBLIC_KEY, (short) 0, (short) 10);
		// Done with tag 1
		cborEncoder.encodeUInt8((byte) 0x02);
		// Tag 2, which is the Authenticator bindings data (turns out this is excluding
		// the clientDataHash)
		cborEncoder.encodeByteString(scratch, (short) 0, (short) 37);
		// Tag 3, the signature of said data
		// Put the tag in
		cborEncoder.encodeUInt8((byte) 0x03);
		// Turns out this is DER encoding, again

		// Sign the data
		tempVars[3] = assertionCredentials[nextAssertion[0]].performSignature(scratch, (short) 0, (short) 69, scratch,
				(short) 69);
		// Create the ByteString to put it into
		cborEncoder.encodeByteString(scratch, (short) 69, tempVars[3]);
		// Tag 4, user details
		cborEncoder.encodeUInt8((byte) 0x04);
		// Start the PublicKeyCredentialUserEntity map

		// If we have "UV" enabled, then we do all the info we have.
		if (authenticatorGetAssertion.options[1]) {
			cborEncoder.startMap(assertionCredentials[nextAssertion[0]].userEntity.numData);
			// We need to check what we have for users
			// Iterate over the bit flags
			boolean[] usrFlags = assertionCredentials[nextAssertion[0]].getPresentUser();
			// This actually
			if (usrFlags[2]) {
				// Has the 'displayName' tag
				cborEncoder.encodeTextString(Utf8Strings.UTF8_DISPLAYNAME, (short) 0, (short) 11);
				cborEncoder.encodeTextString(assertionCredentials[nextAssertion[0]].userEntity.displayName.str, (short) 0,
						assertionCredentials[nextAssertion[0]].userEntity.displayName.len);
			}
			if (usrFlags[1]) {
				// The 'id' tag
				cborEncoder.encodeTextString(Utf8Strings.UTF8_ID, (short) 0, (short) 2);
				cborEncoder.encodeByteString(assertionCredentials[nextAssertion[0]].userEntity.id, (short) 0,
						(short) assertionCredentials[nextAssertion[0]].userEntity.id.length);
			}
			if (usrFlags[0]) {
				// The 'name'
				cborEncoder.encodeTextString(Utf8Strings.UTF8_NAME, (short) 0, (short) 4);
				cborEncoder.encodeTextString(assertionCredentials[nextAssertion[0]].userEntity.name.str, (short) 0,
						assertionCredentials[nextAssertion[0]].userEntity.name.len);
			}
			if (usrFlags[3]) {
				// Has the 'icon' tag
				cborEncoder.encodeTextString(Utf8Strings.UTF8_ICON, (short) 0, (short) 4);
				cborEncoder.encodeTextString(assertionCredentials[nextAssertion[0]].userEntity.icon, (short) 0,
						(short) assertionCredentials[nextAssertion[0]].userEntity.icon.length);
			}
		} else {
			// UV not enabled. Don't send extra info apart from the id field
			cborEncoder.startMap((short) 1);
			cborEncoder.encodeTextString(Utf8Strings.UTF8_ID, (short) 0, (short) 2);
			cborEncoder.encodeByteString(assertionCredentials[nextAssertion[0]].userEntity.id, (short) 0,
					(short) assertionCredentials[nextAssertion[0]].userEntity.id.length);
		}

		// Done tag 4
		if (mapLength == 5) {
			cborEncoder.encodeUInt8((byte) 0x05);
			cborEncoder.encodeUInt8((byte) assertionCredentials.length);
		}

	}

	// There's only so many ways to do this.
	public static boolean isCommandChainingCLA(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		// return true if bit4 is 1 in CLA
		return ((byte) (buf[0] & (byte) 0x10) == (byte) 0x10);
	}

	/**
	 * Gets 256 or fewer bytes from inBuf.
	 *
	 * @param apdu apdu buffer
	 */
	public void getData(APDU apdu) {
		if (outChainRam[0] > 256) {
			// More to go after this
			outChainRam[0] -= 256;
			byte[] buf = apdu.getBuffer();
			Util.arrayCopyNonAtomic(dataBuffer, outChainRam[1], buf, (short) 0, (short) 256);
			apdu.setOutgoingAndSend((short) 0, (short) 256);
			outChainRam[1] += 256;
			if (outChainRam[0] > 255) {
				// At least 256 to go, so 256 more
				ISOException.throwIt((short) 0x6100);
			} else {
				// Less than, so say how many bytes are left.
				ISOException.throwIt(Util.makeShort((byte) 0x61, (byte) outChainRam[0]));
			}
		} else {
			// This is the last message
			byte[] buf = apdu.getBuffer();
			Util.arrayCopyNonAtomic(dataBuffer, outChainRam[1], buf, (short) 0, outChainRam[0]);
			apdu.setOutgoingAndSend((short) 0, outChainRam[0]);
			isOutChaining[0] = false;
			outChainRam[0] = 0;
			outChainRam[1] = 0;
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}
	}

	/**
	 * Set chaining flags to send dataLen bytes from inLen via chaining, if
	 * necessary.
	 *
	 * @param apdu apdu buffer
	 */
	public void sendLongChaining(APDU apdu, short dataLen) {
		if (dataLen > 256) {
			// Set the chaining boolean to 1
			isOutChaining[0] = true;
			// All the bytes are in inBuf already
			// Set the chaining remainder to dataLen minus 256
			outChainRam[0] = (short) (dataLen - 256);
			// Send the first 256 bytes out
			byte[] buf = apdu.getBuffer();
			Util.arrayCopyNonAtomic(dataBuffer, (short) 0, buf, (short) 0, (short) 256);
			apdu.setOutgoingAndSend((short) 0, (short) 256);
			outChainRam[1] = 256;
			// Throw the 61 xx
			if (outChainRam[0] > 255) {
				// More than 255 (at least 256) to go, so 256 more
				ISOException.throwIt((short) 0x6100);
			} else {
				// Less than, so say how many bytes are left.
				ISOException.throwIt(Util.makeShort((byte) 0x61, (byte) outChainRam[0]));
			}
		} else {
			// Chaining not necessary, send in one go
			isOutChaining[0] = false;
			apdu.setOutgoing();
			apdu.setOutgoingLength(dataLen);
			apdu.sendBytesLong(dataBuffer, (short) 0, dataLen);
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}
	}

	private void getCert(APDU apdu) {
		dataBuffer[0] = 0x00;
		tempVars[0] = (short) (attestationKeyPair.getCert(dataBuffer, (short) 1) + 1);
		sendLongChaining(apdu, tempVars[0]);
	}

}
