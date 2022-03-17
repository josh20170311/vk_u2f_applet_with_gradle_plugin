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
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import static com.josh.vku2f.CTAP2ErrorCode.*;

public class CTAP2 extends Applet implements ExtendedLength {

    private final CBORDecoder cborDecoder;
    private final CBOREncoder cborEncoder;

    private byte[] inputBuffer;
    private byte[] scratch;
    private byte[] info;

    private final short[] tempVars;
    private final short[] chainRam;
    private final short[] outChainRam;
    private final short[] nextAssertion;

    private final MessageDigest sha256MessageDigest;
    private final AttestationKeyPair attestationKeyPair;

    private CredentialArray credentialArray;
    private AuthenticatorGetAssertion authenticatorGetAssertion;
    private AuthenticatorMakeCredential authenticatorMakeCredential;

    private final KeyPair ecDhKeyPair;
    private final boolean[] ecDhSet;
    private final boolean[] isChaining;
    private final boolean[] isOutChaining;
    private boolean personalizeComplete;

    private StoredCredential tempCredential;
    private StoredCredential[] assertionCredentials;

    public static final byte ISO_INS_GET_DATA = (byte) 0xC0;
    public static final byte FIDO2_INS_NFCCTAP_MSG = (byte) 0x10;

    public static final byte FIDO2_AUTHENTICATOR_MAKE_CREDENTIAL =      (byte) 0x01;
    public static final byte FIDO2_AUTHENTICATOR_GET_ASSERTION =        (byte) 0x02;
    public static final byte FIDO2_AUTHENTICATOR_GET_NEXT_ASSERTION =   (byte) 0x08;
    public static final byte FIDO2_AUTHENTICATOR_GET_INFO =             (byte) 0x04;
    public static final byte FIDO2_AUTHENTICATOR_CLIENT_PIN =           (byte) 0x06;
    public static final byte FIDO2_AUTHENTICATOR_RESET =                (byte) 0x07;
    // Vendor specific - for attestation cert loading.
    public static final byte FIDO2_VENDOR_ATTEST_SIGN =                 (byte) 0x41;
    public static final byte FIDO2_VENDOR_ATTEST_LOADCERT =             (byte) 0x42;
    public static final byte FIDO2_VENDOR_PERSO_COMPLETE =              (byte) 0x43;
    public static final byte FIDO2_VENDOR_ATTEST_GETPUB =               (byte) 0x44;
    public static final byte FIDO2_VENDOR_GET_COUNT =                   (byte) 0x45;
    public static final byte FIDO2_VENDOR_ATTEST_GETCERT =              (byte) 0x4A;

    public static final byte FIDO2_DESELECT = 0x12;

    // AAGUID - Authenticator Attestation Global Unique Identifier
    // this uniquely identifies the type of authenticator we have built.
    // If you're reusing this code, please generate your own GUID and put it here -
    // this is unique to manufacturer and device model.
    public static final byte[] aaguid = {
            (byte) 't', (byte) 'e', (byte) 's', (byte) 't', (byte) 'g', (byte) 'u', (byte) 'i', (byte) 'd',
            (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };

    private CTAP2() {

        // 1210 bytes of a transient buffer for read-in and out
        // We advertise 1200 bytes supported, but 10 bytes for protocol nonsense
        try {
            inputBuffer = JCSystem.makeTransientByteArray((short) 1210, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            inputBuffer = new byte[1210];
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
        ECPublicKey ecDhPub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PUBLIC,
                JCSystem.MEMORY_TYPE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
        ECPrivateKey ecDhPriv = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
                JCSystem.MEMORY_TYPE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
        ecDhKeyPair = new KeyPair(ecDhPub, ecDhPriv);
        ecDhSet = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_RESET);

    }

    public void handle(APDU apdu) {
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
        switch (inputBuffer[0]) {
            case FIDO2_AUTHENTICATOR_MAKE_CREDENTIAL:
                authMakeCredential(apdu, tempVars[3]);
                break;
            case FIDO2_AUTHENTICATOR_GET_ASSERTION:
                authGetAssertion(apdu, tempVars[3]);
                break;
            case FIDO2_AUTHENTICATOR_GET_INFO:
                authGetInfo(apdu);
                break;
            case FIDO2_AUTHENTICATOR_GET_NEXT_ASSERTION:
                authGetNextAssertion(apdu, buffer);
                break;
            case FIDO2_VENDOR_ATTEST_SIGN: //0x41
                attestSignRaw(apdu, tempVars[3]);
                break;
            case FIDO2_AUTHENTICATOR_CLIENT_PIN:
                clientPin(apdu, tempVars[3]);
                break;
            case FIDO2_VENDOR_ATTEST_LOADCERT: //0x42
                attestSetCert(apdu, tempVars[3]);
                break;
            case FIDO2_VENDOR_PERSO_COMPLETE: //0x43
                persoComplete(apdu);
                break;
            case FIDO2_VENDOR_ATTEST_GETPUB: //0x44
                getAttestPublic(apdu);
                break;
            case FIDO2_VENDOR_ATTEST_GETCERT: //0x4a
                getCert(apdu);
                break;
            case FIDO2_VENDOR_GET_COUNT: //0x45
                getCount(apdu);
                break;
            case FIDO2_AUTHENTICATOR_RESET: //0x07
                // Need to finish doing this, we can, I mean, but I don't like it
                doReset(apdu);
                break;
            default:
                returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
        }

    }

    public void persoComplete(APDU apdu) {
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
    public void getAttestPublic(APDU apdu) {
        if (personalizeComplete) {
            returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
            return;
        }
        inputBuffer[0] = 0x00;
        tempVars[0] = (short) (attestationKeyPair.getPubkey(inputBuffer, (short) 1) + 1);
        apdu.setOutgoing();
        apdu.setOutgoingLength(tempVars[0]);
        apdu.sendBytesLong(inputBuffer, (short) 0, tempVars[0]);
    }

    /** get counter's value */
    public void getCount(APDU apdu){
        short count = credentialArray.getCount();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)2);
        Util.setShort(inputBuffer,(short)0, count);
        apdu.sendBytesLong(inputBuffer,(short)0,(short)2);
    }

    /**
     * Performs raw signatures, may only occur when personalisation is not complete.
     *
     * @param apdu apdu buffer
     * @param bufLen buffer length
     */
    public void attestSignRaw(APDU apdu, short bufLen) {
        if (personalizeComplete) {
            returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
            return;
        }
        Util.arrayCopy(inputBuffer, (short) 1, scratch, (short) 0, (short) (bufLen - 1));
        inputBuffer[0] = 0x00;
        tempVars[2] = attestationKeyPair.sign(scratch, (short) 0, tempVars[1], inputBuffer, (short) 1);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (tempVars[2] + 1));
        apdu.sendBytesLong(inputBuffer, (short) 0, (short) (tempVars[2] + 1));
    }

    public void attestSetCert(APDU apdu, short bufLen) {
        if (personalizeComplete) {
            returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
            return;
        }
        // We don't actually use any CBOR here, simplify copying
        attestationKeyPair.setCert(inputBuffer, (short) 1, (short) (bufLen - 1));
        MessageDigest dig = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        short len = (short) (dig.doFinal(attestationKeyPair.x509cert, (short) 0, attestationKeyPair.x509len, inputBuffer, (short) 3) + 3);
        inputBuffer[0] = 0x00;
        Util.setShort(inputBuffer, (short) 1, attestationKeyPair.x509len);
        apdu.setOutgoing();
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(inputBuffer, (short) 0, len);
    }

    public void authMakeCredential(APDU apdu, short bufLen) {
        // Init the decoder
        cborDecoder.init(inputBuffer, (short) 1, bufLen);
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
            inputBuffer[0] = 0x00;
            cborEncoder.init(inputBuffer, (short) 1, (short) 1199);
            // Create a map in the buffer
            tempVars[0] = cborEncoder.startMap((short) 3);

            // Attestation stuff
            cborEncoder.writeRawByte((byte) 0x01);
            cborEncoder.encodeTextString(Utf8Strings.UTF8_PACKED, (short) 0, (short) 6);

            // Put the authdata identifier there
            cborEncoder.writeRawByte((byte) 0x02);
            // Allocate some space for the byte string
            tempVars[0] = cborEncoder.startByteString((short) (37 + tempCredential.getAttestedLen()));
            // Stash where it begins
            tempVars[7] = tempVars[0];
            // Create the SHA256 hash of the RP ID
            tempCredential.rpEntity.getRp(scratch, (short) 0);
            tempVars[0] += sha256MessageDigest.doFinal(scratch, (short) 0, tempCredential.rpEntity.getRpLen(), inputBuffer, tempVars[0]);
            // Set flags - User presence, user verified, attestation present
            inputBuffer[tempVars[0]++] = (byte) 0x45;
            // Set the signature counter
            tempVars[0] += tempCredential.readCounter(inputBuffer, tempVars[0]);
            // Read the credential details in
            // Just note down where this starts for future ref
            tempVars[0] += tempCredential.getAttestedData(inputBuffer, tempVars[0]);

            // Generate and then attach the attestation
            cborEncoder.writeRawByte((byte) 0x03);
            // Start to build into the cbor array manually, to avoid arrayCopy

            // Create a map with 3 things

            cborEncoder.startMap((short) 3);
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
            attestationKeyPair.update(inputBuffer, tempVars[7], (short) (tempCredential.getAttestedLen() + 37));
            // The client data hash is next, which we use to finish off the signature.
            tempVars[4] = attestationKeyPair.sign(authenticatorMakeCredential.dataHash, (short) 0, (short) authenticatorMakeCredential.dataHash.length, scratch, (short) 0);
            // Create the byte string for the signature
            cborEncoder.encodeByteString(scratch, (short) 0, tempVars[4]);
            // Set the x509 cert now
            cborEncoder.encodeTextString(Utf8Strings.UTF8_X5C, (short) 0, (short) 3);
            // Supposedly we need an array here
            cborEncoder.startArray((short) 1);
            cborEncoder.encodeByteString(attestationKeyPair.x509cert, (short) 0, attestationKeyPair.x509len);
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
        cborDecoder.init(inputBuffer, (short) 1, bufLen);
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
        inputBuffer[0] = 0x00;
        // Create the encoder
        cborEncoder.init(inputBuffer, (short) 1, (short) 1199);
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
     * @param apdu apdu buffer
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
            inputBuffer[0] = 0x00;
            // Create the encoder
            cborEncoder.init(inputBuffer, (short) 1, (short) 1199);
            doAssertionCommon(cborEncoder, (short) 4);

            nextAssertion[0]++;
            // Emit this as a response
            sendLongChaining(apdu, cborEncoder.getCurrentOffset());
        }
    }

    // Process the AuthenticatorClientPin feature
    // Note: we only implement the keyAgreement bit
    public void clientPin(APDU apdu, short bufLen) {
        try {
            cborDecoder.init(inputBuffer, (short) 1, bufLen);
            // Start reading
            cborDecoder.readMajorType(CBORBase.TYPE_MAP);
            // Read pinUvAuthProtocol
            if (cborDecoder.readInt8() != (byte) 0x01) {
                UserException.throwIt(CTAP2_ERR_INVALID_CBOR);
                return;
            }
            // Read subCommand
            if (cborDecoder.readInt8() != (byte) 0x01) {
                UserException.throwIt(CTAP2_ERR_INVALID_CBOR);
                return;
            }
            // Subcommand now
            if (cborDecoder.readInt8() != (byte) 0x02) {
                UserException.throwIt(CTAP2_ERR_INVALID_CBOR);
                return;
            }
            // Actual subcommand
            switch (cborDecoder.readInt8()) {
                case 0x02:
                    // Seems to be a Diffie-Hellman thing
                    generateDH(apdu);
                    break;
                default:
                    UserException.throwIt(CTAP2_ERR_UNSUPPORTED_OPTION);
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

    // Generate a session-specific ECDH P-256 key for Diffie-Hellman with the
    // platform (Used for PIN ,but we only ever do it for hmac-secret)
    private void generateDH(APDU apdu) {
        byte[] w;
        try {
            w = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            w = new byte[65];
        }

        

        if (!ecDhSet[0]) {
            // Grab the public key and set its parameters
            KeyParams.sec256r1params((ECKey) ecDhKeyPair.getPublic());
            // Generate a new key-pair
            ecDhKeyPair.genKeyPair();
        }

        ((ECPublicKey) ecDhKeyPair.getPublic()).getW(w, (short) 0);
        // Return the data requested
        inputBuffer[0] = 0x00;
        cborEncoder.init(inputBuffer, (short) 1, (short) 1199);
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
        cborEncoder.encodeNegativeUInt8((byte) 0x06);
        // Crv tag - negative
        cborEncoder.encodeNegativeUInt8((byte) 0x00);
        // Crv value - P-256
        cborEncoder.encodeUInt8((byte) 0x01);
        // X-coord tag
        cborEncoder.encodeNegativeUInt8((byte) 0x01);
        // X-coord value
        cborEncoder.encodeByteString(w, (short) 1, (short) 32);
        // Y-coord tag
        cborEncoder.encodeNegativeUInt8((byte) 0x02);
        // Y-coord value
        cborEncoder.encodeByteString(w, (short) 33, (short) 32);
        // That's it
        sendLongChaining(apdu, cborEncoder.getCurrentOffset());
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
     * @param apdu   shared APDU object
     * @param err    error code
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
     * @param apdu   shared APDU object
     * @param err    error code
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
    public void authGetInfo(APDU apdu) {
        // Create the authenticator info if not present.
        if (info == null) {
            // Create the authGetInfo - 0x00 is success
            inputBuffer[0] = 0x00;
            cborEncoder.init(inputBuffer, (short) 1, (short) 1199);
            cborEncoder.startMap((short) 4);
            // 0x01, versions
            cborEncoder.encodeUInt8((byte) 0x01);
            // Value is an array of strings
            cborEncoder.startArray((short) 1);
            // Type 1, FIDO2
            cborEncoder.encodeTextString(Utf8Strings.UTF8_FIDO2, (short) 0, (short) 8);
            // AAGUID, 0x03
            cborEncoder.encodeUInt8((byte) 0x03);
            cborEncoder.encodeByteString(aaguid, (short) 0, (short) 16);
            // Options, 0x04
            cborEncoder.encodeUInt8((byte) 0x04);
            // Map of 3
            cborEncoder.startMap((short) 3);
            // Rk
            cborEncoder.encodeTextString(Utf8Strings.UTF8_RK, (short) 0, (short) 2);
            cborEncoder.encodeBoolean(true);
            // UP
            cborEncoder.encodeTextString(Utf8Strings.UTF8_UP, (short) 0, (short) 2);
            cborEncoder.encodeBoolean(true);
            // UV
            cborEncoder.encodeTextString(Utf8Strings.UTF8_UV, (short) 0, (short) 2);
            cborEncoder.encodeBoolean(true);
            // Max msg size, 0x05
            cborEncoder.encodeUInt8((byte) 0x05);
            cborEncoder.encodeUInt16((short) 1200);
            // Done
            JCSystem.beginTransaction();
            info = new byte[cborEncoder.getCurrentOffset()];
            Util.arrayCopy(inputBuffer, (short) 0, info, (short) 0, cborEncoder.getCurrentOffset());
            JCSystem.commitTransaction();
        }
        // Send it
        Util.arrayCopyNonAtomic(info, (short) 0, inputBuffer, (short) 0, (short) info.length);
        sendLongChaining(apdu, (short) info.length);
    }

    /**
     * Covers the common assertion building process.
     * 
     * @param encoder CBOR Encoder
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
    static boolean isCommandChainingCLA(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        return ((byte) (buf[0] & (byte) 0x10) == (byte) 0x10);
    }

    /**
     * Handle the command chaining or extended APDU logic.
     * 
     * Due to the FIDO2 spec requiring support for both extended APDUs and command
     * chaining, we need to implement chaining here.
     * 
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
            chainRam[0] = Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), inputBuffer, chainRam[0], chainRam[1]);
            return 0x00;
        } else if (isChaining[0]) {
            // Must be the last of the chaining - make the copy and return the length.
            chainRam[1] = tempVars[4];
            chainRam[0] = Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), inputBuffer, chainRam[0], chainRam[1]);
            isChaining[0] = false;
            isChaining[1] = true;
            return chainRam[0];
        } else if (tempVars[3] == 0x01) {
            inputBuffer[0] = buffer[apdu.getOffsetCdata()];
            return 0x01;
        } else if (apdu.getCurrentState() == APDU.STATE_FULL_INCOMING) {
            // We need to do no more
            // Read the entirety of the buffer into the inBuf
            Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), inputBuffer, (short) 0, tempVars[3]);
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
                tempVars[4] = Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), inputBuffer, tempVars[4], tempVars[5]);
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
            Util.arrayCopyNonAtomic(inputBuffer, outChainRam[1], buf, (short) 0, (short) 256);
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
            Util.arrayCopyNonAtomic(inputBuffer, outChainRam[1], buf, (short) 0, outChainRam[0]);
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
            Util.arrayCopyNonAtomic(inputBuffer, (short) 0, buf, (short) 0, (short) 256);
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
            apdu.sendBytesLong(inputBuffer, (short) 0, dataLen);
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
    }

    /**
     * Checks if chaining is set for U2FApplet
     * 
     * @return if it is chaining
     */
    public boolean isChaining() {
        return isOutChaining[0];
    }

    private void getCert(APDU apdu) {
        inputBuffer[0] = 0x00;
        tempVars[0] = (short) (attestationKeyPair.getCert(inputBuffer, (short) 1) + 1);
        sendLongChaining(apdu, tempVars[0]);
    }

    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()) {
            Util.arrayCopyNonAtomic(Utf8Strings.UTF8_FIDO2, (short) 0, buffer, (short) 0,
                    (short) Utf8Strings.UTF8_FIDO2.length);
            apdu.setOutgoingAndSend((short) 0, (short) Utf8Strings.UTF8_FIDO2.length);
            return;
        }

        if (!apdu.isCommandChainingCLA() && apdu.isISOInterindustryCLA()) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        JCSystem.requestObjectDeletion();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case ISO_INS_GET_DATA:
                if (isChaining()) {
                    getData(apdu);
                } else {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                break;
            case FIDO2_INS_NFCCTAP_MSG: // 0x10
                handle(apdu);
                break;
            case FIDO2_DESELECT:
                // Appears to be a reset function in the FIDO2 spec, but never referenced
                // anywhere
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

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

}
