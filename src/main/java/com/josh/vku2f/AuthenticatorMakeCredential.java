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

import javacard.framework.JCSystem;
import javacard.framework.UserException;
import javacard.framework.Util;
import static com.josh.vku2f.CTAP2ErrorCode.*;

public class AuthenticatorMakeCredential {
    public byte[] dataHash;
    private PublicKeyCredentialRpEntity rp;
    private PublicKeyCredentialUserEntity user;
    private PublicKeyCredentialParams params;
    private boolean[] options = new boolean[2];

    public PublicKeyCredentialDescriptor[] exclude;

    /**
     * Parses a CBOR structure to create an AuthenticatorMakeCredential object
     * 
     * @param decoder the initialised decoder on the CBOR structure
     * @ param vars    a short array to store variables in
     */
    public AuthenticatorMakeCredential(CBORDecoder decoder) throws UserException {
        short[] vars;
        try {
            vars = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            vars = new short[8];
        }
        // Start reading, we should get a map
        byte[] scratch1;
        try {
            scratch1 = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            scratch1 = new byte[64];
        }
        byte[] scratch2;
        try {
            scratch2 = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            scratch2 = new byte[64];
        }
        short len1 = decoder.readMajorType(CBORBase.TYPE_MAP);
        // options[0] is rk - default true for us
        // options[1] is uv - default false
        options[0] = true;
        options[1] = false;
        // We now have the number of objects in the map
        // Read all the objects in map
        for (short i = 0; i < len1; i++) {
            // Read the ID type
            short type = decoder.readInt8();
            // Do based on the ID
            short len2;
            switch (type) {
                case (short) 1:
                    // Grab and store the data hash
                    len2 = decoder.readByteString(scratch1, (short) 0);
                    dataHash = new byte[len2];
                    Util.arrayCopy(scratch1, (short) 0, dataHash, (short) 0, len2);
                    break;
                case (short) 2:
                    // Rp object, create it
                    rp = new PublicKeyCredentialRpEntity();
                    // Read the map length - should be 2
                    len2 = decoder.readMajorType(CBORBase.TYPE_MAP);
                    // If less than 2, error
                    if (len2 < (short) 2) {
                        UserException.throwIt(CTAP2_ERR_INVALID_CBOR);
                    }
                    // Read the map iteratively
                    for (short j = 0; j < len2; j++) {
                        // Read the text string in
                        decoder.readTextString(scratch1, (short) 0);
                        // Check if it equals id
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_ID, (short) 0,
                                (short) 2) == (byte) 0) {
                            // It does, so read its length
                            short len3 = decoder.readTextString(scratch1, (short) 0);
                            // Set it
                            rp.setRp(scratch1, len3);
                        } else
                        // Check if it equals name, if not id
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_NAME, (short) 0,
                                (short) 4) == (byte) 0) {
                            // Read the string into scratch
                            short len3 = decoder.readTextString(scratch1, (short) 0);
                            // Set it
                            rp.setName(scratch1, len3);
                        }

                    }
                    break;
                case (short) 3:

                    // UserEntity, create
                    user = new PublicKeyCredentialUserEntity();
                    // Read the map length
                    len2 = decoder.readMajorType(CBORBase.TYPE_MAP);
                   
                    // Read the map iteratively
                    for (short j = 0; j < len2; j++) {
                            // Read the text string in
                        decoder.readTextString(scratch1, (short) 0);
                        // Check if it equals id
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_ID, (short) 0,
                                (short) 2) == (byte) 0) {
                            // Read the string into scratch
                            short len3 = decoder.readByteString(scratch1, (short) 0);
                            // Set it
                            user.setId(scratch1, (short) 0, len3);
                        } else
                        // Check if it equals name, if not id
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_NAME, (short) 0,
                                (short) 4) == (byte) 0) {
                            // Read the string into scratch
                            short len3 = decoder.readTextString(scratch1, (short) 0);
                            // Set it
                            user.setName(scratch1, len3);
                        } else
                        // Check if it equals displayName, if not those
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_DISPLAYNAME, (short) 0,
                                (short) 11) == (byte) 0) {
                            // Read the string into scratch
                            short len3 = decoder.readTextString(scratch1, (short) 0);
                            // Set it
                            user.setDisplayName(scratch1, len3);
                        } else
                        // If icon, even
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_ICON, (short) 0, (short) 4) == (byte) 0) {
                                // Read the string into scratch
                            short len3 = decoder.readTextString(scratch2, (short) 0);
                            user.setIcon(scratch2, len3);
                        } else  {
                            // Is optional, so we need to skip the value
                            decoder.skipEntry();
                        }

                    }
                    break;
                case (short) 4:
                    len2 = decoder.readMajorType(CBORBase.TYPE_ARRAY);

                    // Create the params object
                    params = new PublicKeyCredentialParams(len2);
                    // Process the array
                    for (short j = 0; j < len2; j++) {
                        // Read the map length - should be 2
                        short len3 = decoder.readMajorType(CBORBase.TYPE_MAP);
                        if(len3 != 2) {
                            UserException.throwIt(CTAP2_ERR_INVALID_CBOR);
                        }
                        // Iterate over the map
                        for (short k = 0; k < (short) 2; k++) {
                            decoder.readTextString(scratch1, (short) 0);
                            if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_ALG, (short) 0,
                                    (short) 3) == (byte) 0) {
                                // Read the integer type (positive or negative)
                                if (decoder.getMajorType() == CBORBase.TYPE_UNSIGNED_INTEGER) {
                                    // Positive number
                                    len3 = decoder.readEncodedInteger(scratch2, (short) 0);
                                    if (len3 == 1) {
                                        // Single byte
                                        params.addAlgorithm(scratch2[0]);
                                    } else if (len3 == 2) {
                                        // A full short
                                        params.addAlgorithm(Util.makeShort(scratch2[0], scratch2[1]));
                                    }
                                } else if (decoder.getMajorType() == CBORBase.TYPE_NEGATIVE_INTEGER) {
                                    // Negative
                                    len3 = decoder.readEncodedInteger(scratch2, (short) 0);
                                    if (len3 == 1) {
                                        params.addAlgorithm((short) (-1 - scratch2[0]));
                                    } else if (len3 == 2) {
                                        // Full short
                                        params.addAlgorithm((short) (-1 - Util.makeShort(scratch2[0], scratch2[1])));
                                    }
                                }

                            } else if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_TYPE, (short) 0, (short) 4) == (byte) 0) {
                                // Public key type
                                // Check it
                                decoder.readTextString(scratch1, (short) 0);
                                if(Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_PUBLIC_KEY, (short) 0, (short) 10) != (byte) 0) {
                                    UserException.throwIt(CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                                }
                            } else {
                                UserException.throwIt(CTAP2_ERR_INVALID_CBOR);
                            }
                        }
                        // Done
                    }

                    break;
                case (short) 5:
                    // Credential exclusion stuff
                    // Parse it
                    len2 = decoder.readMajorType(CBORBase.TYPE_ARRAY);
                    exclude = new PublicKeyCredentialDescriptor[len2];
                    for (short j = 0; j < len2; j++) {
                        // Read the map. It has 2 things in it.
                        short len3 = decoder.readMajorType(CBORBase.TYPE_MAP);
                        if (len3 != 2) {
                            UserException.throwIt(CTAP2_ERR_INVALID_CBOR);
                        }
                        // Parse it, properly
                        for(short k = 0; k < (short) 2; k++) {
                            decoder.readTextString(scratch1, (short) 0);
                            if(Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_ID, (short) 0, (short) 2) == (byte) 0) {
                                // Read the actual id
                                len3 = decoder.readByteString(scratch1, (short) 0);
                                exclude[j] = new PublicKeyCredentialDescriptor(scratch1, (short) 0, len3);
                            } else if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_TYPE, (short) 0, (short) 4) == (byte) 0) {
                                // Read the type field, it must be text
                                decoder.readTextString(scratch1, (short) 0);
                                // It doesn't matter what it is, just check it's string and exists.
                            } else {
                                // If it's not these two, throw an error
                                UserException.throwIt(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                                break;
                            }
                        }

                    }
                    break;
                case (short) 7:
                    // Options map
                    // Parse the two rk and uv objects
                    // Read the map
                    if(decoder.getMajorType() != CBORBase.TYPE_MAP) {
                        UserException.throwIt(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                        break;
                    }
                    len2 = decoder.readMajorType(CBORBase.TYPE_MAP);
                    for (short j = 0; j < len2; j++) {
                        // Parse the map
                        decoder.readTextString(scratch1, (short) 0);
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_UV, (short) 0,
                                (short) 2) == (short) 0) {
                            // Is the user validation bit
                            options[1] = decoder.readBoolean();
                        } else 
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_RK, (short) 0,
                                (short) 2) == (short) 0) {
                            // Is the resident key bit
                            decoder.readBoolean();
                        } else if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_UP, (short) 0, (short) 2) == (short) 0) {
                            // Error out
                            UserException.throwIt(CTAP2_ERR_INVALID_OPTION);
                            break;
                        } else {
                            // Skip it
                            decoder.skipEntry();
                        }
                    }
                    break;
                
                case (short) 6:
                    // Extensions
                    // We don't support any yet
                    // So check it's a map and skip
                    if(decoder.getMajorType() != CBORBase.TYPE_MAP) {
                        UserException.throwIt(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                        break;
                    }
                    decoder.skipEntry();
                    break;
                default:
                    // Skip it transparently
                    decoder.skipEntry();
                    break;

            }
            

        }
        // Check we've got stuff like the clientDataHash
        if(dataHash == null || rp == null || user == null || params == null) {
            UserException.throwIt(CTAP2_ERR_MISSING_PARAMETER);
        }

        // We're done, I guess
    }

    public PublicKeyCredentialUserEntity getUser() {
        return user;
    }

    public PublicKeyCredentialRpEntity getRp() {
        return rp;
    }

    public boolean isResident() {
        return options[0];
    }

    public byte getAlgorithm() {
        return params.getAlgorithm();
    }

    public boolean isExclude() {
        return (exclude != null && exclude.length > 0);
    }

    /**
     * Reads the clientDataHash into a buffer.
     * 
     * @param outBuf The buffer to read into.
     * @param outOff the offset to begin at.
     * @return the length of the data read out.
     */
    public short getDataHash(byte[] outBuf, short outOff) {
        Util.arrayCopy(dataHash, (short) 0, outBuf, outOff, (short) dataHash.length);
        return (short) dataHash.length;
    }

}
