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

import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacardx.crypto.Cipher;
import javacard.security.RSAPublicKey;

public class StoredRS256Credential extends StoredCredential {
    Cipher kpSignature;

    public StoredRS256Credential(AuthenticatorMakeCredential inputData) {
        // Generate a new RS256 credential
        kp = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
        kp.genKeyPair();
        user = inputData.getUser();
        rp = inputData.getRp();
        kpSignature = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        kpSignature.init(kp.getPrivate(), Cipher.MODE_ENCRYPT);
    }


    public short performSignature(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        incrementCounter();
        // Increment sig counter first
        return kpSignature.doFinal(inBuf, inOff, inLen, outBuf, outOff);

    }

    public short getAttestedLen() {
        // AAGUID (16), 0010 (2), Credential ID (16), map (1 byte header + 7 bytes type
        // and alg + 260 bytes mod inc header, 5 bytes exp inc header)
        return (short) 307;
    }

    public short getAttestedData(byte[] buf, short off) {
        CBOREncoder enc = new CBOREncoder();
        doAttestationCommon(buf, off);
        // Start the public key CBOR
        enc.init(buf, (short) (off + 34), (short) 1000);
        enc.startMap((short) 4);
        // kty - key type
        enc.writeRawByte((byte) 0x01);
        // RSA
        enc.encodeUInt8((byte) 0x03);
        // alg
        enc.writeRawByte((byte) 0x03);
        // RS256 - -257 is 256 negative (minus 1 for neg on CBOR)
        enc.encodeNegativeUInt16((short) 256);
        // Modulus tag
        enc.encodeNegativeUInt8((byte) 0x00);
        // Write the modulus
        short start = enc.startByteString((short) 256);
        ((RSAPublicKey) kp.getPublic()).getModulus(buf, start);
        // Exponent tag
        enc.encodeNegativeUInt8((byte) 0x01);
        // Write the exponent
        start = enc.startByteString((short) 3);
        ((RSAPublicKey) kp.getPublic()).getExponent(buf, start);
        return 306;
    }

}
