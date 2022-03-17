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
import static com.josh.vku2f.CTAP2ErrorCode.*;

/**
 * Dynamically resizable credential storage array. Gracefully handles space errors.
 */
public class CredentialArray {
    private StoredCredential[] credentials;
    private boolean[] slotStatus;
    private short size;
    private short i; // for loop counter
    private short count = 0;//the number of creds in the array


    /**
     * Constructor for a CredentialArray.
     * @param initialSize Initial sizing for the CredentialArray.
     */
    public CredentialArray(short initialSize) {
        credentials = new StoredCredential[initialSize];
        slotStatus = new boolean[initialSize];
        size = initialSize;
    }
    /**
     * Adds a new credential to the first free slot, or overwrites if a matching rp and user id matches.
     * @param newCredential the StoredCredential object to be stored.
     */
    public void addCredential(StoredCredential newCredential) throws UserException{
        try {
            short slot = checkExists(newCredential);
            credentials[slot] = newCredential;
            slotStatus[slot] = true;
            count = (short)(slot + 1);
        } catch (Exception e) {
            UserException.throwIt(CTAP2_ERR_KEY_STORE_FULL);
        }
    }
    /**
     * Finds and returns a StoredCredential given the rpId and userId, returns null if not present.
     * @param rpId
     * @ param off
     * @ param len
     * @ return
     */
    public StoredCredential getCredential(byte[] rpId, short rpOff, short rpLen, byte[] userId, short userOff, short userLen) {
        for(i = 0; i < size; i++) {
            // Check the slot status, if the RP matches, and then if the user matches. If so, return the credential.
            if(slotStatus[i] && credentials[i].rpEntity.checkId(rpId, rpOff, rpLen) && credentials[i].userEntity.checkId(userId, userOff, userLen)) {
                return credentials[i];
            }
        }
        return null;
    }
    
    
    
    /**
     * Confirms there is no already existing discoverable credential - if it finds one, it returns its location for overwriting.
     * @return the location of a discoverable credential already matching the RP and User IDs, or the first free slot otherwise.
     */
    public short checkExists(StoredCredential newCredential) {
        for(i = 0; i < size; i++) {
            // Check the slot status, if the RP matches, and then if the user matches. If so, return the slot to use.
            if(slotStatus[i] &&
                    credentials[i].rpEntity.checkId(newCredential.rpEntity) &&
                    credentials[i].userEntity.checkId(newCredential.userEntity)) {
                return i;
            }
        }
        // Find the first free slot
        for(i = 0; i < size; i++) {
            if(!slotStatus[i]) {
                return i;
            } 
        }
        // No free slots

        // Add more
        StoredCredential[] tmp = new StoredCredential[size];
        boolean[] tmpStatus = new boolean[size];
        for(i = 0; i < size; i++) {
            // SonarLint throws an error here, but JavaCard can only copy byte arrays
            tmp[i] = credentials[i];
            tmpStatus[i] = slotStatus[i];
        }
        credentials = new StoredCredential[(short) (size*2)];
        slotStatus = new boolean[(short) (size*2)];
        for(i = 0; i < size; i++) {
            credentials[i] = tmp[i];
            slotStatus[i] = tmpStatus[i];
        }
        // Actually double the size....
        size *= (short) 2;
        // Delete objects we used to copy
        JCSystem.requestObjectDeletion();
        // Return the first free slot in the new array, which is going to be the counter plus 1
        return ++i;
    }
    /**
     * Get the size of the array.
     * @return the array size
     */
    public short getLength() {
        return size;
    }

    public short getCount(){
        return count;
    }
    /**
     * Returns the credential at position, or null if none.
     * @param position the position to get.
     * @return the credential, or null.
     */
    public StoredCredential get(short position) {
        return credentials[position];
    }
    
}
