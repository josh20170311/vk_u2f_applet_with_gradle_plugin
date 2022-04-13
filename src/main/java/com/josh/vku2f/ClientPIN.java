package com.josh.vku2f;

import javacard.framework.JCSystem;

public class ClientPIN {
    private short i; // counter
    private byte[] PIN ;
    private boolean[] checked;
    ClientPIN(){
        checked = JCSystem.makeTransientBooleanArray((short)1, JCSystem.CLEAR_ON_DESELECT);
    }
    public boolean checkPIN(byte[] pin){
        if(PIN.length != pin.length){
            return false;
        }
        for(i = 0; i < PIN.length; i++){
            if(PIN[i] != pin[i]) {
                return false;
            }
        }
        checked[0] = true;
        return true;
    }

    public void setPIN(){

    }
}
