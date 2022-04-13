package com.josh.vku2f;

public class PinUvAuthToken {
    private byte[] token;
    private byte protocol;
    private byte permissionsRPID ;
    private byte permissionsSet;
    private byte usageTimer;
    private boolean inUseFlag;
    private byte initialUsageTimeLimit;
    private byte userPresentTimeLimit;
    private byte maxUsageTimePeriod;
    private boolean userVerifiedFlag;
    private boolean userPresentFlag;
    PinUvAuthToken(){
        resetTokenState();
    }
    public void generateNewToken(){

    }
    public void resetTokenState(){
        permissionsRPID = 0x00;
        permissionsSet = 0x00;
        usageTimer = 0x00;
        inUseFlag = false;
        initialUsageTimeLimit = 0x00;
        userPresentTimeLimit = 0x00;
        maxUsageTimePeriod = 0x00;
        userVerifiedFlag = false;
        userPresentFlag = false;
    }
    public boolean isInUse(){
        return inUseFlag;
    }
}
