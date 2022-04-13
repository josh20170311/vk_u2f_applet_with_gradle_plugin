package com.josh.vku2f;

public class COSEKey {
    private byte[] w ;
    COSEKey(){
        w = new byte[64];
    }


    public void setW(byte[] w){
        this.w = w;
    }
    public byte[] getW(){
        return w;
    }
    public void encode(CBOREncoder cborEncoder){
    }
}
