package alessandrosalerno.smift.libsmift;


import java.io.File;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import alessandrosalerno.smift.libsmift.smift03.SMIFT03Certificate;

public class Main {
    public static void main(String[] args) throws Exception {
        KeyPair nodeKeys = SMIFTUtils.RSA.newPair(4096);
        KeyPair smiftKeys = SMIFTUtils.RSA.newPair(4096);
        SMIFT03Certificate cert1 = SMIFT03Certificate.generate("My node",
                                                                (RSAPublicKey) nodeKeys.getPublic(),
                                                                (RSAPrivateKey) nodeKeys.getPrivate(),
                                                                (RSAPublicKey) smiftKeys.getPublic(),
                                                                (RSAPrivateKey) smiftKeys.getPrivate(), 30);
        cert1.toFile(new File("./cert"));
        SMIFT03Certificate cert2 = SMIFT03Certificate.fromFile(new File("./cert"));

        System.out.println(" hell: " + cert1.getSmiftNameSignatureissuerSignature().equals(cert2.getSmiftNameSignatureissuerSignature()));
    }
}
