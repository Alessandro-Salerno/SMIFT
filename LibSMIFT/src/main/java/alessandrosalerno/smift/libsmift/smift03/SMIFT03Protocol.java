package alessandrosalerno.smift.libsmift.smift03;

import java.awt.RenderingHints.Key;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

import alessandrosalerno.smift.libsmift.SMIFTChannel;
import alessandrosalerno.smift.libsmift.SMIFTMessage;
import alessandrosalerno.smift.libsmift.SMIFTProtocol;
import alessandrosalerno.smift.libsmift.SMIFTProtocolHook;
import alessandrosalerno.smift.libsmift.SMIFTUtils;
import alessandrosalerno.smift.libsmift.SMIFTUtils.Strings;

public class SMIFT03Protocol implements SMIFTProtocol {
    public static class Messages {
        public static class Requests {
            public static final String HELLO = "HELLO";
            public static final String AUTHENTICATE = "AUTHENTICATE";
            public static final String PROPOSE = "PROPOSE";
            public static final String END_LIST = "END LIST";
            public static final String VERIFY = "VERIFY";
            public static final String ENCRYPT = "ENCRYPT";
            public static final String GOODBYE = "GOODBYE";
        }

        public static class Responses {
            public static class Success {
                public static final String HELLO_200_OK = "HELLO 200 OK";
                public static final String AUTHENTICATE_201_OK = "AUTHENTICATE 201 OK";
                public static final String PROPOSE_202_OK = "PROPOSE 202 OK";
                public static final String VERIFY_203_OK = "VERIFY 203 OK";
                public static final String ENCRYPT_204_OK = "ENCRYPT 204 OK";
            }

            public static class Progress {
                
            }

            public static class Failure {
                public static final String HELLO_300_BAD_VERSION = "HELLO 300 BAD VERSION";

                public static final String AUTHENTICATE_301_BAD_CERTIFICATE = "AUTHENTICATE 301 BAD CERTIFICATE";
                public static final String AUTHENTICATE_302_EXPIRED_CERTIFICATE = "AUTHENTICATE 302 EXPIRED CERTIFICATE";
                public static final String AUTHENTICATE_303_FOREIGN_CERTIFICATE = "AUTHENTICATE 303 FOREIGN CERTIFICATE";

                public static final String PROPOISE_304_BAD_CERTIFICATE = "PROPOSE 304 BAD CERTIFICATE";
                public static final String PROPOSE_305_EXPIRED_CERTIFICATE = "PROPOSE 305 EXPIRED CERTIFICATE";
                public static final String PROPOSE_306_FOREIGN_CERTIFICATE = "PROPOSE 306 FOREIGN CERTIFICATE";

                public static final String VERIFY_307_MISMATCH = "VERIFY 307 MISMATCH";

                public static final String GENERIC_400_MALFORMED_MESSAGE = "GENERIC 400 MALFORMED MESSAGE";
                public static final String GENERIC_401_UNKNOWN_MESSAGE = "GENERIC 401 UNKNOWN MESSAGE";
                public static final String GENERIC_402_PERMISSION_DENIED = "GENERIC 402 PERMISSION DENIED";
            }
        }
    }

    public static record CertificateMessageContents(boolean valid,
                                                    boolean recognized,
                                                    boolean malformed,
                                                    RSAPublicKey issuerKey,
                                                    RSAPublicKey nodeKey) {
    }

    private final SMIFTChannel channel;
    private final Map<String, SMIFTProtocolHook> hooks;
    private final SMIFT03Certificate mainCertificate;
    private final SMIFT03Certificate[] certificates;

    public SMIFT03Protocol(SMIFTChannel channel,
                            SMIFT03Certificate mainCertificate,
                            SMIFT03Certificate[] certificates) {
        this.channel = channel;
        this.hooks = new HashMap<>();
        this.mainCertificate = mainCertificate;
        this.certificates = certificates;
    }

    @Override
    public void loop() {
        new Thread(() -> {
            SMIFT03Protocol.this.runHandshake();

            while (true) {
                SMIFTMessage incoming = this.channel.read();

                if (this.hooks.containsKey(incoming.getMessageType())) {
                    SMIFTProtocolHook hook = this.hooks.get(incoming.getMessageType());
                    SMIFTMessage response = hook.handle(incoming);
                    this.channel.write(response);
                }
            }
        }).run();
    }

    private boolean runHandshake() {
        SMIFTMessage myAuthenticate = newMessage(Messages.Requests.AUTHENTICATE);
        certificateMessage(myAuthenticate, this.mainCertificate);

        if (!this.channel.write(myAuthenticate)) {
            return false;
        }

        SMIFTMessage otherAuthenticate = this.channel.read();

        if (null == otherAuthenticate) {
            return false;
        } else if (!Messages.Requests.AUTHENTICATE.equals(otherAuthenticate.getMessageType())) {
            this.channel.write(newMessage(Messages.Requests.GOODBYE));
            return false;
        }

        CertificateMessageContents otherCertificate = verifyCertificateMessage(otherAuthenticate, this.mainCertificate.getIssuerPublicKey());

        if (otherCertificate.malformed()) {
            this.channel.write(newMessage(Messages.Responses.Failure.AUTHENTICATE_301_BAD_CERTIFICATE));
            return false;
        } else if (!otherCertificate.recognized()) {
            this.channel.write(newMessage(Messages.Responses.Failure.AUTHENTICATE_303_FOREIGN_CERTIFICATE));
            return false;
        } else if (!otherCertificate.valid()) {
             this.channel.write(newMessage(Messages.Responses.Failure.AUTHENTICATE_302_EXPIRED_CERTIFICATE));
            return false;
        }

        if (!this.channel.write(newMessage(Messages.Responses.Success.AUTHENTICATE_201_OK))) {
            return false;
        }

        for (SMIFT03Certificate cert : this.certificates) {
            SMIFTMessage proposal = newMessage(Messages.Requests.PROPOSE);
            certificateMessage(proposal, cert);
            
            if (!this.channel.write(proposal)) {
                return false;
            }
        }

        // TODO: end proposals
        // TODO: read other proposals
        // TODO: all things

        return true;
    }

    @Override
    public void addHook(String messageType, SMIFTProtocolHook hook) {
        this.hooks.put(messageType, hook);
    }

    public static SMIFTMessage newMessage() {
        return new SMIFTMessage("SMIFT/0.3");
    }

    public static SMIFTMessage newMessage(String messageType) {
        return new SMIFTMessage("SMIFT/0.3", messageType);
    }

    public static void certificateMessage(SMIFTMessage messge, SMIFT03Certificate cert) {
        messge.addField("Node-Name", cert.getClearNodeName());
        messge.addField("Certificate-Issuance-Date", cert.getIssuanceDate());
        messge.addFieldUnescaped("Node-Signature", cert.getNodeNameSignature());
        messge.addFieldUnescaped("Issuer-Signature", cert.getIssuerSignature());
        messge.addField("Issuer-Key-Exponent", cert.getIssuerPublicKey().getPublicExponent());
        messge.addField("Issuer-Key-Modulus", cert.getIssuerPublicKey().getModulus());
        messge.addField("Node-Key-Exponent", cert.getNodePublicKey().getPublicExponent());
        messge.addField("Node-Key-Modulus", cert.getNodePublicKey().getModulus());
        messge.addField("Expiration-Date", cert.getExpirationDate());
        messge.addFieldUnescaped("Expiration-Signature", cert.getSmiftExpirationDateSignature());
    }

    public static CertificateMessageContents verifyCertificateMessage(SMIFTMessage message, Key against) {
        try {
            // TODO: check expiration date

            KeyFactory factory = KeyFactory.getInstance("RSA");

            BigInteger issuerKeyExp = new BigInteger(message.getField("Issuer-Key-Exponent"));
            BigInteger issuerKeyMod = new BigInteger(message.getField("Issuer-Key-Modulus"));
            RSAPublicKeySpec issuerKeySpec = new RSAPublicKeySpec(issuerKeyMod, issuerKeyExp);

            BigInteger nodeKeyExp = new BigInteger(message.getField("Node-Key-Exponent"));
            BigInteger nodeKeyMod = new BigInteger(message.getField("Node-Key-Modulus"));
            RSAPublicKeySpec nodeKeySpec = new RSAPublicKeySpec(nodeKeyMod, nodeKeyExp);

            RSAPublicKey issuerKey = (RSAPublicKey) factory.generatePublic(issuerKeySpec);
            RSAPublicKey nodeKey = (RSAPublicKey) factory.generatePublic(nodeKeySpec);

            if (!against.equals(issuerKey)) {
                return new CertificateMessageContents(false, false, false, issuerKey, nodeKey)
            }

            String clearName = message.getField("Node-Name");
            String clearExpirationDate = message.getField("Expiration-Date");
            String clearIssuerSignature = SMIFTUtils.RSA.decryptToString(message.getField("Issuer-Signature"), issuerKey);
            String clearNodeSignature = SMIFTUtils.RSA.decryptToString(message.getField("Node-Signature"), nodeKey);
            String clearExpirationSignature = SMIFTUtils.RSA.decryptToString(message.getField("Expiration-Signature"), issuerKey);

            if (!clearName.equals(clearIssuerSignature)
                || !clearName.equals(clearNodeSignature)
                || !clearExpirationDate.equals(clearExpirationSignature)) {
                return new CertificateMessageContents(false, false, false, issuerKey, nodeKey);
            }

            return new CertificateMessageContents(true, true, false, issuerKey, nodeKey);
        } catch (Exception e) {
            return new CertificateMessageContents(false, false, true, null, null);
        }
    }
}
