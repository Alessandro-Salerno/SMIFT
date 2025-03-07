package alessandrosalerno.smift.libsmift.smift03;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.NoSuchFileException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import org.apache.commons.text.StringEscapeUtils;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import alessandrosalerno.smift.libsmift.SMIFTUtils;

public class SMIFT03Certificate {
    // Name
    private String issuerSignature; // Node name encrypted with issuer key
    private String nodeNameSignature;  // Node name encrypted with its own private key
    private String clearNodeName;

    // Key objects
    private RSAPublicKey issuerPublicKey;
    private RSAPublicKey nodePublicKey;
    private RSAPrivateKey nodePrivateKey;

    // Dates
    private String issuanceDate;
    private String expirationDate;
    private String smiftExpirationDateSignature;

    private SMIFT03Certificate() {
    }

	public String getIssuerSignature() {
		return this.issuerSignature;
	}

	public String getNodeNameSignature() {
		return this.nodeNameSignature;
	}

	public String getClearNodeName() {
		return this.clearNodeName;
	}

	public RSAPublicKey getIssuerPublicKey() {
		return this.issuerPublicKey;
	}

	public RSAPublicKey getNodePublicKey() {
		return this.nodePublicKey;
	}

	public RSAPrivateKey getNodePrivateKey() {
		return this.nodePrivateKey;
	}

	public String getIssuanceDate() {
		return this.issuanceDate;
	}

	public String getExpirationDate() {
		return this.expirationDate;
	}

    public String getSmiftExpirationDateSignature() {
        return this.smiftExpirationDateSignature;
    }

    public void toFile(File file) throws NoSuchFileException,
                                         IOException {
        Gson gson = new Gson();
        JsonObject cert = new JsonObject();
        cert.addProperty("certificateVersion", "2.0.0");
        cert.addProperty("nodeName", this.clearNodeName);
        cert.addProperty("issuanceDate", this.issuanceDate);
        cert.addProperty("expirationDate", this.expirationDate);
        cert.addProperty("expirationSignature", this.smiftExpirationDateSignature);
        cert.addProperty("nodeSignature", this.nodeNameSignature);
        cert.addProperty("issuerSignature", this.issuerSignature);
        cert.addProperty("nodePublicExp", this.nodePublicKey.getPublicExponent());
        cert.addProperty("nodePublicMod", this.nodePublicKey.getModulus());
        cert.addProperty("nodePrivateExp", this.nodePrivateKey.getPrivateExponent());
        cert.addProperty("nodePrivateMod", this.nodePrivateKey.getModulus());
        cert.addProperty("issuerPublicExp", this.issuerPublicKey.getPublicExponent());
        cert.addProperty("issuerPublicMod", this.issuerPublicKey.getModulus());

        String json = gson.toJson(cert);
        byte[] base64 = Base64.getEncoder().encode(json.getBytes(StandardCharsets.UTF_8));

        FileOutputStream fos = new FileOutputStream(file);
        fos.write(base64);
        fos.close();
    }

    public static SMIFT03Certificate fromFile(File file) throws FileNotFoundException,
                                                                IOException {
        FileInputStream fis = new FileInputStream(file);
        byte[] data = fis.readAllBytes();
        fis.close();
        byte[] decoded = Base64.getDecoder().decode(data);
        String clearJson = new String(decoded, StandardCharsets.UTF_8);
        Gson gson = new Gson();
        JsonElement root = gson.fromJson(clearJson, JsonElement.class);
        JsonObject contents = root.getAsJsonObject();

        if (!"2.0.0".equals(contents.get("certificateVersion").getAsString())) {
            throw new IllegalArgumentException("\"" + file.getPath() + "\" is not a valid 2.0.0 certificate");
        }

        SMIFT03Certificate certificate = new SMIFT03Certificate();
        certificate.clearNodeName = contents.get("nodeName").getAsString();
        certificate.nodeNameSignature = contents.get("nodeSignature").getAsString();
        certificate.issuerSignature = contents.get("issuerSignature").getAsString();
        certificate.issuanceDate = contents.get("issuanceDate").getAsString();
        certificate.expirationDate = contents.get("expirationDate").getAsString();
        certificate.smiftExpirationDateSignature = contents.get("expirationSignature").getAsString();

        BigInteger nodePublicExp = contents.get("nodePublicExp").getAsBigInteger();
        BigInteger nodePublicMod = contents.get("nodePublicMod").getAsBigInteger();
        BigInteger nodePrivateExp = contents.get("nodePrivateExp").getAsBigInteger();
        BigInteger nodePrivateMod = contents.get("nodePrivateMod").getAsBigInteger();

        BigInteger issuerPublicExp = contents.get("issuerPublicExp").getAsBigInteger();
        BigInteger issuerPublicMod = contents.get("issuerPublicMod").getAsBigInteger();

        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");

            RSAPublicKeySpec nodePublicKeySpec = new RSAPublicKeySpec(nodePublicMod, nodePublicExp);
            RSAPrivateKeySpec nodePrivateKeySpec = new RSAPrivateKeySpec(nodePrivateMod, nodePrivateExp);
            certificate.nodePublicKey = (RSAPublicKey) factory.generatePublic(nodePublicKeySpec);
            certificate.nodePrivateKey = (RSAPrivateKey) factory.generatePrivate(nodePrivateKeySpec);

            RSAPublicKeySpec issuerPublicKeySpec = new RSAPublicKeySpec(issuerPublicMod, smiftPublicExp);
            certificate.issuerPublicKey = (RSAPublicKey) factory.generatePublic(issuerPublicKeySpec);

            return certificate;
        } catch (Exception ignored) {}

        // Unreachable unless you have the worst JDK on Earth
        return null;
    }

    public static SMIFT03Certificate generate(String nodeName,
                                                RSAPublicKey nodePublicKey,
                                                RSAPrivateKey nodePrivateKey,
                                                RSAPublicKey issuerPublicKey,
                                                RSAPrivateKey issuerPrivateKey,
                                                int durationInDays) {
        SMIFT03Certificate certificate = new SMIFT03Certificate();
        certificate.clearNodeName = nodeName;
        certificate.nodePublicKey = nodePublicKey;
        certificate.nodePrivateKey = nodePrivateKey;
        certificate.issuerPublicKey = issuerPublicKey;

        String rawNodeEnc = SMIFTUtils.RSA.encryptToString(nodeName, nodePrivateKey);
        String rawSmiftEnc = SMIFTUtils.RSA.encryptToString(nodeName, issuerPrivateKey);
        certificate.nodeNameSignature = StringEscapeUtils.escapeJson(rawNodeEnc);
        certificate.issuerSignature = StringEscapeUtils.escapeJson(rawSmiftEnc);
        certificate.issuerPublicKey = issuerPublicKey;

        certificate.issuanceDate = SMIFTUtils.Strings.currentDate();
        certificate.expirationDate = SMIFTUtils.Strings.futureDate(durationInDays);
        String rawExpirationSignature = SMIFTUtils.RSA.encryptToString(certificate.expirationDate,
                issuerPrivateKey);
        certificate.smiftExpirationDateSignature = StringEscapeUtils.escapeJson(rawExpirationSignature);

        return certificate;
    }
}
