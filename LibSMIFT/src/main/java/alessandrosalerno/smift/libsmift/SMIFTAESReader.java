package alessandrosalerno.smift.libsmift;

import java.io.IOException;
import java.io.InputStream;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SMIFTAESReader implements SMIFTReader {
    private SMIFTClearReader backend;
    private final SecretKey key;
    private final IvParameterSpec iv;

    public SMIFTAESReader(SecretKey key, IvParameterSpec iv) {
        this.key = key;
        this.iv = iv;
    }

    @Override
    public void setStream(InputStream stream) {
        this.backend = new SMIFTClearReader(stream);
    }

    @Override
    public String readMessage() throws IOException {
        byte[] cipherText = this.backend.readBytes();
        return SMIFTUtils.AES.decryptToString(cipherText, this.key, this.iv);
    }
}
