package alessandrosalerno.smift.libsmift;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;

public class SMIFTRSAReader implements SMIFTReader {
    private SMIFTClearReader backend;
    private final Key key;

    public SMIFTRSAReader(Key key) {
        this.key = key;
    }

    @Override
    public void setStream(InputStream stream) {
        this.backend = new SMIFTClearReader(stream);
    }

    @Override
    public String readMessage() throws IOException {
        byte[] cipherText = this.backend.readBytes();
        return SMIFTUtils.RSA.decryptToString(cipherText, this.key);
    }
}
