package alessandrosalerno.smift.libsmift;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;

public class SMIFTRSAWriter implements SMIFTWriter {
    private SMIFTClearWriter backend;
    private final Key key;

    public SMIFTRSAWriter(Key key) {
        this.key = key;
    }

    @Override
    public void setStream(OutputStream stream) {
        this.backend = new SMIFTClearWriter(stream);
    }

    @Override
    public void write(SMIFTMessage message) throws IOException {
        this.backend.write(SMIFTUtils.RSA.encrypt(message.toString(), this.key));
    }
}
