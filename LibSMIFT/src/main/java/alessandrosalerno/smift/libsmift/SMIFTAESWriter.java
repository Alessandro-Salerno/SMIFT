package alessandrosalerno.smift.libsmift;

import java.io.IOException;
import java.io.OutputStream;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SMIFTAESWriter implements SMIFTWriter {
    private SMIFTClearWriter backend;
    private final SecretKey key;
    private final IvParameterSpec iv;

    public SMIFTAESWriter(SecretKey key, IvParameterSpec iv) {
        this.key = key;
        this.iv = iv;
    }

    @Override
    public void setStream(OutputStream stream) {
        this.backend = new SMIFTClearWriter(stream);
    }

    @Override
    public void write(SMIFTMessage message) throws IOException {
        this.backend.write(SMIFTUtils.AES.encrypt(message.toString(), this.key, this.iv));
    }
}
