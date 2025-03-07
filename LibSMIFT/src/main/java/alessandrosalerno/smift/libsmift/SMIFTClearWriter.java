package alessandrosalerno.smift.libsmift;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class SMIFTClearWriter implements SMIFTWriter {
    private OutputStream stream;

    public SMIFTClearWriter(OutputStream stream) {
        this.stream = stream;
    }

    public SMIFTClearWriter() {
        this(null);
    }


    @Override
    public void setStream(OutputStream stream) {
        this.stream = stream;
    }

    @Override
    public void write(SMIFTMessage message) throws IOException {
        this.write(message.toString());
    }

    public void write(String message) throws IOException {
        this.stream.write(message.getBytes(StandardCharsets.UTF_8));
    }

    public void write(byte[] message) throws IOException {
        ByteBuffer lenBuf = ByteBuffer.allocate(4);
        lenBuf.putInt(message.length);
        this.stream.write(lenBuf.array());
        this.stream.write(message);
    }
}
