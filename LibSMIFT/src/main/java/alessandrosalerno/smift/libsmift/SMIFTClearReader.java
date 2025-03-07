package alessandrosalerno.smift.libsmift;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class SMIFTClearReader implements SMIFTReader {
    private InputStream stream;

    public SMIFTClearReader(InputStream stream) {
        this.stream = stream;
    }

    public SMIFTClearReader() {
        this(null);
    }

    @Override
    public void setStream(InputStream stream) {
        this.stream = stream;
    }

    @Override
    public String readMessage() throws IOException {
        return new String(this.readBytes(), StandardCharsets.UTF_8);
    }

    public byte[] readBytes() throws IOException {
        byte[] lenBytes = this.stream.readNBytes(4);
        int len = ByteBuffer.wrap(lenBytes).getInt();
        return this.stream.readNBytes(len);
    }
}
