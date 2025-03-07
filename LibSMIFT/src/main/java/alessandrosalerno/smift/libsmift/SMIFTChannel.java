package alessandrosalerno.smift.libsmift;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;

public class SMIFTChannel {
    private final InputStream input;
    private final OutputStream output;
    private SMIFTReader reader;
    private SMIFTWriter writer;

    public SMIFTChannel(InputStream inputStream, OutputStream outputStream) {
        this.input = inputStream;
        this.output = outputStream;
        this.switchToClear();
    }

    public SMIFTMessage read() {
        try {
            return SMIFTMessage.fromString(this.reader.readMessage());
        } catch (IOException e) {
            return null;
        }
    }

    public boolean write(SMIFTMessage message) {
        try {
            this.writer.write(message);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public void setReader(SMIFTReader reader) {
        reader.setStream(this.input);
        this.reader = reader;
    }

    public void setWriter(SMIFTWriter writer) {
        writer.setStream(this.output);
        this.writer = writer;
    }

    public void switchToClear() {
        this.reader = new SMIFTClearReader(this.input);
        this.writer = new SMIFTClearWriter(this.output);
    }
}
