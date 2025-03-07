package alessandrosalerno.smift.libsmift;

import java.io.IOException;
import java.io.OutputStream;

public interface SMIFTWriter {
    void setStream(OutputStream stream);
    void write(SMIFTMessage message) throws IOException;
}
