package alessandrosalerno.smift.libsmift;

public interface SMIFTProtocol {
    void loop();
    void addHook(String messageType, SMIFTProtocolHook hook);   
}
