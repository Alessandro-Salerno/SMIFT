package alessandrosalerno.smift.libsmift;

public interface SMIFTProtocolHook {
    SMIFTMessage handle(SMIFTMessage message);
}
