package alessandrosalerno.smift.libsmift;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.text.StringEscapeUtils;

public class SMIFTMessage {
    private final String smiftString;
    private final String messageType;
    private final Map<String, String> fields;

    public SMIFTMessage(String smiftString, String messageType) {
        this.smiftString = smiftString;
        this.messageType = messageType;
        this.fields = new HashMap<>();
        this.addField("Timestamp", SMIFTUtils.Strings.currentDate());
    }

    public SMIFTMessage(String smiftString) {
        this(smiftString, "TEMPLATE");
    }

    public String getSmiftString() {
        return this.smiftString;
    }
    
    public String getMessageType() {
        return this.messageType;
    }

    public String getField(String key) {
        return StringEscapeUtils.unescapeJson(this.fields.get(key));
    }

    public String getFieldEscaped(String key) {
        return this.fields.get(key);
    }

    public void addField(String key, Object value) {
        this.fields.put(key, StringEscapeUtils.escapeJson(value.toString()));
    }

    public void addFieldUnescaped(String key, Object value) {
        this.fields.put(key, value.toString());
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(this.smiftString).append(" ").append(this.messageType);

        for (String key : this.fields.keySet()) {
            builder.append(key).append(": ").append(this.getFieldEscaped(key));
        }

        return builder.toString();
    }

    public SMIFTMessage reply() {
        return new SMIFTMessage(this.smiftString);
    }

    public static SMIFTMessage fromString(String input) {
        // TODO: implement this
        return null;
    }
}
