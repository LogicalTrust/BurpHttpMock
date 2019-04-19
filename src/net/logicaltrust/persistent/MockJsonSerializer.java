package net.logicaltrust.persistent;

import burp.BurpExtender;
import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.model.MockProtocolEnum;
import net.logicaltrust.model.MockRule;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class MockJsonSerializer {

    private final SimpleLogger logger;
    private final Gson gson;

    public MockJsonSerializer() {
        this.logger = BurpExtender.getLogger();
        this.gson = new GsonBuilder()
                .excludeFieldsWithoutExposeAnnotation()
                .registerTypeHierarchyAdapter(byte[].class, new ByteArrayToBase64TypeAdapter())
                .setPrettyPrinting()
                .registerTypeAdapter(MockRule.class, new MockRuleAdapter())
                .create();
    }

    public byte[] serialize(List<MockEntry> entries) {
        String json = gson.toJson(entries);
        return json.getBytes(StandardCharsets.UTF_8);
    }

    public List<MockEntry> deserialize(File json) {
        List<MockEntry> result = new ArrayList<>();
        int index = 0;
        try {
            JsonReader reader = new JsonReader(new FileReader(json));
            reader.beginArray();
            while (reader.hasNext()) {
                try {
                    MockEntry entry = gson.fromJson(reader, MockEntry.class);
                    result.add(entry);
                } catch (Exception e) {
                    logger.debugForce("Cannot deserialize entry " + index);
                    reader.endObject();
                }
                index++;
            }
            reader.endArray();
        } catch (Exception e) {
            e.printStackTrace(logger.getStderr());
        }
        return result;
    }

    private static class MockRuleAdapter extends TypeAdapter<MockRule> {

        @Override
        public void write(JsonWriter jsonWriter, MockRule mockRule) throws IOException {
            jsonWriter.beginObject();
            jsonWriter.name("host").value(mockRule.getHost());
            jsonWriter.name("path").value(mockRule.getPath());
            jsonWriter.name("port").value(mockRule.getPort());
            jsonWriter.name("protocol").value(mockRule.getProtocol().name());
            jsonWriter.endObject();
        }

        @Override
        public MockRule read(JsonReader jsonReader) throws IOException {
            MockRule rule = new MockRule();
            jsonReader.beginObject();
            while (jsonReader.hasNext()) {
                switch (jsonReader.nextName()) {
                    case "host":
                        rule.setHost(jsonReader.nextString());
                        break;

                    case "path":
                        rule.setPath(jsonReader.nextString());
                        break;

                    case "port":
                        rule.setPort(jsonReader.nextString());
                        break;

                    case "protocol":
                        rule.setProtocol(MockProtocolEnum.valueOf(jsonReader.nextString()));
                        break;
                }
            }
            jsonReader.endObject();
            return rule;
        }
    }

    private static class ByteArrayToBase64TypeAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {
        public byte[] deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            return Base64.getDecoder().decode(json.getAsString());
        }

        public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(Base64.getEncoder().encodeToString(src));
        }
    }

}
