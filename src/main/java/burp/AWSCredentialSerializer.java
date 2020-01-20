package burp;

import com.google.gson.*;

import java.lang.reflect.Type;

public class AWSCredentialSerializer implements JsonSerializer<AWSCredential>, JsonDeserializer<AWSCredential>
{
    public final static String CLASS_NAME = "className";

    @Override
    public JsonElement serialize(AWSCredential src, Type typeOfSrc, JsonSerializationContext context)
    {
        JsonObject obj = context.serialize(src).getAsJsonObject();
        obj.addProperty(CLASS_NAME, src.getClassName());
        return obj;
    }

    @Override
    public AWSCredential deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException
    {
        final JsonObject obj = json.getAsJsonObject();
        final String className = obj.get(CLASS_NAME).getAsString();
        obj.remove(CLASS_NAME); // this is a meta property
        Class<AWSCredential> credentialClass;
        try {
            credentialClass = (Class<AWSCredential>) Class.forName(className);
        } catch (ClassNotFoundException exc) {
            throw new JsonParseException("Failed to instantiate class: "+className);
        }
        return context.deserialize(obj, credentialClass);
    }
}
