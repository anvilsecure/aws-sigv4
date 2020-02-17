package burp;

import com.google.gson.*;

import java.lang.reflect.Type;

public class SigCredentialSerializer implements JsonSerializer<SigCredential>, JsonDeserializer<SigCredential>
{
    public final static String CLASS_NAME = "className";

    @Override
    public JsonElement serialize(SigCredential src, Type typeOfSrc, JsonSerializationContext context)
    {
        JsonObject obj = context.serialize(src).getAsJsonObject();
        obj.addProperty(CLASS_NAME, src.getClassName());
        return obj;
    }

    @Override
    public SigCredential deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException
    {
        final JsonObject obj = json.getAsJsonObject();
        final String className = obj.get(CLASS_NAME).getAsString();
        obj.remove(CLASS_NAME); // this is a meta property
        Class<SigCredential> credentialClass;
        try {
            credentialClass = (Class<SigCredential>) Class.forName(className);
        } catch (ClassNotFoundException exc) {
            throw new JsonParseException("Failed to instantiate class: "+className);
        }
        return context.deserialize(obj, credentialClass);
    }
}
