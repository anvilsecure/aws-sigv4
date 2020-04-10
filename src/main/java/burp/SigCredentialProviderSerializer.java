package burp;

import com.google.gson.*;

import java.lang.reflect.Type;

public class SigCredentialProviderSerializer implements JsonSerializer<SigCredentialProvider>, JsonDeserializer<SigCredentialProvider>
{
    public final static String CLASS_NAME = "className";

    @Override
    public JsonElement serialize(SigCredentialProvider src, Type typeOfSrc, JsonSerializationContext context)
    {
        JsonObject obj = context.serialize(src).getAsJsonObject();
        obj.addProperty(CLASS_NAME, src.getClassName());
        return obj;
    }

    @Override
    public SigCredentialProvider deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException
    {
        final JsonObject obj = json.getAsJsonObject();
        final String className = obj.get(CLASS_NAME).getAsString();
        obj.remove(CLASS_NAME); // this is a meta property
        Class<SigCredentialProvider> providerClass;
        try {
            @SuppressWarnings("unchecked")
            Class<SigCredentialProvider> tempProviderClass = (Class<SigCredentialProvider>) Class.forName(className);
            providerClass = tempProviderClass;
        } catch (ClassNotFoundException | ClassCastException exc) {
            throw new JsonParseException("Failed to instantiate class: "+className);
        }
        return context.deserialize(obj, providerClass);
    }
}
