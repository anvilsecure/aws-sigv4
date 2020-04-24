package burp;

import com.google.gson.*;

import java.lang.reflect.Type;
import java.util.Map;

public class SigCredentialSerializer implements JsonSerializer<SigCredential>, JsonDeserializer<SigCredential>
{
    public final static String CLASS_NAME = "className";

    private static final Map<String, Object> handledClasses = Map.of(
            SigStaticCredential.class.getName(), SigStaticCredential.class,
            SigTemporaryCredential.class.getName(), SigTemporaryCredential.class);


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
        if (!handledClasses.containsKey(className)) {
            return null;
        }
        obj.remove(CLASS_NAME); // this is a meta property
        Class<SigCredential> credentialClass;
        try {
            @SuppressWarnings("unchecked")
            Class<SigCredential> tempCredentialClass = (Class<SigCredential>) handledClasses.get(className);
            if (!SigCredential.class.isAssignableFrom(tempCredentialClass)) {
                throw new JsonParseException("Class does not implement SigCredential: "+className);
            }
            credentialClass = tempCredentialClass;
        } catch (ClassCastException exc) {
            throw new JsonParseException("Failed to handle class: "+className);
        }
        return context.deserialize(obj, credentialClass);
    }
}
