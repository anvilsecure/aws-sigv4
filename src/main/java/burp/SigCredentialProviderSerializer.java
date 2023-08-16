package burp;

import com.google.gson.*;

import java.lang.reflect.Type;
import java.util.Map;

public class SigCredentialProviderSerializer implements JsonSerializer<SigCredentialProvider>, JsonDeserializer<SigCredentialProvider>
{
    public final static String CLASS_NAME = "className";

    private static final Map<String, Object> handledClasses = Map.of(
            SigStaticCredentialProvider.class.getName(), SigStaticCredentialProvider.class,
            SigHttpCredentialProvider.class.getName(), SigHttpCredentialProvider.class,
            SigAssumeRoleCredentialProvider.class.getName(), SigAssumeRoleCredentialProvider.class,
            SigAwsProfileCredentialProvider.class.getName(), SigAwsProfileCredentialProvider.class);

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
        if (!handledClasses.containsKey(className)) {
            return null;
        }
        obj.remove(CLASS_NAME); // this is a meta property
        Class<SigCredentialProvider> providerClass;
        try {
            @SuppressWarnings("unchecked")
            Class<SigCredentialProvider> tempProviderClass = (Class<SigCredentialProvider>) handledClasses.get(className);
            if (!SigCredentialProvider.class.isAssignableFrom(tempProviderClass)) {
                throw new JsonParseException("Class does not implement SigCredentialProvider: "+className);
            }
            providerClass = tempProviderClass;
        } catch (ClassCastException exc) {
            throw new JsonParseException("Failed to handle class: "+className);
        }
        return context.deserialize(obj, providerClass);
    }
}
