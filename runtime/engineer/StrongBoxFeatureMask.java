package omk.strongbox;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;

public final class StrongBoxFeatureMask {
    private static final String SYSTEM_CONFIG_CLASS = "com.android.server.SystemConfig";
    private static final String STRONGBOX_FEATURE = "android.hardware.strongbox_keystore";

    private Method availableFeaturesBackup;
    private boolean removalLogged;

    private static native Method hook(Method target, Object owner, Method callback);

    public static void install() throws Exception {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        if (loader == null) loader = ClassLoader.getSystemClassLoader();
        Class<?> systemConfig = Class.forName(SYSTEM_CONFIG_CLASS, false, loader);
        Method target = systemConfig.getDeclaredMethod("getAvailableFeatures");
        target.setAccessible(true);
        if (!Map.class.isAssignableFrom(target.getReturnType())) {
            throw new IllegalStateException("SystemConfig returned an unsupported feature map");
        }

        StrongBoxFeatureMask owner = new StrongBoxFeatureMask();
        Method callback = StrongBoxFeatureMask.class.getDeclaredMethod(
                "onAvailableFeatures", Object[].class);
        owner.availableFeaturesBackup = hook(target, owner, callback);
        if (owner.availableFeaturesBackup == null) {
            throw new IllegalStateException("SystemConfig feature hook failed");
        }
        owner.availableFeaturesBackup.setAccessible(true);
        System.err.println("OMK StrongBox feature hook installed");
    }

    public Object onAvailableFeatures(Object[] args) throws Throwable {
        Object result = invoke(availableFeaturesBackup, args[0], new Object[0]);
        if (!(result instanceof Map<?, ?>)) return result;
        Map<?, ?> features = (Map<?, ?>) result;

        try {
            if (features.remove(STRONGBOX_FEATURE) != null && !removalLogged) {
                removalLogged = true;
                System.err.println("OMK StrongBox feature declaration hidden");
            }
        } catch (Throwable error) {
            System.err.println("OMK StrongBox feature mask failed: " + error);
        }
        return result;
    }

    private static Object invoke(Method method, Object receiver, Object[] args) throws Throwable {
        try {
            return method.invoke(receiver, args);
        } catch (InvocationTargetException error) {
            throw error.getCause();
        }
    }
}
