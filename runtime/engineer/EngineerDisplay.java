package omk.engineer;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/** App-local display compatibility only. Never provisions or validates keys. */
public final class EngineerDisplay {
    private Method attachBackup;
    private Method statusBackup;
    private boolean installed;

    private static native Method hook(Method target, Object owner, Method callback);
    private static native boolean deoptimize(Method target);
    private static native boolean selected();

    public static void install() throws Exception {
        EngineerDisplay owner = new EngineerDisplay();
        Class<?> application = Class.forName("android.app.Application");
        Class<?> instrumentation = Class.forName("android.app.Instrumentation");
        Method attach = instrumentation.getDeclaredMethod("callApplicationOnCreate", application);
        owner.attachBackup = hook(attach, owner,
                EngineerDisplay.class.getDeclaredMethod("onAttach", Object[].class));
        if (owner.attachBackup == null) throw new IllegalStateException("Application attach hook failed");
        owner.attachBackup.setAccessible(true);
        try {
            Class<?> thread = Class.forName("android.app.ActivityThread");
            Class<?> bind = Class.forName("android.app.ActivityThread$AppBindData");
            deoptimize(thread.getDeclaredMethod("handleBindApplication", bind));
        } catch (ReflectiveOperationException ignored) { }
    }

    public Object onAttach(Object[] args) throws Throwable {
        if (!installed) {
            try {
                ClassLoader loader = (ClassLoader) args[1].getClass().getMethod("getClassLoader").invoke(args[1]);
                Class<?> security = Class.forName(
                        "com.oplus.engineermode.security.SecurityInterface", false, loader);
                Method target = security.getDeclaredMethod("isGoogleKeyImport");
                if (target.getReturnType() != boolean.class
                        || !java.lang.reflect.Modifier.isStatic(target.getModifiers()))
                    return invoke(attachBackup, args[0], new Object[] {args[1]});
                Method backup = hook(target, this,
                        EngineerDisplay.class.getDeclaredMethod("onStatus", Object[].class));
                if (backup != null) {
                    backup.setAccessible(true);
                    statusBackup = backup;
                    installed = true;
                    System.err.println("OMK EngineerMode status method hooked");
                    // Prevent a precompiled tiny caller from bypassing this method.
                    try {
                        Class<?> caller = Class.forName(
                                "com.oplus.engineermode.security.KeyInstanceImpl$GoogleKey", false, loader);
                        deoptimize(caller.getDeclaredMethod("isKeyImported"));
                    } catch (ReflectiveOperationException ignored) { }
                }
            } catch (ReflectiveOperationException | LinkageError error) {
                // Unsupported firmware keeps its original result.
                System.err.println("OMK EngineerMode status hook failed: " + error);
            }
        }
        return invoke(attachBackup, args[0], new Object[] {args[1]});
    }

    public Object onStatus(Object[] args) throws Throwable {
        if (selected()) return Boolean.TRUE;
        return invoke(statusBackup, null, args);
    }

    private static Object invoke(Method method, Object receiver, Object[] args) throws Throwable {
        try {
            return method.invoke(receiver, args);
        } catch (InvocationTargetException error) {
            throw error.getCause();
        }
    }
}
