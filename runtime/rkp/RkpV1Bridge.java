// Copyright (c) 2026 Eltavine (尉迟栩澜)
// Derived from Duck-ToolBox commit 7567a8e084d31b1a6da3541bf0e8e2692ee45e0a.
// SPDX-License-Identifier: MIT
//
// MIT License
//
// Copyright (c) 2026 Eltavine (尉迟栩澜)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package duck.rkp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;

/** Calls the device's own stable AIDL proxy; owns no keys, network or output artifacts. */
public final class RkpV1Bridge {
    private static final String PREFIX = "android.hardware.security.keymint.";
    private static final String SERVICE = PREFIX + "IRemotelyProvisionedComponent";
    private static final int LIMIT = 0xa000;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("expected exchange directory");
        File directory = new File(args[0]);
        // Status 0: MAC, DeviceInfo, ProtectedData. Status 1: AIDL error code and message.
        // Status 2: transport error. Status 3: invalid HAL response.
        // Every byte string has a big-endian int length.
        byte[] response;
        try {
            response = request(directory);
        } catch (Throwable failure) {
            while (failure instanceof InvocationTargetException && failure.getCause() != null) {
                failure = failure.getCause();
            }
            if (failure.getClass().getName().equals("android.os.ServiceSpecificException")) {
                int code = failure.getClass().getField("errorCode").getInt(failure);
                response = errorReply(1, code, failure.toString());
            } else {
                response = errorReply(2, 0, failure.toString());
            }
        }
        try (FileOutputStream file = new FileOutputStream(new File(directory, "reply.bin"))) {
            file.write(response);
        }
    }

    private static byte[] request(File directory) throws Exception {
        byte[] challenge, maced, p256, x25519;
        try (DataInputStream input = new DataInputStream(
                new FileInputStream(new File(directory, "request.bin")))) {
            challenge = readBytes(input);
            maced = readBytes(input);
            p256 = readBytes(input);
            x25519 = readBytes(input);
            if (input.read() != -1) throw new IOException("trailing request bytes");
        }
        if (challenge.length == 0 || challenge.length > 64 || maced.length == 0) {
            throw new IOException("invalid challenge or MacedPublicKey");
        }
        Class<?> binder = Class.forName("android.os.IBinder");
        Object service = Class.forName("android.os.ServiceManager")
                .getMethod("checkService", String.class).invoke(null, SERVICE + "/default");
        if (service == null) throw new IOException("RKP default service is unavailable");
        Class<?> api = Class.forName(SERVICE);
        Object proxy = Class.forName(SERVICE + "$Stub")
                .getMethod("asInterface", binder).invoke(null, service);
        Object info = api.getMethod("getHardwareInfo").invoke(proxy);
        int curve = info.getClass().getField("supportedEekCurve").getInt(info);
        byte[] eek;
        if (curve == 1) eek = p256;
        else if (curve == 2) eek = x25519;
        else throw new IOException("unsupported EEK curve: " + curve);
        if (eek.length == 0) throw new IOException("server supplied no EEK chain for curve " + curve);

        Class<?> keyClass = Class.forName(PREFIX + "MacedPublicKey");
        Object key = keyClass.getConstructor().newInstance();
        keyClass.getField("macedKey").set(key, maced);
        Object keys = Array.newInstance(keyClass, 1);
        Array.set(keys, 0, key);
        Class<?> deviceClass = Class.forName(PREFIX + "DeviceInfo");
        Class<?> protectedClass = Class.forName(PREFIX + "ProtectedData");
        Object device = deviceClass.getConstructor().newInstance();
        Object protectedData = protectedClass.getConstructor().newInstance();
        byte[] mac = (byte[]) api.getMethod("generateCertificateRequest",
                boolean.class, keys.getClass(), byte[].class, byte[].class,
                deviceClass, protectedClass).invoke(proxy, false, keys, eek, challenge,
                device, protectedData);
        byte[] deviceBytes = (byte[]) deviceClass.getField("deviceInfo").get(device);
        byte[] protectedBytes = (byte[]) protectedClass.getField("protectedData").get(protectedData);
        if (mac == null || mac.length != 32) return errorReply(3, 0, "invalid keysToSign MAC");
        if (deviceBytes == null || deviceBytes.length == 0 || deviceBytes.length > LIMIT) {
            return errorReply(3, 0, "invalid DeviceInfo length");
        }
        if (protectedBytes == null || protectedBytes.length == 0 || protectedBytes.length > LIMIT) {
            return errorReply(3, 0, "invalid ProtectedData length");
        }
        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(0);
            writeBytes(output, mac);
            writeBytes(output, deviceBytes);
            writeBytes(output, protectedBytes);
        }
        return buffer.toByteArray();
    }

    private static byte[] errorReply(int status, int code, String message) throws IOException {
        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(status);
            if (status == 1) output.writeInt(code);
            if (message.length() > 1024) message = message.substring(0, 1024);
            writeBytes(output, message.getBytes(StandardCharsets.UTF_8));
        }
        return buffer.toByteArray();
    }

    private static byte[] readBytes(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > LIMIT) throw new IOException("invalid input length");
        byte[] bytes = new byte[length];
        input.readFully(bytes);
        return bytes;
    }

    private static void writeBytes(DataOutputStream output, byte[] bytes) throws IOException {
        if (bytes == null || bytes.length > LIMIT) throw new IOException("invalid output length");
        output.writeInt(bytes.length);
        output.write(bytes);
    }
}
