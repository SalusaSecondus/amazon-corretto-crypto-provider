// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyConstruct;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyGetField;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke_int;
import static org.junit.Assert.*;

import java.io.OutputStream;
import java.lang.ref.SoftReference;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.junit.Test;

public class AccessibleByteArrayOutputStreamTest {

    @Test
    public void badConstructors() {
        assertThrows(IllegalArgumentException.class, () -> getInstance(-5, -5));
        assertThrows(IllegalArgumentException.class, () -> getInstance(-5, 10));
        assertThrows(IllegalArgumentException.class, () -> getInstance(20, 10));
    }

    @Test
    public void singleByteWrite() throws Throwable {
        OutputStream instance = getInstance(0, 5);
        instance.write(0);
        instance.write(1);
        instance.write(2);
        assertEquals(3, sneakyInvoke_int(instance, "size"));
        byte[] buf = sneakyInvoke(instance, "getDataBuffer");
        assertEquals(0, buf[0]);
        assertEquals(1, buf[1]);
        assertEquals(2, buf[2]);
    }

    @Test
    public void limitEnforced() throws Throwable {
        OutputStream instance = getInstance(0, 5);
        instance.write(new byte[4]);
        instance.write(5);
        assertThrows(IllegalArgumentException.class, () -> { instance.write(6); });
    }

    @Test
    public void outOfMemory() throws Throwable {
        OutputStream instance = getInstance();
        instance.write(new byte[1024]);
        assertThrows(OutOfMemoryError.class, () -> instance.write(null, 0, Integer.MAX_VALUE - 512));
    }

    @Test
    public void resetWorks() throws Throwable {
        OutputStream instance = getInstance(2, 5);
        byte[] expected = new byte[5];
        Arrays.fill(expected, (byte) 5);
        instance.write(expected);
        byte[] retrieved = sneakyInvoke(instance, "getDataBuffer"); // Purposefully holding a reference
        assertArrayEquals(expected, retrieved);
        sneakyInvoke(instance, "reset");

        assertEquals(0, retrieved[0]);
        instance.write(expected);
        assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
    }

    @Test
    public void resetWithReuse() throws Throwable {
        OutputStream instance = getInstance(2, 5);
        byte[] expected = new byte[5];
        Arrays.fill(expected, (byte) 5);
        instance.write(expected);
        byte[] retrieved = sneakyInvoke(instance, "getDataBuffer"); // Purposefully holding a reference
        assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
        sneakyInvoke(instance, "reset");

        assertEquals(0, retrieved[0]);
        instance.write(expected);
        assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
        // Ensures that the objects are the same
        assertSame(retrieved, sneakyInvoke(instance, "getDataBuffer"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void resetWithoutReuse() throws Throwable {
        OutputStream instance = getInstance(2, 5);
        byte[] expected = new byte[5];
        Arrays.fill(expected, (byte) 5);
        instance.write(expected);
        byte[] retrieved = sneakyInvoke(instance, "getDataBuffer"); // Purposefully holding a reference
        assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
        sneakyInvoke(instance, "reset");

        // Clear the reference
        ((SoftReference<byte[]>) sneakyGetField(instance, "bufForReuse")).clear();

        assertEquals(0, retrieved[0]);
        instance.write(expected);
        assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
        // Ensures that the objects are the same
        assertNotSame(retrieved, sneakyInvoke(instance, "getDataBuffer"));
    }

    @Test
    public void resetNotReusedDueToSize() throws Throwable {
        OutputStream instance = getInstance(2, 1024);
        byte[] expected = new byte[5];
        Arrays.fill(expected, (byte) 5);
        instance.write(expected);
        byte[] retrieved = sneakyInvoke(instance, "getDataBuffer"); // Purposefully holding a reference
        assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
        sneakyInvoke(instance, "reset");

        assertEquals(0, retrieved[0]);
        byte[] expected2 = new byte[512];
        Arrays.fill(expected2, (byte) 7);
        instance.write(expected2);
        assertArrayEquals(expected2, sneakyInvoke(instance, "getDataBuffer"));
    }

    @Test
    public void writeByteBuffer() throws Throwable {
        OutputStream instance = getInstance(2, 10);
        byte[] expected = new byte[5];
        Arrays.fill(expected, (byte) 5);
        ByteBuffer wrapped = ByteBuffer.wrap(expected);
        ByteBuffer direct = ByteBuffer.allocateDirect(5);
        direct.put(expected).flip();

        sneakyInvoke(instance, "write", wrapped);
        sneakyInvoke(instance, "write", direct);

        assertEquals(wrapped.limit(), wrapped.position());
        assertEquals(direct.limit(), direct.position());
        expected = new byte[10];
        Arrays.fill(expected, (byte) 5);
        assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
    }

    @Test
    public void testClone() throws Throwable {
        OutputStream instance = getInstance(2, 5);
        byte[] expected = new byte[5];
        Arrays.fill(expected, (byte) 5);
        byte[] expected2 = new byte[5];
        Arrays.fill(expected2, (byte) 6);

        instance.write(expected);
        assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
        OutputStream cloned = sneakyInvoke(instance, "clone");
        assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
        sneakyInvoke(instance, "reset");
        assertArrayEquals(expected, sneakyInvoke(cloned, "getDataBuffer"));
        instance.write(expected2);
        assertArrayEquals(expected2, sneakyInvoke(instance, "getDataBuffer"));
        assertArrayEquals(expected, sneakyInvoke(cloned, "getDataBuffer"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void cloneClearsBufForReuse() throws Throwable {
        OutputStream instance = getInstance(2, 5);
        byte[] expected = new byte[5];
        Arrays.fill(expected, (byte) 5);

        instance.write(expected);
        byte[] retrieved = sneakyInvoke(instance, "getDataBuffer"); // Purposefully holding a reference
        sneakyInvoke(instance, "reset");

        assertSame(retrieved, ((SoftReference<byte[]>) sneakyGetField(instance, "bufForReuse")).get());

        OutputStream cloned = sneakyInvoke(instance, "clone");
        assertNull(sneakyGetField(cloned, "bufForReuse"));
    }

    private static OutputStream getInstance(final Object... args) throws Throwable {
        return (OutputStream) sneakyConstruct("com.amazon.corretto.crypto.provider.AccessibleByteArrayOutputStream", args);
    }
}
