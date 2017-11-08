/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 *
 */
package org.wildfly.openssl.util;

import org.wildfly.openssl.Messages;
import sun.misc.Unsafe;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.PrivilegedAction;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * {@link DirectByteBufferDeallocator} Utility class used to free direct buffer memory.
 */
public final class DirectByteBufferDeallocator {

    private static final Logger logger = Logger.getLogger(DirectByteBufferDeallocator.class.getName());

    private static final boolean SUPPORTED;
    private static final Method cleaner;
    private static final Method cleanerClean;

    private static final Unsafe UNSAFE;


    static {
        String versionString = System.getProperty("java.specification.version");
        if (versionString.startsWith("1.")) {
            versionString = versionString.substring(2);
        }
        int version = Integer.parseInt(versionString);

        Method tmpCleaner = null;
        Method tmpCleanerClean = null;
        boolean supported;
        Unsafe tmpUnsafe = null;
        if (version < 9) {
            try {
                tmpCleaner = Class.forName("java.nio.DirectByteBuffer").getMethod("cleaner");
                tmpCleaner.setAccessible(true);
                tmpCleanerClean = Class.forName("sun.misc.Cleaner").getMethod("clean");
                tmpCleanerClean.setAccessible(true);
                supported = true;
            } catch (Throwable t) {
                logger.log(Level.WARNING, Messages.MESSAGES.directBufferDeallocatorInitializationFailed(), t);
                supported = false;
            }
        } else {
            tmpUnsafe = getUnsafe();
            try {
                tmpCleanerClean = tmpUnsafe.getClass().getDeclaredMethod("invokeCleaner", ByteBuffer.class);
                tmpCleanerClean.setAccessible(true);
                supported = true;
            } catch (Throwable t) {
                logger.log(Level.WARNING, Messages.MESSAGES.directBufferDeallocatorInitializationFailed(), t);
                supported = false;
            }
        }
        SUPPORTED = supported;
        cleaner = tmpCleaner;
        cleanerClean = tmpCleanerClean;
        UNSAFE = tmpUnsafe;

    }

    private DirectByteBufferDeallocator() {
        // Utility Class
    }

    /**
     * Attempts to deallocate the underlying direct memory.
     * This is a no-op for buffers where {@link ByteBuffer#isDirect()} returns false.
     *
     * @param buffer to deallocate
     */
    public static void free(ByteBuffer buffer) {
        if (SUPPORTED && buffer != null && buffer.isDirect()) {
            try {
                if (UNSAFE != null) {
                    //use the JDK9 method
                    cleanerClean.invoke(UNSAFE, buffer);
                } else {
                    Object cleaner = DirectByteBufferDeallocator.cleaner.invoke(buffer);
                    cleanerClean.invoke(cleaner);
                }
            } catch (Throwable t) {
                logger.log(Level.WARNING, Messages.MESSAGES.directBufferDeallocationFailed(), t);
            }
        }
    }

    private static Unsafe getUnsafe() {
        if (System.getSecurityManager() != null) {
            return new PrivilegedAction<Unsafe>() {
                public Unsafe run() {
                    return getUnsafe0();
                }
            }.run();
        }
        return getUnsafe0();
    }

    private static Unsafe getUnsafe0() {
        try {
            Field theUnsafe = Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            return (Unsafe) theUnsafe.get(null);
        } catch (Throwable t) {
            throw new RuntimeException("JDK did not allow accessing unsafe", t);
        }
    }
}
