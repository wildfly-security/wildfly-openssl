/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.openssl;

import java.io.Closeable;
import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

/**
 * A byte buffer pool that supports reference counted pools. This is only used for the SSLSocket implementation,
 * which requires a high performance direct buffer pool implementation.
 *
 * TODO: clean this up, it has just been compied from Undertow and can be simplified
 *
 * @author Stuart Douglas
 */
class DefaultByteBufferPool {

    //TODO: make configurable
    static final DefaultByteBufferPool WRITE_DIRECT_POOL = new DefaultByteBufferPool(true, Integer.getInteger("org.wildfly.openssl.write-buffer-size", 16 * 1024));

    static final DefaultByteBufferPool DIRECT_POOL = new DefaultByteBufferPool(true, Integer.getInteger("org.wildfly.openssl.buffer-size", 17 * 1024));
    static final DefaultByteBufferPool HEAP_POOL = new DefaultByteBufferPool(false, Integer.getInteger("org.wildfly.openssl.buffer-size", 17 * 1024));

    private final ThreadLocal<ThreadLocalData> threadLocalCache = new ThreadLocal<>();
    private final List<WeakReference<ThreadLocalData>> threadLocalDataList = Collections.synchronizedList(new ArrayList<WeakReference<ThreadLocalData>>());
    private final ConcurrentLinkedQueue<ByteBuffer> queue = new ConcurrentLinkedQueue<>();

    private final boolean direct;
    private final int bufferSize;
    private final int maximumPoolSize;
    private final int threadLocalCacheSize;
    private final int leakDetectionPercent;
    private int count; //racily updated count used in leak detection

    @SuppressWarnings({"unused", "FieldCanBeLocal"})
    private volatile int currentQueueLength = 0;
    private static final AtomicIntegerFieldUpdater<DefaultByteBufferPool> currentQueueLengthUpdater = AtomicIntegerFieldUpdater.newUpdater(DefaultByteBufferPool.class, "currentQueueLength");

    @SuppressWarnings({"unused", "FieldCanBeLocal"})
    private volatile int reclaimedThreadLocals = 0;
    private static final AtomicIntegerFieldUpdater<DefaultByteBufferPool> reclaimedThreadLocalsUpdater = AtomicIntegerFieldUpdater.newUpdater(DefaultByteBufferPool.class, "reclaimedThreadLocals");


    /**
     * @param direct     If this implementation should use direct buffers
     * @param bufferSize The buffer size to use
     */
    DefaultByteBufferPool(boolean direct, int bufferSize) {
        this(direct, bufferSize, -1, 12, 0);
    }

    /**
     * @param direct               If this implementation should use direct buffers
     * @param bufferSize           The buffer size to use
     * @param maximumPoolSize      The maximum pool size, in number of buffers, it does not include buffers in thread local caches
     * @param threadLocalCacheSize The maximum number of buffers that can be stored in a thread local cache
     */
    DefaultByteBufferPool(boolean direct, int bufferSize, int maximumPoolSize, int threadLocalCacheSize, int leakDecetionPercent) {
        this.direct = direct;
        this.bufferSize = bufferSize;
        this.maximumPoolSize = maximumPoolSize;
        this.threadLocalCacheSize = threadLocalCacheSize;
        this.leakDetectionPercent = leakDecetionPercent;
    }


    /**
     * @param direct               If this implementation should use direct buffers
     * @param bufferSize           The buffer size to use
     * @param maximumPoolSize      The maximum pool size, in number of buffers, it does not include buffers in thread local caches
     * @param threadLocalCacheSize The maximum number of buffers that can be stored in a thread local cache
     */
    DefaultByteBufferPool(boolean direct, int bufferSize, int maximumPoolSize, int threadLocalCacheSize) {
        this(direct, bufferSize, maximumPoolSize, threadLocalCacheSize, 0);
    }

    public int getBufferSize() {
        return bufferSize;
    }

    public PooledByteBuffer allocate() {
        ByteBuffer buffer = null;
        ThreadLocalData local = null;
        if (threadLocalCacheSize > 0) {
            local = threadLocalCache.get();
            if (local != null) {
                buffer = local.buffers.poll();
                if (buffer != null) {
                    currentQueueLengthUpdater.decrementAndGet(this);
                }
            } else {
                local = new ThreadLocalData();
                synchronized (threadLocalDataList) {
                    cleanupThreadLocalData();
                    threadLocalDataList.add(new WeakReference<>(local));
                    threadLocalCache.set(local);
                }

            }
        }
        if (buffer == null) {
            buffer = queue.poll();
        }
        if (buffer == null) {
            if (direct) {
                buffer = ByteBuffer.allocateDirect(bufferSize);
            } else {
                buffer = ByteBuffer.allocate(bufferSize);
            }
        }
        if (local != null) {
            local.allocationDepth++;
        }
        buffer.clear();
        return new DefaultPooledBuffer(this, buffer, leakDetectionPercent == 0 ? false : (++count % 100 > leakDetectionPercent));
    }

    private void cleanupThreadLocalData() {
        // Called under lock, and only when at least quarter of the capacity has been collected.

        int size = threadLocalDataList.size();

        if (reclaimedThreadLocals > (size / 4)) {
            int j = 0;
            for (int i = 0; i < size; i++) {
                WeakReference<ThreadLocalData> ref = threadLocalDataList.get(i);
                if (ref.get() != null) {
                    threadLocalDataList.set(j++, ref);
                }
            }
            for (int i = size - 1; i >= j; i--) {
                // A tail remove is inlined to a range change check and a decrement
                threadLocalDataList.remove(i);
            }
            reclaimedThreadLocalsUpdater.addAndGet(this, -1 * (size - j));
        }
    }

    private void freeInternal(ByteBuffer buffer) {
        ThreadLocalData local = threadLocalCache.get();
        if (local != null) {
            if (local.allocationDepth > 0) {
                local.allocationDepth--;
                if (local.buffers.size() < threadLocalCacheSize) {
                    local.buffers.add(buffer);
                    return;
                }
            }
        }
        queueIfUnderMax(buffer);
    }

    private void queueIfUnderMax(ByteBuffer buffer) {
        int size;
        do {
            size = currentQueueLength;
            if (size > maximumPoolSize) {
                return;
            }
        } while (!currentQueueLengthUpdater.compareAndSet(this, size, currentQueueLength + 1));
        queue.add(buffer);
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        queue.clear();

        synchronized (threadLocalDataList) {
            for (WeakReference<ThreadLocalData> ref : threadLocalDataList) {
                ThreadLocalData local = ref.get();
                if (local != null) {
                    local.buffers.clear();
                }
                ref.clear();
            }
            threadLocalDataList.clear();
        }
    }

    private static class DefaultPooledBuffer implements PooledByteBuffer {

        private final DefaultByteBufferPool pool;
        private final LeakDetector leakDetector;
        private ByteBuffer buffer;

        private volatile int referenceCount = 1;
        private static final AtomicIntegerFieldUpdater<DefaultPooledBuffer> referenceCountUpdater = AtomicIntegerFieldUpdater.newUpdater(DefaultPooledBuffer.class, "referenceCount");

        DefaultPooledBuffer(DefaultByteBufferPool pool, ByteBuffer buffer, boolean detectLeaks) {
            this.pool = pool;
            this.buffer = buffer;
            this.leakDetector = detectLeaks ? new LeakDetector() : null;
        }

        @Override
        public ByteBuffer getBuffer() {
            if (referenceCount == 0) {
                throw new RuntimeException(Messages.MESSAGES.bufferAlreadyFreed());
            }
            return buffer;
        }

        @Override
        public void close() {
            if (referenceCountUpdater.compareAndSet(this, 1, 0)) {
                if (leakDetector != null) {
                    leakDetector.closed = true;
                }
                pool.freeInternal(buffer);
                this.buffer = null;
            }
        }

        @Override
        public boolean isOpen() {
            return referenceCount > 0;
        }

        @Override
        public String toString() {
            return "DefaultPooledBuffer{" +
                    "buffer=" + buffer +
                    ", referenceCount=" + referenceCount +
                    '}';
        }
    }

    private class ThreadLocalData {
        ArrayDeque<ByteBuffer> buffers = new ArrayDeque<>(threadLocalCacheSize);
        int allocationDepth = 0;

        @Override
        protected void finalize() throws Throwable {
            super.finalize();
            reclaimedThreadLocalsUpdater.incrementAndGet(DefaultByteBufferPool.this);
            if (buffers != null) {
                // Recycle them
                ByteBuffer buffer;
                while ((buffer = buffers.poll()) != null) {
                    queueIfUnderMax(buffer);
                }
            }
        }
    }

    private static class LeakDetector {

        volatile boolean closed = false;
        private final Throwable allocationPoint;

        private LeakDetector() {
            this.allocationPoint = new Throwable(Messages.MESSAGES.bufferLeakDetected());
        }

        @Override
        protected void finalize() throws Throwable {
            super.finalize();
            if (!closed) {
                allocationPoint.printStackTrace();
            }
        }
    }

    interface PooledByteBuffer extends AutoCloseable, Closeable {

        ByteBuffer getBuffer();

        void close();

        boolean isOpen();
    }

}
