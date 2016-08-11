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

/**
 * {@link OpenSSLSessionContext} implementation which offers extra methods which
 * are only useful for the client-side.
 */
public final class OpenSSLClientSessionContext extends OpenSSLSessionContext {
    OpenSSLClientSessionContext(long context) {
        super(context);
    }

    @Override
    public void setSessionTimeout(int seconds) {
        if (seconds < 0) {
            throw new IllegalArgumentException();
        }
        SSL.getInstance().setSessionCacheTimeout(context, seconds);
    }

    @Override
    public int getSessionTimeout() {
        return (int) SSL.getInstance().getSessionCacheTimeout(context);
    }

    @Override
    public void setSessionCacheSize(int size) {
        //todo:
    }

    @Override
    public int getSessionCacheSize() {
        //todo
        return 0;
    }

    @Override
    public void setSessionCacheEnabled(boolean enabled) {
        //todo
    }

    @Override
    public boolean isSessionCacheEnabled() {
        return true;
    }
}
