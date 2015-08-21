/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#include "utssl.h"

extern crypto_dynamic_methods crypto_methods;

/* This file contains all thread related functions */

/*define our lock structure for dynamic locks*/
#ifdef WIN32
#define ssl_lock_type HANDLE
static HANDLE* ssl_lock_cs;
struct CRYPTO_dynlock_value = todo;
#else
#define ssl_lock_type pthread_mutex_t
static pthread_mutex_t* ssl_lock_cs;
struct CRYPTO_dynlock_value {
    pthread_mutex_t mutex;
};
#endif

/*The number of mutexes to create */
static int ssl_lock_num_locks;



static void ssl_thread_lock(int mode, int type,
                            const char *file, int line)
{
    if (type < ssl_lock_num_locks) {
        if (mode & CRYPTO_LOCK) {
#ifdef WIN32
            todo
#else
            pthread_mutex_lock(&ssl_lock_cs[type]);
#endif
        }
        else {
#ifdef WIN32
            todo
#else
            pthread_mutex_unlock(&ssl_lock_cs[type]);
#endif
        }
    }
}

static unsigned long ssl_thread_id(void)
{
    /* OpenSSL needs this to return an unsigned long.  On OS/390, the pthread
     * id is a structure twice that big.  Use the TCB pointer instead as a
     * unique unsigned long.
     */
#ifdef __MVS__
    struct PSA {
        char unmapped[540];
        unsigned long PSATOLD;
    } *psaptr = 0;

    return psaptr->PSATOLD;
#elif defined(WIN32)
    return (unsigned long)GetCurrentThreadId();
#else
    return (unsigned long)(pthread_self());
#endif
}

/*
 * Dynamic lock creation callback
 */
static struct CRYPTO_dynlock_value *ssl_dyn_create_function(const char *file,
                                                     int line)
{
    struct CRYPTO_dynlock_value *value;
    #ifdef WIN32
    todo
    #else
        value = malloc(sizeof(*value));
        if(value == NULL) {
            printf("Failed to allocate memory for mutex");
            return NULL;
        }
        int val = pthread_mutex_init(&(value->mutex), 0);
        if(val != 0) {
                printf("Failed to create mutex, error %d", val);
                return NULL;
        }
    #endif
    return value;
}

/*
 * Dynamic locking and unlocking function
 */

static void ssl_dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
                           const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
#ifdef WIN32
            todo
#else
        pthread_mutex_lock(&(l->mutex));
#endif
    }
    else {
#ifdef WIN32
        todo
#else
        pthread_mutex_unlock(&(l->mutex));
#endif
    }
}

/*
 * Dynamic lock destruction callback
 */
static void ssl_dyn_destroy_function(struct CRYPTO_dynlock_value *l,
                          const char *file, int line)
{

#ifdef WIN32
            todo
#else
    pthread_mutex_destroy(&(l->mutex));
    free(l);
#endif
}
void ssl_thread_setup()
{
    int i;
    ssl_lock_num_locks = crypto_methods.CRYPTO_num_locks();
    ssl_lock_cs = malloc(ssl_lock_num_locks * sizeof(ssl_lock_type));

    for (i = 0; i < ssl_lock_num_locks; i++) {
#ifdef WINDOWS
        todo
#else
         pthread_mutex_init(&ssl_lock_cs[i], 0);
#endif
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(OPENSSL_USE_DEPRECATED)
    crypto_methods.CRYPTO_set_id_callback(ssl_thread_id);
#endif
    crypto_methods.CRYPTO_set_locking_callback(ssl_thread_lock);

    /* Set up dynamic locking scaffolding for OpenSSL to use at its
     * convenience.
     */
    crypto_methods.CRYPTO_set_dynlock_create_callback(ssl_dyn_create_function);
    crypto_methods.CRYPTO_set_dynlock_lock_callback(ssl_dyn_lock_function);
    crypto_methods.CRYPTO_set_dynlock_destroy_callback(ssl_dyn_destroy_function);
}
