/*
 *
 *    Copyright (c) 2020 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *          Provides an implementation of the ThreadStackManager object
 *          for the Texas Instruments CC13XX_26XX platform.
 *
 * NOTE: currently a bare-bones implementation to allow for building.
 */

#pragma once

#include <platform/FreeRTOS/GenericThreadStackManagerImpl_FreeRTOS.h>
#include <platform/OpenThread/GenericThreadStackManagerImpl_OpenThread.h>

#include <openthread/tasklet.h>
#include <openthread/thread.h>

#include <queue.h>

extern "C" void platformAlarmSignal();
extern "C" void platformAlarmMicroSignal();
extern "C" void platformRadioSignal(uintptr_t arg);
extern "C" void platformUartSignal(uintptr_t arg);

namespace chip {
namespace DeviceLayer {

class ThreadStackManager;
class ThreadStackManagerImpl;

/**
 * Concrete implementation of the ThreadStackManager singleton object for CC13XX_26XX.
 */
class ThreadStackManagerImpl final : public ThreadStackManager,
                                     public Internal::GenericThreadStackManagerImpl_OpenThread<ThreadStackManagerImpl>,
                                     public Internal::GenericThreadStackManagerImpl_FreeRTOS<ThreadStackManagerImpl>
{
    // Allow the ThreadStackManager interface class to delegate method calls to
    // the implementation methods provided by this class.
    friend class ThreadStackManager;

    // Allow the generic implementation base classes to call helper methods on
    // this class.
#ifndef DOXYGEN_SHOULD_SKIP_THIS
    friend Internal::GenericThreadStackManagerImpl_OpenThread<ThreadStackManagerImpl>;
    friend Internal::GenericThreadStackManagerImpl_FreeRTOS<ThreadStackManagerImpl>;
#endif

    // Allow glue functions called by OpenThread to call helper methods on this
    // class.
    friend void ::platformAlarmSignal();
    friend void ::platformAlarmMicroSignal();
    friend void ::platformRadioSignal(uintptr_t arg);
    friend void ::platformUartSignal(uintptr_t arg);
    friend void ::otTaskletsSignalPending(otInstance * otInst);

    enum procQueueCmd
    {
        procQueueCmd_alarm,
        procQueueCmd_radio,
        procQueueCmd_tasklets,
        procQueueCmd_uart,
        procQueueCmd_alarmu,
    };

    struct procQueueMsg
    {
        enum procQueueCmd cmd;
        uintptr_t arg;
    };

public:
    // ===== Platform-specific members that may be accessed directly by the application.

    using ThreadStackManager::InitThreadStack;
    CHIP_ERROR InitThreadStack(otInstance * otInst);
    void _SendProcMessage(procQueueMsg & procMsg);
    void _ProcMessage(otInstance * aInstance);
    void GetExtAddress(otExtAddress & aExtAddr);
    CHIP_ERROR GetBufferInfo(void);
    bool IsThreadAttached(void);
    bool IsThreadEnabled(void);

private:
    // ===== Methods that implement the ThreadStackManager abstract interface.

    CHIP_ERROR _InitThreadStack(void);

    // ===== Members for internal use by the following friends.

    friend ThreadStackManager & ::chip::DeviceLayer::ThreadStackMgr(void);
    friend ThreadStackManagerImpl & ::chip::DeviceLayer::ThreadStackMgrImpl(void);

    static ThreadStackManagerImpl sInstance;

    static bool IsInitialized();

    // ===== Private members for use by this class only.

    ThreadStackManagerImpl() = default;
    QueueHandle_t procQueue;
    QueueHandle_t procQueue_radio;
};

/**
 * Returns the public interface of the ThreadStackManager singleton object.
 *
 * chip applications should use this to access features of the ThreadStackManager object
 * that are common to all platforms.
 */
inline ThreadStackManager & ThreadStackMgr(void)
{
    return ThreadStackManagerImpl::sInstance;
}

/**
 * Returns the platform-specific implementation of the ThreadStackManager singleton object.
 *
 * chip applications can use this to gain access to features of the ThreadStackManager
 * that are specific to SoC.
 */
inline ThreadStackManagerImpl & ThreadStackMgrImpl(void)
{
    return ThreadStackManagerImpl::sInstance;
}

} // namespace DeviceLayer
} // namespace chip
