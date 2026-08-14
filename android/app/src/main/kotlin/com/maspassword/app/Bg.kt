package com.maspassword.app

import android.os.Handler
import android.os.Looper
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Tiny background-work helper: a single IO thread plus main-thread delivery.
 * Deliberately used instead of coroutines/RxJava to keep the dependency
 * surface of a password manager as small and reviewable as possible.
 */
object Bg {

    private val executor: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "maspassword-io").apply { isDaemon = true }
    }
    private val main = Handler(Looper.getMainLooper())

    /** Run [work] off the main thread; deliver the Result on the main thread. */
    fun <T> submit(work: () -> T, done: (Result<T>) -> Unit) {
        executor.execute {
            val result = runCatching(work)
            main.post { done(result) }
        }
    }

    fun onMain(action: () -> Unit) {
        main.post(action)
    }

    fun onMainDelayed(delayMillis: Long, action: () -> Unit) {
        main.postDelayed(action, delayMillis)
    }
}
