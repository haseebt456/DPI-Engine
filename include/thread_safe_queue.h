#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>

// A blocking, thread-safe queue. One or more producers call push(); one or
// more consumers call pop(), which sleeps (rather than busy-spins) until
// there's work or the queue has been shut down.
template <typename T>
class ThreadSafeQueue {
public:
    void push(T item) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(item));
        }
        cv_.notify_one(); // wake exactly one sleeping consumer
    }

    // Blocks until an item is available. Returns std::nullopt only once
    // shutdown() has been called AND the queue has been fully drained --
    // that's how a worker thread knows it's safe to exit.
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !queue_.empty() || shutdown_; });

        if (queue_.empty() && shutdown_) {
            return std::nullopt;
        }

        T item = std::move(queue_.front());
        queue_.pop();
        return item;
    }

    // Signals all consumers: no more items are coming. Any already queued
    // items are still delivered via pop() before it starts returning nullopt.
    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            shutdown_ = true;
        }
        cv_.notify_all();
    }

private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool shutdown_ = false;
};
