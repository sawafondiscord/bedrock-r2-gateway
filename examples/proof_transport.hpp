#pragma once
#include <syslocker/bedrock/http.hpp>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

// Captures raw responses, never grants access. The SDK and Worker verify independently.
class ProofTransport final : public syslocker::bedrock::IHttpClient {
public:
    explicit ProofTransport(std::unique_ptr<syslocker::bedrock::IHttpClient> inner,
                            std::string origin = "https://systemlocker.net")
        : inner_(std::move(inner)), origin_(std::move(origin)) {
        if (!inner_) throw std::invalid_argument("HTTP transport is required");
    }
    syslocker::bedrock::HttpResponse post(
        std::string_view url, const syslocker::bedrock::FormFields& fields) override {
        const bool bedrock = url == origin_ + "/auth/bedrock/init" ||
                             url == origin_ + "/auth/bedrock/beat";
        if (bedrock) clear();
        auto response = inner_->post(url, fields);
        if (bedrock && response.ok() && response.body.size() <= 65536) {
            std::lock_guard<std::mutex> lock(mutex_);
            proof_ = response.body;
        }
        return response;
    }
    syslocker::bedrock::HttpResponse get(
        std::string_view url, const syslocker::bedrock::HttpHeaders& headers) override {
        return inner_->get(url, headers);
    }
    std::string snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return proof_;
    }
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        proof_.clear();
    }
private:
    std::unique_ptr<syslocker::bedrock::IHttpClient> inner_;
    std::string origin_;
    mutable std::mutex mutex_;
    std::string proof_;
};
