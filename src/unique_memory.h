#pragma once

#include <memory.h>

template<typename Type>
using AllocatePtr = void *(*)(size_t);

template<typename Type>
using FreePtr = void (*)(void *);

template<typename Type, AllocatePtr<Type> Allocate, FreePtr<Type> Free>
class unique_ptr {

    Type *m_ptr = nullptr;

public:
    unique_ptr() = default;

    unique_ptr(Type* ptr) : m_ptr(ptr) {}
    unique_ptr& operator=(Type* ptr) {

        if (m_ptr) {
            Free(m_ptr);
        }

        m_ptr = ptr;
        return *this;
    }

    unique_ptr(const unique_ptr&) = delete;
    unique_ptr& operator=(const unique_ptr&) = delete;

    unique_ptr(unique_ptr&& obj) noexcept {
        free();
        m_ptr = obj.m_ptr;
        obj.m_ptr = {};
    }

    unique_ptr& operator=(unique_ptr&& obj) noexcept {
        free();
        m_ptr = obj.m_ptr;
        obj.m_ptr = {};
        return *this;
    }

    [[nodiscard]]
    Type *operator->() const noexcept {
        return m_ptr;
    }

    ~unique_ptr() noexcept {
        free();
    }

    [[nodiscard]]
    bool allocate(size_t size = 1) noexcept {

        if (m_ptr) {
            Free(m_ptr);
        }

        m_ptr = (Type *)Allocate(size * sizeof(Type));
        return m_ptr != nullptr;
    }

    void free() noexcept {

        if (m_ptr) {
            Free(m_ptr);
        }

        m_ptr = nullptr;
    }

    [[nodiscard]]
    bool operator==(Type *ptr) const noexcept { return m_ptr == ptr; }

    [[nodiscard]]
    Type *data() const noexcept { return m_ptr; }
};

template<typename Type>
using unique_c_mem = unique_ptr<Type, ::malloc, ::free>;

using unique_c_buffer = unique_ptr<uint8_t, ::malloc, ::free>;

// https://en.cppreference.com/w/cpp/experimental/unique_resource

template<typename Type, typename Destroy>
class unique_resource {

    Type m_res = {};

public:
    unique_resource() = default;

    unique_resource(Type res) : m_res(res) {}
    unique_resource& operator=(Type* res) {

        if (m_res) {
            Destroy(m_res);
        }

        m_res = res;
        return *this;
    }

    unique_resource(const unique_resource&) = delete;
    unique_resource& operator=(const unique_resource&) = delete;

    unique_resource(unique_resource&& obj) noexcept {
        destroy();
        m_res = obj.m_res;
        obj.m_res = {};
    }

    unique_resource& operator=(unique_resource&& obj) noexcept {
        destroy();
        m_res = obj.m_res;
        obj.m_res = {};
        return *this;
    }

    ~unique_resource() noexcept {
        destroy();
    }

    void destroy() noexcept {

        if (m_res) {
            Destroy(m_res);
        }

        m_res = {};
    }

    Type *reset() noexcept {
        destroy();
        return &m_res;
    }

    [[nodiscard]]
    bool operator==(Type res) const noexcept { return m_res == res; }

    [[nodiscard]]
    Type get() const noexcept { return m_res; }
};
