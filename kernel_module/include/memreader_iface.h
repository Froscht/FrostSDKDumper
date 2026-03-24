#pragma once
#include <cstdint>
#include <cstddef>

struct IMemoryReader {
    virtual ~IMemoryReader() = default;
    virtual bool Read(uint64_t addr, void* out, size_t size) = 0;

    template<typename T>
    bool ReadT(uint64_t addr, T& out) {
        return Read(addr, &out, sizeof(T));
    }

    template<typename T>
    T ReadVal(uint64_t addr, bool* success = nullptr) {
        T val = {};
        bool s = Read(addr, &val, sizeof(T));
        if (success) *success = s;
        return val;
    }

};
