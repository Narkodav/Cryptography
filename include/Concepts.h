#pragma once
namespace Cryptography {

    template <typename T>
    concept Container = requires(T t) {
        t.data();
        t.size();
        t.begin();
        t.operator[](size_t{});
    };

}