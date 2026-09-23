#ifndef fatoora_Text_HPP
#define fatoora_Text_HPP

#include "Text.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "../diplomat_runtime.hpp"
#include "BindingError.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_Text_value_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Text_value_result;
    fatoora_Text_value_result fatoora_Text_value(const fatoora::capi::Text* self, diplomat::capi::DiplomatWrite* write);

    void fatoora_Text_destroy(Text* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Text::value() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Text_value(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Text::value_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Text_value(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::Text* fatoora::Text::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::Text*>(this);
}

inline fatoora::capi::Text* fatoora::Text::AsFFI() {
    return reinterpret_cast<fatoora::capi::Text*>(this);
}

inline const fatoora::Text* fatoora::Text::FromFFI(const fatoora::capi::Text* ptr) {
    return reinterpret_cast<const fatoora::Text*>(ptr);
}

inline fatoora::Text* fatoora::Text::FromFFI(fatoora::capi::Text* ptr) {
    return reinterpret_cast<fatoora::Text*>(ptr);
}

inline void fatoora::Text::operator delete(void* ptr) {
    fatoora::capi::fatoora_Text_destroy(reinterpret_cast<fatoora::capi::Text*>(ptr));
}


#endif // fatoora_Text_HPP
