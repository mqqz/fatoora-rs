#ifndef _NATIVE_ValidationMessage_HPP
#define _NATIVE_ValidationMessage_HPP

#include "ValidationMessage.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "BindingError.hpp"
#include "Text.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_ValidationMessage_message_type_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_message_type_result;
    fatoora_ValidationMessage_message_type_result fatoora_ValidationMessage_message_type(const _native::capi::ValidationMessage* self);

    typedef struct fatoora_ValidationMessage_code_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_code_result;
    fatoora_ValidationMessage_code_result fatoora_ValidationMessage_code(const _native::capi::ValidationMessage* self);

    typedef struct fatoora_ValidationMessage_category_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_category_result;
    fatoora_ValidationMessage_category_result fatoora_ValidationMessage_category(const _native::capi::ValidationMessage* self);

    typedef struct fatoora_ValidationMessage_message_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_message_result;
    fatoora_ValidationMessage_message_result fatoora_ValidationMessage_message(const _native::capi::ValidationMessage* self);

    typedef struct fatoora_ValidationMessage_status_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_status_result;
    fatoora_ValidationMessage_status_result fatoora_ValidationMessage_status(const _native::capi::ValidationMessage* self);

    void fatoora_ValidationMessage_destroy(ValidationMessage* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::ValidationMessage::message_type() const {
    auto result = _native::capi::fatoora_ValidationMessage_message_type(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::ValidationMessage::code() const {
    auto result = _native::capi::fatoora_ValidationMessage_code(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::ValidationMessage::category() const {
    auto result = _native::capi::fatoora_ValidationMessage_category(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::ValidationMessage::message() const {
    auto result = _native::capi::fatoora_ValidationMessage_message(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::ValidationMessage::status() const {
    auto result = _native::capi::fatoora_ValidationMessage_status(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::ValidationMessage* _native::ValidationMessage::AsFFI() const {
    return reinterpret_cast<const _native::capi::ValidationMessage*>(this);
}

inline _native::capi::ValidationMessage* _native::ValidationMessage::AsFFI() {
    return reinterpret_cast<_native::capi::ValidationMessage*>(this);
}

inline const _native::ValidationMessage* _native::ValidationMessage::FromFFI(const _native::capi::ValidationMessage* ptr) {
    return reinterpret_cast<const _native::ValidationMessage*>(ptr);
}

inline _native::ValidationMessage* _native::ValidationMessage::FromFFI(_native::capi::ValidationMessage* ptr) {
    return reinterpret_cast<_native::ValidationMessage*>(ptr);
}

inline void _native::ValidationMessage::operator delete(void* ptr) {
    _native::capi::fatoora_ValidationMessage_destroy(reinterpret_cast<_native::capi::ValidationMessage*>(ptr));
}


#endif // _NATIVE_ValidationMessage_HPP
