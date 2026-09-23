#ifndef _NATIVE_ValidationResults_HPP
#define _NATIVE_ValidationResults_HPP

#include "ValidationResults.d.hpp"

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
#include "ValidationMessage.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_ValidationResults_status_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResults_status_result;
    fatoora_ValidationResults_status_result fatoora_ValidationResults_status(const _native::capi::ValidationResults* self);

    size_t fatoora_ValidationResults_info_len(const _native::capi::ValidationResults* self);

    typedef struct fatoora_ValidationResults_info_message_result {union {_native::capi::ValidationMessage* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResults_info_message_result;
    fatoora_ValidationResults_info_message_result fatoora_ValidationResults_info_message(const _native::capi::ValidationResults* self, size_t index);

    size_t fatoora_ValidationResults_warning_len(const _native::capi::ValidationResults* self);

    typedef struct fatoora_ValidationResults_warning_message_result {union {_native::capi::ValidationMessage* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResults_warning_message_result;
    fatoora_ValidationResults_warning_message_result fatoora_ValidationResults_warning_message(const _native::capi::ValidationResults* self, size_t index);

    size_t fatoora_ValidationResults_error_len(const _native::capi::ValidationResults* self);

    typedef struct fatoora_ValidationResults_error_message_result {union {_native::capi::ValidationMessage* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResults_error_message_result;
    fatoora_ValidationResults_error_message_result fatoora_ValidationResults_error_message(const _native::capi::ValidationResults* self, size_t index);

    void fatoora_ValidationResults_destroy(ValidationResults* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::ValidationResults::status() const {
    auto result = _native::capi::fatoora_ValidationResults_status(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline size_t _native::ValidationResults::info_len() const {
    auto result = _native::capi::fatoora_ValidationResults_info_len(this->AsFFI());
    return result;
}

inline _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>> _native::ValidationResults::info_message(size_t index) const {
    auto result = _native::capi::fatoora_ValidationResults_info_message(this->AsFFI(),
        index);
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::ValidationMessage>>(std::unique_ptr<_native::ValidationMessage>(_native::ValidationMessage::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline size_t _native::ValidationResults::warning_len() const {
    auto result = _native::capi::fatoora_ValidationResults_warning_len(this->AsFFI());
    return result;
}

inline _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>> _native::ValidationResults::warning_message(size_t index) const {
    auto result = _native::capi::fatoora_ValidationResults_warning_message(this->AsFFI(),
        index);
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::ValidationMessage>>(std::unique_ptr<_native::ValidationMessage>(_native::ValidationMessage::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline size_t _native::ValidationResults::error_len() const {
    auto result = _native::capi::fatoora_ValidationResults_error_len(this->AsFFI());
    return result;
}

inline _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>> _native::ValidationResults::error_message(size_t index) const {
    auto result = _native::capi::fatoora_ValidationResults_error_message(this->AsFFI(),
        index);
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::ValidationMessage>>(std::unique_ptr<_native::ValidationMessage>(_native::ValidationMessage::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::ValidationResults* _native::ValidationResults::AsFFI() const {
    return reinterpret_cast<const _native::capi::ValidationResults*>(this);
}

inline _native::capi::ValidationResults* _native::ValidationResults::AsFFI() {
    return reinterpret_cast<_native::capi::ValidationResults*>(this);
}

inline const _native::ValidationResults* _native::ValidationResults::FromFFI(const _native::capi::ValidationResults* ptr) {
    return reinterpret_cast<const _native::ValidationResults*>(ptr);
}

inline _native::ValidationResults* _native::ValidationResults::FromFFI(_native::capi::ValidationResults* ptr) {
    return reinterpret_cast<_native::ValidationResults*>(ptr);
}

inline void _native::ValidationResults::operator delete(void* ptr) {
    _native::capi::fatoora_ValidationResults_destroy(reinterpret_cast<_native::capi::ValidationResults*>(ptr));
}


#endif // _NATIVE_ValidationResults_HPP
