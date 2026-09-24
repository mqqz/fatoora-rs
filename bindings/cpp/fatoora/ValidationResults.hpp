#ifndef fatoora_ValidationResults_HPP
#define fatoora_ValidationResults_HPP

#include "ValidationResults.d.hpp"

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
#include "Text.hpp"
#include "ValidationMessage.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_ValidationResults_status_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResults_status_result;
    fatoora_ValidationResults_status_result fatoora_ValidationResults_status(const fatoora::capi::ValidationResults* self);

    size_t fatoora_ValidationResults_info_len(const fatoora::capi::ValidationResults* self);

    typedef struct fatoora_ValidationResults_info_message_result {union {fatoora::capi::ValidationMessage* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResults_info_message_result;
    fatoora_ValidationResults_info_message_result fatoora_ValidationResults_info_message(const fatoora::capi::ValidationResults* self, size_t index);

    size_t fatoora_ValidationResults_warning_len(const fatoora::capi::ValidationResults* self);

    typedef struct fatoora_ValidationResults_warning_message_result {union {fatoora::capi::ValidationMessage* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResults_warning_message_result;
    fatoora_ValidationResults_warning_message_result fatoora_ValidationResults_warning_message(const fatoora::capi::ValidationResults* self, size_t index);

    size_t fatoora_ValidationResults_error_len(const fatoora::capi::ValidationResults* self);

    typedef struct fatoora_ValidationResults_error_message_result {union {fatoora::capi::ValidationMessage* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResults_error_message_result;
    fatoora_ValidationResults_error_message_result fatoora_ValidationResults_error_message(const fatoora::capi::ValidationResults* self, size_t index);

    void fatoora_ValidationResults_destroy(ValidationResults* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResults::status() const {
    auto result = fatoora::capi::fatoora_ValidationResults_status(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline size_t fatoora::ValidationResults::info_len() const {
    auto result = fatoora::capi::fatoora_ValidationResults_info_len(this->AsFFI());
    return result;
}

inline diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResults::info_message(size_t index) const {
    auto result = fatoora::capi::fatoora_ValidationResults_info_message(this->AsFFI(),
        index);
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::ValidationMessage>>(std::unique_ptr<fatoora::ValidationMessage>(fatoora::ValidationMessage::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline size_t fatoora::ValidationResults::warning_len() const {
    auto result = fatoora::capi::fatoora_ValidationResults_warning_len(this->AsFFI());
    return result;
}

inline diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResults::warning_message(size_t index) const {
    auto result = fatoora::capi::fatoora_ValidationResults_warning_message(this->AsFFI(),
        index);
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::ValidationMessage>>(std::unique_ptr<fatoora::ValidationMessage>(fatoora::ValidationMessage::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline size_t fatoora::ValidationResults::error_len() const {
    auto result = fatoora::capi::fatoora_ValidationResults_error_len(this->AsFFI());
    return result;
}

inline diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResults::error_message(size_t index) const {
    auto result = fatoora::capi::fatoora_ValidationResults_error_message(this->AsFFI(),
        index);
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::ValidationMessage>>(std::unique_ptr<fatoora::ValidationMessage>(fatoora::ValidationMessage::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::ValidationResults* fatoora::ValidationResults::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::ValidationResults*>(this);
}

inline fatoora::capi::ValidationResults* fatoora::ValidationResults::AsFFI() {
    return reinterpret_cast<fatoora::capi::ValidationResults*>(this);
}

inline const fatoora::ValidationResults* fatoora::ValidationResults::FromFFI(const fatoora::capi::ValidationResults* ptr) {
    return reinterpret_cast<const fatoora::ValidationResults*>(ptr);
}

inline fatoora::ValidationResults* fatoora::ValidationResults::FromFFI(fatoora::capi::ValidationResults* ptr) {
    return reinterpret_cast<fatoora::ValidationResults*>(ptr);
}

inline void fatoora::ValidationResults::operator delete(void* ptr) {
    fatoora::capi::fatoora_ValidationResults_destroy(reinterpret_cast<fatoora::capi::ValidationResults*>(ptr));
}


#endif // fatoora_ValidationResults_HPP
