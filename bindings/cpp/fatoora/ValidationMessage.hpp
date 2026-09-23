#ifndef fatoora_ValidationMessage_HPP
#define fatoora_ValidationMessage_HPP

#include "ValidationMessage.d.hpp"

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


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_ValidationMessage_message_type_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_message_type_result;
    fatoora_ValidationMessage_message_type_result fatoora_ValidationMessage_message_type(const fatoora::capi::ValidationMessage* self);

    typedef struct fatoora_ValidationMessage_code_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_code_result;
    fatoora_ValidationMessage_code_result fatoora_ValidationMessage_code(const fatoora::capi::ValidationMessage* self);

    typedef struct fatoora_ValidationMessage_category_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_category_result;
    fatoora_ValidationMessage_category_result fatoora_ValidationMessage_category(const fatoora::capi::ValidationMessage* self);

    typedef struct fatoora_ValidationMessage_message_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_message_result;
    fatoora_ValidationMessage_message_result fatoora_ValidationMessage_message(const fatoora::capi::ValidationMessage* self);

    typedef struct fatoora_ValidationMessage_status_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_status_result;
    fatoora_ValidationMessage_status_result fatoora_ValidationMessage_status(const fatoora::capi::ValidationMessage* self);

    void fatoora_ValidationMessage_destroy(ValidationMessage* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationMessage::message_type() const {
    auto result = fatoora::capi::fatoora_ValidationMessage_message_type(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationMessage::code() const {
    auto result = fatoora::capi::fatoora_ValidationMessage_code(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationMessage::category() const {
    auto result = fatoora::capi::fatoora_ValidationMessage_category(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationMessage::message() const {
    auto result = fatoora::capi::fatoora_ValidationMessage_message(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationMessage::status() const {
    auto result = fatoora::capi::fatoora_ValidationMessage_status(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::ValidationMessage* fatoora::ValidationMessage::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::ValidationMessage*>(this);
}

inline fatoora::capi::ValidationMessage* fatoora::ValidationMessage::AsFFI() {
    return reinterpret_cast<fatoora::capi::ValidationMessage*>(this);
}

inline const fatoora::ValidationMessage* fatoora::ValidationMessage::FromFFI(const fatoora::capi::ValidationMessage* ptr) {
    return reinterpret_cast<const fatoora::ValidationMessage*>(ptr);
}

inline fatoora::ValidationMessage* fatoora::ValidationMessage::FromFFI(fatoora::capi::ValidationMessage* ptr) {
    return reinterpret_cast<fatoora::ValidationMessage*>(ptr);
}

inline void fatoora::ValidationMessage::operator delete(void* ptr) {
    fatoora::capi::fatoora_ValidationMessage_destroy(reinterpret_cast<fatoora::capi::ValidationMessage*>(ptr));
}


#endif // fatoora_ValidationMessage_HPP
