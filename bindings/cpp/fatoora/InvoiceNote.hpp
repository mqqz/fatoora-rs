#ifndef fatoora_InvoiceNote_HPP
#define fatoora_InvoiceNote_HPP

#include "InvoiceNote.d.hpp"

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

    typedef struct fatoora_InvoiceNote_language_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceNote_language_result;
    fatoora_InvoiceNote_language_result fatoora_InvoiceNote_language(const fatoora::capi::InvoiceNote* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceNote_text_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceNote_text_result;
    fatoora_InvoiceNote_text_result fatoora_InvoiceNote_text(const fatoora::capi::InvoiceNote* self, diplomat::capi::DiplomatWrite* write);

    void fatoora_InvoiceNote_destroy(InvoiceNote* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceNote::language() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceNote_language(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceNote::language_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceNote_language(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceNote::text() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceNote_text(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceNote::text_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceNote_text(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::InvoiceNote* fatoora::InvoiceNote::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::InvoiceNote*>(this);
}

inline fatoora::capi::InvoiceNote* fatoora::InvoiceNote::AsFFI() {
    return reinterpret_cast<fatoora::capi::InvoiceNote*>(this);
}

inline const fatoora::InvoiceNote* fatoora::InvoiceNote::FromFFI(const fatoora::capi::InvoiceNote* ptr) {
    return reinterpret_cast<const fatoora::InvoiceNote*>(ptr);
}

inline fatoora::InvoiceNote* fatoora::InvoiceNote::FromFFI(fatoora::capi::InvoiceNote* ptr) {
    return reinterpret_cast<fatoora::InvoiceNote*>(ptr);
}

inline void fatoora::InvoiceNote::operator delete(void* ptr) {
    fatoora::capi::fatoora_InvoiceNote_destroy(reinterpret_cast<fatoora::capi::InvoiceNote*>(ptr));
}


#endif // fatoora_InvoiceNote_HPP
