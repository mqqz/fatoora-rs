#ifndef fatoora_OriginalInvoiceRef_HPP
#define fatoora_OriginalInvoiceRef_HPP

#include "OriginalInvoiceRef.d.hpp"

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

    typedef struct fatoora_OriginalInvoiceRef_id_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_OriginalInvoiceRef_id_result;
    fatoora_OriginalInvoiceRef_id_result fatoora_OriginalInvoiceRef_id(const fatoora::capi::OriginalInvoiceRef* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_OriginalInvoiceRef_uuid_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_OriginalInvoiceRef_uuid_result;
    fatoora_OriginalInvoiceRef_uuid_result fatoora_OriginalInvoiceRef_uuid(const fatoora::capi::OriginalInvoiceRef* self);

    typedef struct fatoora_OriginalInvoiceRef_issue_date_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_OriginalInvoiceRef_issue_date_result;
    fatoora_OriginalInvoiceRef_issue_date_result fatoora_OriginalInvoiceRef_issue_date(const fatoora::capi::OriginalInvoiceRef* self);

    void fatoora_OriginalInvoiceRef_destroy(OriginalInvoiceRef* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::OriginalInvoiceRef::id() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_OriginalInvoiceRef_id(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::OriginalInvoiceRef::id_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_OriginalInvoiceRef_id(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::OriginalInvoiceRef::uuid() const {
    auto result = fatoora::capi::fatoora_OriginalInvoiceRef_uuid(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::OriginalInvoiceRef::issue_date() const {
    auto result = fatoora::capi::fatoora_OriginalInvoiceRef_issue_date(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::OriginalInvoiceRef* fatoora::OriginalInvoiceRef::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::OriginalInvoiceRef*>(this);
}

inline fatoora::capi::OriginalInvoiceRef* fatoora::OriginalInvoiceRef::AsFFI() {
    return reinterpret_cast<fatoora::capi::OriginalInvoiceRef*>(this);
}

inline const fatoora::OriginalInvoiceRef* fatoora::OriginalInvoiceRef::FromFFI(const fatoora::capi::OriginalInvoiceRef* ptr) {
    return reinterpret_cast<const fatoora::OriginalInvoiceRef*>(ptr);
}

inline fatoora::OriginalInvoiceRef* fatoora::OriginalInvoiceRef::FromFFI(fatoora::capi::OriginalInvoiceRef* ptr) {
    return reinterpret_cast<fatoora::OriginalInvoiceRef*>(ptr);
}

inline void fatoora::OriginalInvoiceRef::operator delete(void* ptr) {
    fatoora::capi::fatoora_OriginalInvoiceRef_destroy(reinterpret_cast<fatoora::capi::OriginalInvoiceRef*>(ptr));
}


#endif // fatoora_OriginalInvoiceRef_HPP
