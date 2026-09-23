#ifndef _NATIVE_OriginalInvoiceRef_HPP
#define _NATIVE_OriginalInvoiceRef_HPP

#include "OriginalInvoiceRef.d.hpp"

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

    typedef struct fatoora_OriginalInvoiceRef_id_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_OriginalInvoiceRef_id_result;
    fatoora_OriginalInvoiceRef_id_result fatoora_OriginalInvoiceRef_id(const _native::capi::OriginalInvoiceRef* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_OriginalInvoiceRef_uuid_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_OriginalInvoiceRef_uuid_result;
    fatoora_OriginalInvoiceRef_uuid_result fatoora_OriginalInvoiceRef_uuid(const _native::capi::OriginalInvoiceRef* self);

    typedef struct fatoora_OriginalInvoiceRef_issue_date_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_OriginalInvoiceRef_issue_date_result;
    fatoora_OriginalInvoiceRef_issue_date_result fatoora_OriginalInvoiceRef_issue_date(const _native::capi::OriginalInvoiceRef* self);

    void fatoora_OriginalInvoiceRef_destroy(OriginalInvoiceRef* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::OriginalInvoiceRef::id() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_OriginalInvoiceRef_id(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::OriginalInvoiceRef::id_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_OriginalInvoiceRef_id(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::OriginalInvoiceRef::uuid() const {
    auto result = _native::capi::fatoora_OriginalInvoiceRef_uuid(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::OriginalInvoiceRef::issue_date() const {
    auto result = _native::capi::fatoora_OriginalInvoiceRef_issue_date(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::OriginalInvoiceRef* _native::OriginalInvoiceRef::AsFFI() const {
    return reinterpret_cast<const _native::capi::OriginalInvoiceRef*>(this);
}

inline _native::capi::OriginalInvoiceRef* _native::OriginalInvoiceRef::AsFFI() {
    return reinterpret_cast<_native::capi::OriginalInvoiceRef*>(this);
}

inline const _native::OriginalInvoiceRef* _native::OriginalInvoiceRef::FromFFI(const _native::capi::OriginalInvoiceRef* ptr) {
    return reinterpret_cast<const _native::OriginalInvoiceRef*>(ptr);
}

inline _native::OriginalInvoiceRef* _native::OriginalInvoiceRef::FromFFI(_native::capi::OriginalInvoiceRef* ptr) {
    return reinterpret_cast<_native::OriginalInvoiceRef*>(ptr);
}

inline void _native::OriginalInvoiceRef::operator delete(void* ptr) {
    _native::capi::fatoora_OriginalInvoiceRef_destroy(reinterpret_cast<_native::capi::OriginalInvoiceRef*>(ptr));
}


#endif // _NATIVE_OriginalInvoiceRef_HPP
