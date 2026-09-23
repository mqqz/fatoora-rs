#ifndef _NATIVE_Party_HPP
#define _NATIVE_Party_HPP

#include "Party.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "Address.hpp"
#include "BindingError.hpp"
#include "OtherId.hpp"
#include "VatId.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_Party_address_result {union {_native::capi::Address* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Party_address_result;
    fatoora_Party_address_result fatoora_Party_address(const _native::capi::Party* self);

    typedef struct fatoora_Party_vat_id_result {union {_native::capi::VatId* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Party_vat_id_result;
    fatoora_Party_vat_id_result fatoora_Party_vat_id(const _native::capi::Party* self);

    typedef struct fatoora_Party_other_id_result {union {_native::capi::OtherId* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Party_other_id_result;
    fatoora_Party_other_id_result fatoora_Party_other_id(const _native::capi::Party* self);

    typedef struct fatoora_Party_name_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Party_name_result;
    fatoora_Party_name_result fatoora_Party_name(const _native::capi::Party* self, _native::diplomat::capi::DiplomatWrite* write);

    void fatoora_Party_destroy(Party* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::Address>, std::unique_ptr<_native::BindingError>> _native::Party::address() const {
    auto result = _native::capi::fatoora_Party_address(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Address>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Address>>(std::unique_ptr<_native::Address>(_native::Address::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Address>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::VatId>, std::unique_ptr<_native::BindingError>> _native::Party::vat_id() const {
    auto result = _native::capi::fatoora_Party_vat_id(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::VatId>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::VatId>>(std::unique_ptr<_native::VatId>(_native::VatId::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::VatId>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::OtherId>, std::unique_ptr<_native::BindingError>> _native::Party::other_id() const {
    auto result = _native::capi::fatoora_Party_other_id(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::OtherId>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::OtherId>>(std::unique_ptr<_native::OtherId>(_native::OtherId::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::OtherId>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Party::name() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Party_name(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Party::name_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Party_name(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::Party* _native::Party::AsFFI() const {
    return reinterpret_cast<const _native::capi::Party*>(this);
}

inline _native::capi::Party* _native::Party::AsFFI() {
    return reinterpret_cast<_native::capi::Party*>(this);
}

inline const _native::Party* _native::Party::FromFFI(const _native::capi::Party* ptr) {
    return reinterpret_cast<const _native::Party*>(ptr);
}

inline _native::Party* _native::Party::FromFFI(_native::capi::Party* ptr) {
    return reinterpret_cast<_native::Party*>(ptr);
}

inline void _native::Party::operator delete(void* ptr) {
    _native::capi::fatoora_Party_destroy(reinterpret_cast<_native::capi::Party*>(ptr));
}


#endif // _NATIVE_Party_HPP
