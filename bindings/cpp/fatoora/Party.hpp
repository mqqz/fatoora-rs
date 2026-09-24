#ifndef fatoora_Party_HPP
#define fatoora_Party_HPP

#include "Party.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "../diplomat_runtime.hpp"
#include "Address.hpp"
#include "BindingError.hpp"
#include "OtherId.hpp"
#include "VatId.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_Party_address_result {union {fatoora::capi::Address* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Party_address_result;
    fatoora_Party_address_result fatoora_Party_address(const fatoora::capi::Party* self);

    typedef struct fatoora_Party_vat_id_result {union {fatoora::capi::VatId* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Party_vat_id_result;
    fatoora_Party_vat_id_result fatoora_Party_vat_id(const fatoora::capi::Party* self);

    typedef struct fatoora_Party_other_id_result {union {fatoora::capi::OtherId* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Party_other_id_result;
    fatoora_Party_other_id_result fatoora_Party_other_id(const fatoora::capi::Party* self);

    typedef struct fatoora_Party_name_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Party_name_result;
    fatoora_Party_name_result fatoora_Party_name(const fatoora::capi::Party* self, diplomat::capi::DiplomatWrite* write);

    void fatoora_Party_destroy(Party* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::Address>, std::unique_ptr<fatoora::BindingError>> fatoora::Party::address() const {
    auto result = fatoora::capi::fatoora_Party_address(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Address>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Address>>(std::unique_ptr<fatoora::Address>(fatoora::Address::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Address>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::VatId>, std::unique_ptr<fatoora::BindingError>> fatoora::Party::vat_id() const {
    auto result = fatoora::capi::fatoora_Party_vat_id(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::VatId>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::VatId>>(std::unique_ptr<fatoora::VatId>(fatoora::VatId::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::VatId>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::OtherId>, std::unique_ptr<fatoora::BindingError>> fatoora::Party::other_id() const {
    auto result = fatoora::capi::fatoora_Party_other_id(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::OtherId>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::OtherId>>(std::unique_ptr<fatoora::OtherId>(fatoora::OtherId::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::OtherId>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Party::name() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Party_name(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Party::name_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Party_name(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::Party* fatoora::Party::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::Party*>(this);
}

inline fatoora::capi::Party* fatoora::Party::AsFFI() {
    return reinterpret_cast<fatoora::capi::Party*>(this);
}

inline const fatoora::Party* fatoora::Party::FromFFI(const fatoora::capi::Party* ptr) {
    return reinterpret_cast<const fatoora::Party*>(ptr);
}

inline fatoora::Party* fatoora::Party::FromFFI(fatoora::capi::Party* ptr) {
    return reinterpret_cast<fatoora::Party*>(ptr);
}

inline void fatoora::Party::operator delete(void* ptr) {
    fatoora::capi::fatoora_Party_destroy(reinterpret_cast<fatoora::capi::Party*>(ptr));
}


#endif // fatoora_Party_HPP
