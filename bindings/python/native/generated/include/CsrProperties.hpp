#ifndef _NATIVE_CsrProperties_HPP
#define _NATIVE_CsrProperties_HPP

#include "CsrProperties.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "BindingError.hpp"
#include "Csr.hpp"
#include "SigningKey.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_CsrProperties_new_result {union {_native::capi::CsrProperties* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsrProperties_new_result;
    fatoora_CsrProperties_new_result fatoora_CsrProperties_new(_native::diplomat::capi::DiplomatStringView common_name, _native::diplomat::capi::DiplomatStringView serial_number, _native::diplomat::capi::DiplomatStringView organization_identifier, _native::diplomat::capi::DiplomatStringView organization_unit_name, _native::diplomat::capi::DiplomatStringView organization_name, _native::diplomat::capi::DiplomatStringView country_name, _native::diplomat::capi::DiplomatStringView invoice_type, _native::diplomat::capi::DiplomatStringView location_address, _native::diplomat::capi::DiplomatStringView industry_business_category);

    typedef struct fatoora_CsrProperties_from_properties_str_result {union {_native::capi::CsrProperties* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsrProperties_from_properties_str_result;
    fatoora_CsrProperties_from_properties_str_result fatoora_CsrProperties_from_properties_str(_native::diplomat::capi::DiplomatStringView properties);

    typedef struct fatoora_CsrProperties_parse_csr_config_file_result {union {_native::capi::CsrProperties* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsrProperties_parse_csr_config_file_result;
    fatoora_CsrProperties_parse_csr_config_file_result fatoora_CsrProperties_parse_csr_config_file(_native::diplomat::capi::DiplomatStringView path);

    typedef struct fatoora_CsrProperties_build_result {union {_native::capi::Csr* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsrProperties_build_result;
    fatoora_CsrProperties_build_result fatoora_CsrProperties_build(const _native::capi::CsrProperties* self, const _native::capi::SigningKey* key, uint8_t env);

    void fatoora_CsrProperties_destroy(CsrProperties* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>> _native::CsrProperties::new_(std::string_view common_name, std::string_view serial_number, std::string_view organization_identifier, std::string_view organization_unit_name, std::string_view organization_name, std::string_view country_name, std::string_view invoice_type, std::string_view location_address, std::string_view industry_business_category) {
    auto result = _native::capi::fatoora_CsrProperties_new({common_name.data(), common_name.size()},
        {serial_number.data(), serial_number.size()},
        {organization_identifier.data(), organization_identifier.size()},
        {organization_unit_name.data(), organization_unit_name.size()},
        {organization_name.data(), organization_name.size()},
        {country_name.data(), country_name.size()},
        {invoice_type.data(), invoice_type.size()},
        {location_address.data(), location_address.size()},
        {industry_business_category.data(), industry_business_category.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::CsrProperties>>(std::unique_ptr<_native::CsrProperties>(_native::CsrProperties::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>> _native::CsrProperties::from_properties_str(std::string_view properties) {
    auto result = _native::capi::fatoora_CsrProperties_from_properties_str({properties.data(), properties.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::CsrProperties>>(std::unique_ptr<_native::CsrProperties>(_native::CsrProperties::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>> _native::CsrProperties::parse_csr_config_file(std::string_view path) {
    auto result = _native::capi::fatoora_CsrProperties_parse_csr_config_file({path.data(), path.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::CsrProperties>>(std::unique_ptr<_native::CsrProperties>(_native::CsrProperties::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Csr>, std::unique_ptr<_native::BindingError>> _native::CsrProperties::build(const _native::SigningKey& key, uint8_t env) const {
    auto result = _native::capi::fatoora_CsrProperties_build(this->AsFFI(),
        key.AsFFI(),
        env);
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Csr>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Csr>>(std::unique_ptr<_native::Csr>(_native::Csr::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Csr>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::CsrProperties* _native::CsrProperties::AsFFI() const {
    return reinterpret_cast<const _native::capi::CsrProperties*>(this);
}

inline _native::capi::CsrProperties* _native::CsrProperties::AsFFI() {
    return reinterpret_cast<_native::capi::CsrProperties*>(this);
}

inline const _native::CsrProperties* _native::CsrProperties::FromFFI(const _native::capi::CsrProperties* ptr) {
    return reinterpret_cast<const _native::CsrProperties*>(ptr);
}

inline _native::CsrProperties* _native::CsrProperties::FromFFI(_native::capi::CsrProperties* ptr) {
    return reinterpret_cast<_native::CsrProperties*>(ptr);
}

inline void _native::CsrProperties::operator delete(void* ptr) {
    _native::capi::fatoora_CsrProperties_destroy(reinterpret_cast<_native::capi::CsrProperties*>(ptr));
}


#endif // _NATIVE_CsrProperties_HPP
