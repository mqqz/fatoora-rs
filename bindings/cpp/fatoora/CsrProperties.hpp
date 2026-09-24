#ifndef fatoora_CsrProperties_HPP
#define fatoora_CsrProperties_HPP

#include "CsrProperties.d.hpp"

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
#include "Csr.hpp"
#include "SigningKey.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_CsrProperties_new_result {union {fatoora::capi::CsrProperties* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsrProperties_new_result;
    fatoora_CsrProperties_new_result fatoora_CsrProperties_new(diplomat::capi::DiplomatStringView common_name, diplomat::capi::DiplomatStringView serial_number, diplomat::capi::DiplomatStringView organization_identifier, diplomat::capi::DiplomatStringView organization_unit_name, diplomat::capi::DiplomatStringView organization_name, diplomat::capi::DiplomatStringView country_name, diplomat::capi::DiplomatStringView invoice_type, diplomat::capi::DiplomatStringView location_address, diplomat::capi::DiplomatStringView industry_business_category);

    typedef struct fatoora_CsrProperties_from_properties_str_result {union {fatoora::capi::CsrProperties* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsrProperties_from_properties_str_result;
    fatoora_CsrProperties_from_properties_str_result fatoora_CsrProperties_from_properties_str(diplomat::capi::DiplomatStringView properties);

    typedef struct fatoora_CsrProperties_parse_csr_config_file_result {union {fatoora::capi::CsrProperties* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsrProperties_parse_csr_config_file_result;
    fatoora_CsrProperties_parse_csr_config_file_result fatoora_CsrProperties_parse_csr_config_file(diplomat::capi::DiplomatStringView path);

    typedef struct fatoora_CsrProperties_build_result {union {fatoora::capi::Csr* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsrProperties_build_result;
    fatoora_CsrProperties_build_result fatoora_CsrProperties_build(const fatoora::capi::CsrProperties* self, const fatoora::capi::SigningKey* key, uint8_t env);

    void fatoora_CsrProperties_destroy(CsrProperties* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::CsrProperties>, std::unique_ptr<fatoora::BindingError>> fatoora::CsrProperties::new_(std::string_view common_name, std::string_view serial_number, std::string_view organization_identifier, std::string_view organization_unit_name, std::string_view organization_name, std::string_view country_name, std::string_view invoice_type, std::string_view location_address, std::string_view industry_business_category) {
    auto result = fatoora::capi::fatoora_CsrProperties_new({common_name.data(), common_name.size()},
        {serial_number.data(), serial_number.size()},
        {organization_identifier.data(), organization_identifier.size()},
        {organization_unit_name.data(), organization_unit_name.size()},
        {organization_name.data(), organization_name.size()},
        {country_name.data(), country_name.size()},
        {invoice_type.data(), invoice_type.size()},
        {location_address.data(), location_address.size()},
        {industry_business_category.data(), industry_business_category.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::CsrProperties>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::CsrProperties>>(std::unique_ptr<fatoora::CsrProperties>(fatoora::CsrProperties::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::CsrProperties>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::CsrProperties>, std::unique_ptr<fatoora::BindingError>> fatoora::CsrProperties::from_properties_str(std::string_view properties) {
    auto result = fatoora::capi::fatoora_CsrProperties_from_properties_str({properties.data(), properties.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::CsrProperties>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::CsrProperties>>(std::unique_ptr<fatoora::CsrProperties>(fatoora::CsrProperties::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::CsrProperties>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::CsrProperties>, std::unique_ptr<fatoora::BindingError>> fatoora::CsrProperties::parse_csr_config_file(std::string_view path) {
    auto result = fatoora::capi::fatoora_CsrProperties_parse_csr_config_file({path.data(), path.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::CsrProperties>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::CsrProperties>>(std::unique_ptr<fatoora::CsrProperties>(fatoora::CsrProperties::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::CsrProperties>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Csr>, std::unique_ptr<fatoora::BindingError>> fatoora::CsrProperties::build(const fatoora::SigningKey& key, uint8_t env) const {
    auto result = fatoora::capi::fatoora_CsrProperties_build(this->AsFFI(),
        key.AsFFI(),
        env);
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Csr>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Csr>>(std::unique_ptr<fatoora::Csr>(fatoora::Csr::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Csr>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::CsrProperties* fatoora::CsrProperties::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::CsrProperties*>(this);
}

inline fatoora::capi::CsrProperties* fatoora::CsrProperties::AsFFI() {
    return reinterpret_cast<fatoora::capi::CsrProperties*>(this);
}

inline const fatoora::CsrProperties* fatoora::CsrProperties::FromFFI(const fatoora::capi::CsrProperties* ptr) {
    return reinterpret_cast<const fatoora::CsrProperties*>(ptr);
}

inline fatoora::CsrProperties* fatoora::CsrProperties::FromFFI(fatoora::capi::CsrProperties* ptr) {
    return reinterpret_cast<fatoora::CsrProperties*>(ptr);
}

inline void fatoora::CsrProperties::operator delete(void* ptr) {
    fatoora::capi::fatoora_CsrProperties_destroy(reinterpret_cast<fatoora::capi::CsrProperties*>(ptr));
}


#endif // fatoora_CsrProperties_HPP
