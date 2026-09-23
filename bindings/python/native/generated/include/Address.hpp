#ifndef _NATIVE_Address_HPP
#define _NATIVE_Address_HPP

#include "Address.d.hpp"

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

    typedef struct fatoora_Address_new_result {union {_native::capi::Address* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Address_new_result;
    fatoora_Address_new_result fatoora_Address_new(_native::diplomat::capi::DiplomatStringView country_code, _native::diplomat::capi::DiplomatStringView city, _native::diplomat::capi::DiplomatStringView street, _native::diplomat::capi::DiplomatStringView building_number, _native::diplomat::capi::DiplomatStringView postal_code, _native::diplomat::capi::OptionStringView additional_street, _native::diplomat::capi::OptionStringView additional_number, _native::diplomat::capi::OptionStringView district);

    typedef struct fatoora_Address_city_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Address_city_result;
    fatoora_Address_city_result fatoora_Address_city(const _native::capi::Address* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Address_street_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Address_street_result;
    fatoora_Address_street_result fatoora_Address_street(const _native::capi::Address* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Address_building_number_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Address_building_number_result;
    fatoora_Address_building_number_result fatoora_Address_building_number(const _native::capi::Address* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Address_postal_code_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Address_postal_code_result;
    fatoora_Address_postal_code_result fatoora_Address_postal_code(const _native::capi::Address* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Address_country_code_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Address_country_code_result;
    fatoora_Address_country_code_result fatoora_Address_country_code(const _native::capi::Address* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Address_additional_street_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Address_additional_street_result;
    fatoora_Address_additional_street_result fatoora_Address_additional_street(const _native::capi::Address* self);

    typedef struct fatoora_Address_additional_number_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Address_additional_number_result;
    fatoora_Address_additional_number_result fatoora_Address_additional_number(const _native::capi::Address* self);

    typedef struct fatoora_Address_district_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Address_district_result;
    fatoora_Address_district_result fatoora_Address_district(const _native::capi::Address* self);

    void fatoora_Address_destroy(Address* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::Address>, std::unique_ptr<_native::BindingError>> _native::Address::new_(std::string_view country_code, std::string_view city, std::string_view street, std::string_view building_number, std::string_view postal_code, std::optional<std::string_view> additional_street, std::optional<std::string_view> additional_number, std::optional<std::string_view> district) {
    auto result = _native::capi::fatoora_Address_new({country_code.data(), country_code.size()},
        {city.data(), city.size()},
        {street.data(), street.size()},
        {building_number.data(), building_number.size()},
        {postal_code.data(), postal_code.size()},
        additional_street.has_value() ? (_native::diplomat::capi::OptionStringView{ { {additional_street.value().data(), additional_street.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        additional_number.has_value() ? (_native::diplomat::capi::OptionStringView{ { {additional_number.value().data(), additional_number.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        district.has_value() ? (_native::diplomat::capi::OptionStringView{ { {district.value().data(), district.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }));
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Address>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Address>>(std::unique_ptr<_native::Address>(_native::Address::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Address>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Address::city() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Address_city(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Address::city_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Address_city(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Address::street() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Address_street(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Address::street_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Address_street(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Address::building_number() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Address_building_number(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Address::building_number_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Address_building_number(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Address::postal_code() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Address_postal_code(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Address::postal_code_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Address_postal_code(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Address::country_code() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Address_country_code(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Address::country_code_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Address_country_code(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::Address::additional_street() const {
    auto result = _native::capi::fatoora_Address_additional_street(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::Address::additional_number() const {
    auto result = _native::capi::fatoora_Address_additional_number(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::Address::district() const {
    auto result = _native::capi::fatoora_Address_district(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::Address* _native::Address::AsFFI() const {
    return reinterpret_cast<const _native::capi::Address*>(this);
}

inline _native::capi::Address* _native::Address::AsFFI() {
    return reinterpret_cast<_native::capi::Address*>(this);
}

inline const _native::Address* _native::Address::FromFFI(const _native::capi::Address* ptr) {
    return reinterpret_cast<const _native::Address*>(ptr);
}

inline _native::Address* _native::Address::FromFFI(_native::capi::Address* ptr) {
    return reinterpret_cast<_native::Address*>(ptr);
}

inline void _native::Address::operator delete(void* ptr) {
    _native::capi::fatoora_Address_destroy(reinterpret_cast<_native::capi::Address*>(ptr));
}


#endif // _NATIVE_Address_HPP
