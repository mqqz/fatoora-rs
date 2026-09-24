#ifndef fatoora_Address_HPP
#define fatoora_Address_HPP

#include "Address.d.hpp"

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

    typedef struct fatoora_Address_new_result {union {fatoora::capi::Address* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Address_new_result;
    fatoora_Address_new_result fatoora_Address_new(diplomat::capi::DiplomatStringView country_code, diplomat::capi::DiplomatStringView city, diplomat::capi::DiplomatStringView street, diplomat::capi::DiplomatStringView building_number, diplomat::capi::DiplomatStringView postal_code, diplomat::capi::OptionStringView additional_street, diplomat::capi::OptionStringView additional_number, diplomat::capi::OptionStringView district);

    typedef struct fatoora_Address_city_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Address_city_result;
    fatoora_Address_city_result fatoora_Address_city(const fatoora::capi::Address* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Address_street_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Address_street_result;
    fatoora_Address_street_result fatoora_Address_street(const fatoora::capi::Address* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Address_building_number_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Address_building_number_result;
    fatoora_Address_building_number_result fatoora_Address_building_number(const fatoora::capi::Address* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Address_postal_code_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Address_postal_code_result;
    fatoora_Address_postal_code_result fatoora_Address_postal_code(const fatoora::capi::Address* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Address_country_code_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Address_country_code_result;
    fatoora_Address_country_code_result fatoora_Address_country_code(const fatoora::capi::Address* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Address_additional_street_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Address_additional_street_result;
    fatoora_Address_additional_street_result fatoora_Address_additional_street(const fatoora::capi::Address* self);

    typedef struct fatoora_Address_additional_number_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Address_additional_number_result;
    fatoora_Address_additional_number_result fatoora_Address_additional_number(const fatoora::capi::Address* self);

    typedef struct fatoora_Address_district_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Address_district_result;
    fatoora_Address_district_result fatoora_Address_district(const fatoora::capi::Address* self);

    void fatoora_Address_destroy(Address* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::Address>, std::unique_ptr<fatoora::BindingError>> fatoora::Address::new_(std::string_view country_code, std::string_view city, std::string_view street, std::string_view building_number, std::string_view postal_code, std::optional<std::string_view> additional_street, std::optional<std::string_view> additional_number, std::optional<std::string_view> district) {
    auto result = fatoora::capi::fatoora_Address_new({country_code.data(), country_code.size()},
        {city.data(), city.size()},
        {street.data(), street.size()},
        {building_number.data(), building_number.size()},
        {postal_code.data(), postal_code.size()},
        additional_street.has_value() ? (diplomat::capi::OptionStringView{ { {additional_street.value().data(), additional_street.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }),
        additional_number.has_value() ? (diplomat::capi::OptionStringView{ { {additional_number.value().data(), additional_number.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }),
        district.has_value() ? (diplomat::capi::OptionStringView{ { {district.value().data(), district.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }));
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Address>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Address>>(std::unique_ptr<fatoora::Address>(fatoora::Address::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Address>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Address::city() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Address_city(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Address::city_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Address_city(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Address::street() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Address_street(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Address::street_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Address_street(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Address::building_number() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Address_building_number(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Address::building_number_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Address_building_number(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Address::postal_code() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Address_postal_code(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Address::postal_code_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Address_postal_code(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Address::country_code() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Address_country_code(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Address::country_code_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Address_country_code(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::Address::additional_street() const {
    auto result = fatoora::capi::fatoora_Address_additional_street(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::Address::additional_number() const {
    auto result = fatoora::capi::fatoora_Address_additional_number(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::Address::district() const {
    auto result = fatoora::capi::fatoora_Address_district(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::Address* fatoora::Address::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::Address*>(this);
}

inline fatoora::capi::Address* fatoora::Address::AsFFI() {
    return reinterpret_cast<fatoora::capi::Address*>(this);
}

inline const fatoora::Address* fatoora::Address::FromFFI(const fatoora::capi::Address* ptr) {
    return reinterpret_cast<const fatoora::Address*>(ptr);
}

inline fatoora::Address* fatoora::Address::FromFFI(fatoora::capi::Address* ptr) {
    return reinterpret_cast<fatoora::Address*>(ptr);
}

inline void fatoora::Address::operator delete(void* ptr) {
    fatoora::capi::fatoora_Address_destroy(reinterpret_cast<fatoora::capi::Address*>(ptr));
}


#endif // fatoora_Address_HPP
