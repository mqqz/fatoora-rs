#ifndef _NATIVE_Xml_HPP
#define _NATIVE_Xml_HPP

#include "Xml.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "BindingError.hpp"
#include "Config.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_Xml_validate_zatca_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Xml_validate_zatca_result;
    fatoora_Xml_validate_zatca_result fatoora_Xml_validate_zatca(const _native::capi::Config* config, _native::diplomat::capi::DiplomatStringView xml, _native::diplomat::capi::OptionStringView options_json, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Xml_validate_result {union {bool ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Xml_validate_result;
    fatoora_Xml_validate_result fatoora_Xml_validate(const _native::capi::Config* config, _native::diplomat::capi::DiplomatStringView xml);

    typedef struct fatoora_Xml_hash_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Xml_hash_result;
    fatoora_Xml_hash_result fatoora_Xml_hash(_native::diplomat::capi::DiplomatStringView xml, _native::diplomat::capi::DiplomatWrite* write);

    void fatoora_Xml_destroy(Xml* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Xml::validate_zatca(const _native::Config& config, std::string_view xml, std::optional<std::string_view> options_json) {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Xml_validate_zatca(config.AsFFI(),
        {xml.data(), xml.size()},
        options_json.has_value() ? (_native::diplomat::capi::OptionStringView{ { {options_json.value().data(), options_json.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Xml::validate_zatca_write(const _native::Config& config, std::string_view xml, std::optional<std::string_view> options_json, W& writeable) {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Xml_validate_zatca(config.AsFFI(),
        {xml.data(), xml.size()},
        options_json.has_value() ? (_native::diplomat::capi::OptionStringView{ { {options_json.value().data(), options_json.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<bool, std::unique_ptr<_native::BindingError>> _native::Xml::validate(const _native::Config& config, std::string_view xml) {
    auto result = _native::capi::fatoora_Xml_validate(config.AsFFI(),
        {xml.data(), xml.size()});
    return result.is_ok ? _native::diplomat::result<bool, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<bool>(result.ok)) : _native::diplomat::result<bool, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Xml::hash(std::string_view xml) {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Xml_hash({xml.data(), xml.size()},
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Xml::hash_write(std::string_view xml, W& writeable) {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Xml_hash({xml.data(), xml.size()},
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::Xml* _native::Xml::AsFFI() const {
    return reinterpret_cast<const _native::capi::Xml*>(this);
}

inline _native::capi::Xml* _native::Xml::AsFFI() {
    return reinterpret_cast<_native::capi::Xml*>(this);
}

inline const _native::Xml* _native::Xml::FromFFI(const _native::capi::Xml* ptr) {
    return reinterpret_cast<const _native::Xml*>(ptr);
}

inline _native::Xml* _native::Xml::FromFFI(_native::capi::Xml* ptr) {
    return reinterpret_cast<_native::Xml*>(ptr);
}

inline void _native::Xml::operator delete(void* ptr) {
    _native::capi::fatoora_Xml_destroy(reinterpret_cast<_native::capi::Xml*>(ptr));
}


#endif // _NATIVE_Xml_HPP
