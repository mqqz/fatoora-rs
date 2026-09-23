#ifndef fatoora_Xml_HPP
#define fatoora_Xml_HPP

#include "Xml.d.hpp"

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
#include "Config.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_Xml_validate_result {union {bool ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Xml_validate_result;
    fatoora_Xml_validate_result fatoora_Xml_validate(const fatoora::capi::Config* config, diplomat::capi::DiplomatStringView xml);

    typedef struct fatoora_Xml_hash_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Xml_hash_result;
    fatoora_Xml_hash_result fatoora_Xml_hash(diplomat::capi::DiplomatStringView xml, diplomat::capi::DiplomatWrite* write);

    void fatoora_Xml_destroy(Xml* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<bool, std::unique_ptr<fatoora::BindingError>> fatoora::Xml::validate(const fatoora::Config& config, std::string_view xml) {
    auto result = fatoora::capi::fatoora_Xml_validate(config.AsFFI(),
        {xml.data(), xml.size()});
    return result.is_ok ? diplomat::result<bool, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<bool>(result.ok)) : diplomat::result<bool, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Xml::hash(std::string_view xml) {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Xml_hash({xml.data(), xml.size()},
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Xml::hash_write(std::string_view xml, W& writeable) {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Xml_hash({xml.data(), xml.size()},
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::Xml* fatoora::Xml::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::Xml*>(this);
}

inline fatoora::capi::Xml* fatoora::Xml::AsFFI() {
    return reinterpret_cast<fatoora::capi::Xml*>(this);
}

inline const fatoora::Xml* fatoora::Xml::FromFFI(const fatoora::capi::Xml* ptr) {
    return reinterpret_cast<const fatoora::Xml*>(ptr);
}

inline fatoora::Xml* fatoora::Xml::FromFFI(fatoora::capi::Xml* ptr) {
    return reinterpret_cast<fatoora::Xml*>(ptr);
}

inline void fatoora::Xml::operator delete(void* ptr) {
    fatoora::capi::fatoora_Xml_destroy(reinterpret_cast<fatoora::capi::Xml*>(ptr));
}


#endif // fatoora_Xml_HPP
