#include "SignatureVerifier.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <Softpub.h>
#include <Wincrypt.h>
#include <Wintrust.h>

namespace kernelscope::analysis {
namespace {

class TrustState final {
public:
    TrustState(GUID& action, WINTRUST_DATA& data) noexcept
        : action_(action), data_(data) {}
    ~TrustState() noexcept
    {
        data_.dwStateAction = WTD_STATEACTION_CLOSE;
        (void)WinVerifyTrust(nullptr, &action_, &data_);
    }
    TrustState(const TrustState&) = delete;
    TrustState& operator=(const TrustState&) = delete;

private:
    GUID& action_;
    WINTRUST_DATA& data_;
};

}  // namespace

const char* SignatureStatusName(const SignatureStatus status) noexcept
{
    switch (status) {
    case SignatureStatus::Valid: return "valid";
    case SignatureStatus::Invalid: return "invalid";
    case SignatureStatus::Unsigned: return "unsigned";
    case SignatureStatus::VerificationError: return "verification_error";
    case SignatureStatus::RevocationStatusUnknown: return "revocation_status_unknown";
    }
    return "verification_error";
}

SignatureResult VerifyAuthenticode(const std::filesystem::path& path)
{
    SignatureResult result;
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = static_cast<DWORD>(sizeof(fileInfo));
    const std::wstring nativePath = path.wstring();
    fileInfo.pcwszFilePath = nativePath.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = static_cast<DWORD>(sizeof(trustData));
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    [[maybe_unused]] TrustState trustState(action, trustData);
    const LONG status = WinVerifyTrust(nullptr, &action, &trustData);
    result.trustStatus = status;

    if (status == ERROR_SUCCESS) {
        result.status = SignatureStatus::Valid;
        result.detail = "The Authenticode signature and cached trust chain are valid.";
    } else if (status == TRUST_E_NOSIGNATURE ||
        status == TRUST_E_SUBJECT_FORM_UNKNOWN || status == TRUST_E_PROVIDER_UNKNOWN) {
        result.status = SignatureStatus::Unsigned;
        result.detail = "No supported Authenticode signature was found.";
    } else if (status == CRYPT_E_REVOCATION_OFFLINE || status == CERT_E_REVOCATION_FAILURE) {
        result.status = SignatureStatus::RevocationStatusUnknown;
        result.detail = "Signature validation could not establish revocation status from cached data.";
    } else if (status == TRUST_E_BAD_DIGEST || status == TRUST_E_EXPLICIT_DISTRUST ||
        status == CERT_E_REVOKED || status == CERT_E_EXPIRED ||
        status == CERT_E_UNTRUSTEDROOT || status == CERT_E_CHAINING) {
        result.status = SignatureStatus::Invalid;
        result.detail = "The Authenticode signature or trust chain is invalid.";
    } else {
        result.status = SignatureStatus::VerificationError;
        result.detail = "WinVerifyTrust returned an unclassified verification error.";
    }

    return result;
}

}  // namespace kernelscope::analysis
