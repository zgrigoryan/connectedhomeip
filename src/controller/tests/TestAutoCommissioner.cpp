/*
 *
 *    Copyright (c) 2020-2025 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <pw_unit_test/framework.h>

#include <controller/AutoCommissioner.h>
#include <controller/CommissioningDelegate.h>
#include <controller/tests/AutoCommissionerTestAccess.h>
#include <lib/core/StringBuilderAdapters.h>
#include <lib/support/CHIPMemString.h>

#include <cstring>
#include <memory>

using namespace chip;
using namespace chip::Dnssd;
using namespace chip::Controller;
using namespace chip::Test;

namespace {

constexpr uint64_t epochJanFirst2000 = 946695600; // Monday, January 1, 2000 12:00 AM
constexpr uint64_t epochJanFirst2001 = 978318000; // Monday, January 1, 2001 12:00 AM

class AutoCommissionerTest : public ::testing::Test
{
protected:
    AutoCommissioner mCommissioner{};
    CommissioningParameters mParams{};
};

TEST_F(AutoCommissionerTest, DetectsThreadOperationalDatasetExceedsBuffer)
{
    auto up = std::make_unique<uint8_t[]>(CommissioningParameters::kMaxThreadDatasetLen + 1);

    ASSERT_TRUE(up);

    std::memset(up.get(), 0x00, CommissioningParameters::kMaxThreadDatasetLen + 1);

    mParams.SetThreadOperationalDataset(ByteSpan{ up.get(), CommissioningParameters::kMaxThreadDatasetLen + 1 });

    auto r = mCommissioner.SetCommissioningParameters(mParams);

    ASSERT_EQ(r, CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, DetectsWifiCredentialsExceedBuffer)
{
    auto ssid_buffer_up = std::make_unique<uint8_t[]>(CommissioningParameters::kMaxSsidLen + 1);

    auto creds_buffer_up = std::make_unique<uint8_t[]>(CommissioningParameters::kMaxCredentialsLen + 1);

    mParams.SetWiFiCredentials(WiFiCredentials{
        ByteSpan{ ssid_buffer_up.get(), CommissioningParameters::kMaxSsidLen + 1 },
        ByteSpan{ creds_buffer_up.get(), CommissioningParameters::kMaxCredentialsLen + 1 },
    });

    auto r = mCommissioner.SetCommissioningParameters(mParams);

    ASSERT_EQ(r, CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, DetectsCountryCodeExceedsBuffer)
{
    mParams.SetCountryCode("012"_span);

    auto r = mCommissioner.SetCommissioningParameters(mParams);

    ASSERT_EQ(r, CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, DetectsAttestationNonceExceedsBuffer)
{
    auto attestation_nonce_buffer_up = std::make_unique<uint8_t[]>(kAttestationNonceLength + 1);

    mParams.SetAttestationNonce(ByteSpan{ attestation_nonce_buffer_up.get(), kAttestationNonceLength + 1 });

    auto r = mCommissioner.SetCommissioningParameters(mParams);

    ASSERT_EQ(r, CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, DetectsCSRNonceExceedsBuffer)
{
    auto csr_nonce_buffer_up = std::make_unique<uint8_t[]>(kCSRNonceLength + 1);

    mParams.SetCSRNonce(ByteSpan{ csr_nonce_buffer_up.get(), kCSRNonceLength + 1 });

    auto r = mCommissioner.SetCommissioningParameters(mParams);

    ASSERT_EQ(r, CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, FeaturesPassedDSTOffsetsValue)
{
    app::Clusters::TimeSynchronization::Structs::DSTOffsetStruct::Type sDSTBuf;

    sDSTBuf.offset        = int32_t{ 10 };
    sDSTBuf.validStarting = epochJanFirst2000;
    sDSTBuf.validUntil    = epochJanFirst2001;
    app::DataModel::List<app::Clusters::TimeSynchronization::Structs::DSTOffsetStruct::Type> list(&sDSTBuf, 1);

    mParams.SetDSTOffsets(list);

    auto r = mCommissioner.SetCommissioningParameters(mParams);

    auto commissioning_params = mCommissioner.GetCommissioningParameters();

    ASSERT_EQ(r, CHIP_NO_ERROR);
    ASSERT_TRUE(commissioning_params.GetDSTOffsets().HasValue());
    ASSERT_EQ(commissioning_params.GetDSTOffsets().Value().size(), size_t{ 1 });
    ASSERT_EQ(commissioning_params.GetDSTOffsets().Value()[0].offset, 10);
    ASSERT_EQ(commissioning_params.GetDSTOffsets().Value()[0].validStarting, epochJanFirst2000);
    ASSERT_EQ(commissioning_params.GetDSTOffsets().Value()[0].validUntil, epochJanFirst2001);
}

TEST_F(AutoCommissionerTest, FeaturesPassedTimeZoneValue)
{
    app::Clusters::TimeSynchronization::Structs::TimeZoneStruct::Type sTimeZoneBuf;

    constexpr CharSpan countryName = "ARG"_span;

    sTimeZoneBuf.offset  = int32_t{ 10 };
    sTimeZoneBuf.validAt = epochJanFirst2000; // Monday, January 1, 2000 12:00 AM
    sTimeZoneBuf.name.SetValue(chip::CharSpan{ countryName });

    app::DataModel::List<app::Clusters::TimeSynchronization::Structs::TimeZoneStruct::Type> list(&sTimeZoneBuf, 1);
    mParams.SetTimeZone(list);

    auto r = mCommissioner.SetCommissioningParameters(mParams);

    auto commissioning_params = mCommissioner.GetCommissioningParameters();

    ASSERT_EQ(r, CHIP_NO_ERROR);
    ASSERT_TRUE(commissioning_params.GetTimeZone().HasValue());
    ASSERT_EQ(commissioning_params.GetTimeZone().Value().size(), size_t{ 1 });
    ASSERT_EQ(commissioning_params.GetTimeZone().Value()[0].offset, 10);
    ASSERT_EQ(commissioning_params.GetTimeZone().Value()[0].validAt, epochJanFirst2000);
    ASSERT_TRUE(commissioning_params.GetTimeZone().Value()[0].name.HasValue());
    ASSERT_TRUE(commissioning_params.GetTimeZone().Value()[0].name.Value().data_equal("ARG"_span));
}

TEST_F(AutoCommissionerTest, FeaturesPassedNTPValue)
{
    constexpr CharSpan defaultNTPBuffer = "default"_span;

    mParams.SetDefaultNTP(chip::app::DataModel::MakeNullable(defaultNTPBuffer));

    auto r = mCommissioner.SetCommissioningParameters(mParams);

    auto commissioning_params = mCommissioner.GetCommissioningParameters();

    ASSERT_EQ(r, CHIP_NO_ERROR);
    ASSERT_TRUE(commissioning_params.GetDefaultNTP().HasValue());
    ASSERT_TRUE(commissioning_params.GetDefaultNTP().Value().Value().data_equal("default"_span));
}

TEST_F(AutoCommissionerTest, FeaturesPassedICDRegistrationKey)
{
    mParams.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);

    uint8_t symmetric_key_buffer[Crypto::kAES_CCM128_Key_Length];

    std::memset(symmetric_key_buffer, 0x00, Crypto::kAES_CCM128_Key_Length);

    mParams.SetICDSymmetricKey(ByteSpan{ symmetric_key_buffer, Crypto::kAES_CCM128_Key_Length });
    mParams.SetICDCheckInNodeId(NodeId{ 10000 });
    mParams.SetICDMonitoredSubject(uint64_t{ 9999 });
    mParams.SetICDClientType(app::Clusters::IcdManagement::ClientTypeEnum::kPermanent);

    auto r = mCommissioner.SetCommissioningParameters(mParams);

    auto commissioning_params = mCommissioner.GetCommissioningParameters();

    ASSERT_EQ(r, CHIP_NO_ERROR);
    ASSERT_TRUE(commissioning_params.GetICDSymmetricKey().HasValue());
    ASSERT_EQ(commissioning_params.GetICDRegistrationStrategy(), ICDRegistrationStrategy::kBeforeComplete);
    ASSERT_TRUE(commissioning_params.GetICDSymmetricKey().HasValue());
    ASSERT_EQ(commissioning_params.GetICDSymmetricKey().Value().size(), Crypto::kAES_CCM128_Key_Length);
    ASSERT_TRUE(commissioning_params.GetICDSymmetricKey().Value().data_equal(ByteSpan{ symmetric_key_buffer }));
    ASSERT_TRUE(commissioning_params.GetICDCheckInNodeId().HasValue());
    ASSERT_EQ(commissioning_params.GetICDCheckInNodeId().Value(), NodeId{ 10000 });
    ASSERT_TRUE(commissioning_params.GetICDMonitoredSubject().HasValue());
    ASSERT_EQ(commissioning_params.GetICDMonitoredSubject().Value(), uint64_t{ 9999 });
    ASSERT_TRUE(commissioning_params.GetICDClientType().HasValue());
    ASSERT_EQ(commissioning_params.GetICDClientType().Value(), app::Clusters::IcdManagement::ClientTypeEnum::kPermanent);
}

TEST_F(AutoCommissionerTest, FeaturesPassedExtraReadPaths)
{
    chip::app::AttributePathParams attributes[1];

    constexpr uint32_t endpointId  = 1;
    constexpr uint32_t clusterId   = 2;
    constexpr uint32_t attributeId = 3;

    attributes[0] = chip::app::AttributePathParams{ endpointId, clusterId, attributeId };

    mParams.SetExtraReadPaths(Span<const app::AttributePathParams>{ attributes, 1 });

    auto pathParams = mParams.GetExtraReadPaths();

    ASSERT_EQ(pathParams.size(), size_t{ 1 });
    ASSERT_EQ(pathParams[0].mEndpointId, endpointId);
    ASSERT_EQ(pathParams[0].mClusterId, clusterId);
    ASSERT_EQ(pathParams[0].mAttributeId, attributeId);
}

// kStages are enumerators from enum type name CommissioningStage
struct StageTransition
{
    CommissioningStage currentStage;
    CommissioningStage nextStage;
};

const std::vector<StageTransition> kStagePairs = {
    // Only linear transitions are tested here;
    // Branching cases (like kReadCommissioningInfo, kConfigureTCAcknowledgments, etc.) are tested separately
    { kSecurePairing, kReadCommissioningInfo },
    { kArmFailsafe, kConfigRegulatory },
    { kConfigRegulatory, kConfigureTCAcknowledgments },
    { kConfigureDefaultNTP, kSendPAICertificateRequest },
    { kSendPAICertificateRequest, kSendDACCertificateRequest },
    { kSendDACCertificateRequest, kSendAttestationRequest },
    { kSendAttestationRequest, kAttestationVerification },
    { kAttestationVerification, kAttestationRevocationCheck },
    { kJCMTrustVerification, kSendOpCertSigningRequest },
    { kSendOpCertSigningRequest, kValidateCSR },
    { kValidateCSR, kGenerateNOCChain },
    { kGenerateNOCChain, kSendTrustedRootCert },
    { kSendTrustedRootCert, kSendNOC },
    { kICDGetRegistrationInfo, kICDRegistration },
    { kScanNetworks, kNeedsNetworkCreds },
    { kWiFiNetworkSetup, kFailsafeBeforeWiFiEnable },
    { kThreadNetworkSetup, kFailsafeBeforeThreadEnable },
    { kFailsafeBeforeWiFiEnable, kWiFiNetworkEnable },
    { kFailsafeBeforeThreadEnable, kThreadNetworkEnable },
    { kEvictPreviousCaseSessions, kFindOperationalForStayActive },
    { kFindOperationalForStayActive, kICDSendStayActive },
    { kICDSendStayActive, kFindOperationalForCommissioningComplete },
    { kFindOperationalForCommissioningComplete, kSendComplete },
    { kSendComplete, kCleanup },
    { kCleanup, kError },
    { kError, kError },
    { static_cast<CommissioningStage>(250), kError }, // triggers default case in switch statement

};

// Test each case pair for the next commissioning stage
TEST_F(AutoCommissionerTest, NextCommissioningStage)
{
    // Accessor class used due to private/protected members.
    AutoCommissionerTestAccess privateConfigCommissioner(&mCommissioner);
    CHIP_ERROR err = CHIP_NO_ERROR;

    for (const auto & stagePair : kStagePairs)
    {
        CommissioningStage nextStage =
            privateConfigCommissioner.AccessGetNextCommissioningStageInternal(stagePair.currentStage, err);
        EXPECT_EQ(nextStage, stagePair.nextStage);
    }
}

// if commissioning is manually stopped, the next stage should be kCleanup
TEST_F(AutoCommissionerTest, NextStageStopCommissioning)
{
    AutoCommissionerTestAccess privateConfigCommissioner(&mCommissioner);
    mCommissioner.StopCommissioning();

    CHIP_ERROR err           = CHIP_ERROR_INTERNAL;
    CommissioningStage stage = privateConfigCommissioner.AccessGetNextCommissioningStageInternal(kSecurePairing, err);
    EXPECT_EQ(stage, kCleanup);
}

// if commissioning failed, then the next stage should be cleanup
TEST_F(AutoCommissionerTest, NextCommissioningStageAfterError)
{
    AutoCommissionerTestAccess privateConfigCommissioner(&mCommissioner);

    CHIP_ERROR err           = CHIP_ERROR_INTERNAL;
    CommissioningStage stage = privateConfigCommissioner.AccessGetNextCommissioningStageInternal(kSecurePairing, err);
    EXPECT_EQ(stage, kCleanup);
}

// Verifies that the commissioner proceeds to ConfigureTCAcknowledgments under the correct conditions.
TEST_F(AutoCommissionerTest, NextStageReadCommissioningInfo)
{
    AutoCommissionerTestAccess privateConfigCommissioner(&mCommissioner);
    CHIP_ERROR err = CHIP_NO_ERROR;

    privateConfigCommissioner.SetBreadcrumb(0);
    CommissioningStage nextStage = privateConfigCommissioner.AccessGetNextCommissioningStageInternal(kReadCommissioningInfo, err);

    EXPECT_EQ(nextStage, kArmFailsafe);

    // if breadcrumb > 0, the stage changes to kSendNOC; subsequent stages progress accordingly.
    privateConfigCommissioner.SetBreadcrumb(1);

    CommissioningStage nextStageReadCommissioningInfo =
        privateConfigCommissioner.AccessGetNextCommissioningStageInternal(kReadCommissioningInfo, err);
    CommissioningStage nextStageSendNOC = privateConfigCommissioner.AccessGetNextCommissioningStageInternal(kSendNOC, err);

    EXPECT_EQ(nextStageReadCommissioningInfo, nextStageSendNOC);
}

// Ensures TCAcknowledgment stage is triggered only under expected commissioning conditions.
TEST_F(AutoCommissionerTest, NextStageConfigureTCAcknowledgments)
{
    AutoCommissionerTestAccess privateConfigCommissioner(&mCommissioner);
    CHIP_ERROR err = CHIP_NO_ERROR;

    privateConfigCommissioner.SetUTCRequirements(true);

    CommissioningStage nextStage =
        privateConfigCommissioner.AccessGetNextCommissioningStageInternal(kConfigureTCAcknowledgments, err);

    EXPECT_EQ(nextStage, kConfigureUTCTime);

    privateConfigCommissioner.SetUTCRequirements(false);

    nextStage = privateConfigCommissioner.AccessGetNextCommissioningStageInternal(kConfigureTCAcknowledgments, err);

    EXPECT_EQ(nextStage, kSendPAICertificateRequest);
}
TEST_F(AutoCommissionerTest, IcdRegistrationFailsOnMissingPiecesOrBadKeySize)
{
    // Always use a non-Ignore strategy so the ICD block is considered when key is present.
    mParams.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);

    // 1) Wrong key length -> INVALID_ARGUMENT
    {
        CommissioningParameters p{};
        p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);
        uint8_t short_key[Crypto::kAES_CCM128_Key_Length - 1] = {};
        p.SetICDSymmetricKey(ByteSpan{ short_key, sizeof(short_key) });
        ASSERT_EQ(mCommissioner.SetCommissioningParameters(p), CHIP_ERROR_INVALID_ARGUMENT);
    }

    // 2) Strategy set but key missing -> NO_ERROR (ICD validation skipped; nothing applied)
    {
        CommissioningParameters p{};
        p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);
        ASSERT_EQ(mCommissioner.SetCommissioningParameters(p), CHIP_NO_ERROR);
        const auto & out = mCommissioner.GetCommissioningParameters();
        ASSERT_FALSE(out.GetICDSymmetricKey().HasValue());
        ASSERT_FALSE(out.GetICDCheckInNodeId().HasValue());
        ASSERT_FALSE(out.GetICDMonitoredSubject().HasValue());
        ASSERT_FALSE(out.GetICDClientType().HasValue());
    }

    // 3) Key present but missing check-in node id -> INVALID_ARGUMENT
    {
        CommissioningParameters p{};
        p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);
        uint8_t ok_key[Crypto::kAES_CCM128_Key_Length] = {};
        p.SetICDSymmetricKey(ByteSpan{ ok_key, sizeof(ok_key) });
        ASSERT_EQ(mCommissioner.SetCommissioningParameters(p), CHIP_ERROR_INVALID_ARGUMENT);
    }

    // 4) Add check-in node id; still missing monitored subject -> INVALID_ARGUMENT
    {
        CommissioningParameters p{};
        p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);
        uint8_t ok_key[Crypto::kAES_CCM128_Key_Length] = {};
        p.SetICDSymmetricKey(ByteSpan{ ok_key, sizeof(ok_key) });
        p.SetICDCheckInNodeId(NodeId{ 42 });
        ASSERT_EQ(mCommissioner.SetCommissioningParameters(p), CHIP_ERROR_INVALID_ARGUMENT);
    }

    // 5) Add monitored subject; still missing client type -> INVALID_ARGUMENT
    {
        CommissioningParameters p{};
        p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);
        uint8_t ok_key[Crypto::kAES_CCM128_Key_Length] = {};
        p.SetICDSymmetricKey(ByteSpan{ ok_key, sizeof(ok_key) });
        p.SetICDCheckInNodeId(NodeId{ 42 });
        p.SetICDMonitoredSubject(uint64_t{ 7 });
        ASSERT_EQ(mCommissioner.SetCommissioningParameters(p), CHIP_ERROR_INVALID_ARGUMENT);
    }
}

TEST_F(AutoCommissionerTest, SetCommissioningParametersIsNoOpWhenPassingOwnParams)
{
    // First set some value so we know params are initialized
    mParams.SetCountryCode("US"_span);
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(mParams), CHIP_NO_ERROR);

    // Now pass the *same* reference back (address equality check)
    const CommissioningParameters & same = mCommissioner.GetCommissioningParameters();
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(same), CHIP_NO_ERROR);

    // Stays the same and valid
    auto again = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(again.GetCountryCode().HasValue());
    ASSERT_TRUE(again.GetCountryCode().Value().data_equal("US"_span));
}

TEST_F(AutoCommissionerTest, CopiesValidThreadDataset)
{
    uint8_t ds[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    mParams.SetThreadOperationalDataset(ByteSpan{ ds, sizeof(ds) });
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(mParams), CHIP_NO_ERROR);

    auto p = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p.GetThreadOperationalDataset().HasValue());
    ASSERT_EQ(p.GetThreadOperationalDataset().Value().size(), sizeof(ds));
    ASSERT_TRUE(p.GetThreadOperationalDataset().Value().data_equal(ByteSpan{ ds, sizeof(ds) }));
}

TEST_F(AutoCommissionerTest, CopiesValidWifiCredentials)
{
    const uint8_t ssid_bytes[] = { 'A', 'P' };
    const uint8_t pass_bytes[] = { '1', '2', '3', '4' };
    mParams.SetWiFiCredentials(WiFiCredentials{ ByteSpan{ ssid_bytes }, ByteSpan{ pass_bytes } });

    ASSERT_EQ(mCommissioner.SetCommissioningParameters(mParams), CHIP_NO_ERROR);
    auto p = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p.GetWiFiCredentials().HasValue());
    auto creds = p.GetWiFiCredentials().Value();
    ASSERT_TRUE(creds.ssid.data_equal(ByteSpan{ ssid_bytes }));
    ASSERT_TRUE(creds.credentials.data_equal(ByteSpan{ pass_bytes }));
}

TEST_F(AutoCommissionerTest, AcceptsTwoCharCountryCode)
{
    mParams.SetCountryCode("AM"_span);
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(mParams), CHIP_NO_ERROR);

    auto p = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p.GetCountryCode().HasValue());
    ASSERT_TRUE(p.GetCountryCode().Value().data_equal("AM"_span));
}

TEST_F(AutoCommissionerTest, UsesProvidedNoncesOrGeneratesRandomWhenMissing)
{
    // Provided attestation/CSR nonces of exact size are accepted
    std::unique_ptr<uint8_t[]> att(new uint8_t[kAttestationNonceLength]);
    std::unique_ptr<uint8_t[]> csr(new uint8_t[kCSRNonceLength]);
    std::memset(att.get(), 0xAB, kAttestationNonceLength);
    std::memset(csr.get(), 0xCD, kCSRNonceLength);
    mParams.SetAttestationNonce(ByteSpan{ att.get(), kAttestationNonceLength });
    mParams.SetCSRNonce(ByteSpan{ csr.get(), kCSRNonceLength });

    ASSERT_EQ(mCommissioner.SetCommissioningParameters(mParams), CHIP_NO_ERROR);
    auto p1 = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p1.GetAttestationNonce().HasValue());
    ASSERT_EQ(p1.GetAttestationNonce().Value().size(), kAttestationNonceLength);
    ASSERT_TRUE(p1.GetAttestationNonce().Value().data_equal(ByteSpan{ att.get(), kAttestationNonceLength }));

    ASSERT_TRUE(p1.GetCSRNonce().HasValue());
    ASSERT_EQ(p1.GetCSRNonce().Value().size(), kCSRNonceLength);
    ASSERT_TRUE(p1.GetCSRNonce().Value().data_equal(ByteSpan{ csr.get(), kCSRNonceLength }));

    // Clear nonces: AutoCommissioner should generate random ones and set them back
    CommissioningParameters empty;
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(empty), CHIP_NO_ERROR);
    auto p2 = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p2.GetAttestationNonce().HasValue());
    ASSERT_EQ(p2.GetAttestationNonce().Value().size(), kAttestationNonceLength);
    ASSERT_TRUE(p2.GetCSRNonce().HasValue());
    ASSERT_EQ(p2.GetCSRNonce().Value().size(), kCSRNonceLength);
}

TEST_F(AutoCommissionerTest, TimeZoneNameTooLongIsCleared)
{
    app::Clusters::TimeSynchronization::Structs::TimeZoneStruct::Type tz{};
    tz.offset  = 0;
    tz.validAt = epochJanFirst2000;

    // Make a clearly-too-long name (well beyond any reasonable internal cap).
    std::vector<char> long_name(4096, 'X');
    tz.name.SetValue(CharSpan{ long_name.data(), long_name.size() });

    app::DataModel::List<app::Clusters::TimeSynchronization::Structs::TimeZoneStruct::Type> list(&tz, 1);
    mParams.SetTimeZone(list);

    ASSERT_EQ(mCommissioner.SetCommissioningParameters(mParams), CHIP_NO_ERROR);

    auto p = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p.GetTimeZone().HasValue());
    ASSERT_EQ(p.GetTimeZone().Value().size(), size_t{ 1 });
    // Name must be cleared when longer than the internal kMaxTimeZoneNameLen.
    ASSERT_FALSE(p.GetTimeZone().Value()[0].name.HasValue());
}

TEST_F(AutoCommissionerTest, OversizedDefaultNtpIsIgnoredAndNotSet)
{
    // Make an NTP string far beyond the internal limit so it will be ignored.
    std::vector<char> long_ntp(4096, 'n');
    mParams.SetDefaultNTP(chip::app::DataModel::MakeNullable(CharSpan{ long_ntp.data(), long_ntp.size() }));

    ASSERT_EQ(mCommissioner.SetCommissioningParameters(mParams), CHIP_NO_ERROR);

    auto p = mCommissioner.GetCommissioningParameters();
    // Too-long NTP should NOT be set (code only sets when size <= kMaxDefaultNtpSize).
    ASSERT_FALSE(p.GetDefaultNTP().HasValue());
}

} // namespace
