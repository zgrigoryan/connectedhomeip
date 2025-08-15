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

#include <array>
#include <cstring>
#include <memory>
#include <vector>

using namespace chip;
using namespace chip::Dnssd;
using namespace chip::Controller;
using namespace chip::Test;

namespace {

// ---- Small utilities to cut repetition in tests ----

inline CHIP_ERROR SetAndReturn(AutoCommissioner & c, const CommissioningParameters & p)
{
    return c.SetCommissioningParameters(p);
}

inline void ExpectSetOk(AutoCommissioner & c, const CommissioningParameters & p)
{
    ASSERT_EQ(SetAndReturn(c, p), CHIP_NO_ERROR);
}

inline void ExpectSetErr(AutoCommissioner & c, const CommissioningParameters & p, CHIP_ERROR err)
{
    ASSERT_EQ(SetAndReturn(c, p), err);
}

inline std::vector<uint8_t> Bytes(size_t n, uint8_t v = 0)
{
    return std::vector<uint8_t>(n, v);
}

inline chip::app::AttributePathParams MakeAttrPath(chip::EndpointId ep, chip::ClusterId cl, chip::AttributeId attr)
{
    return chip::app::AttributePathParams(ep, cl, attr);
}

using DST = app::Clusters::TimeSynchronization::Structs::DSTOffsetStruct::Type;
using TZ  = app::Clusters::TimeSynchronization::Structs::TimeZoneStruct::Type;

constexpr uint64_t epochJanFirst2000 = 946695600; // Monday, January 1, 2000 12:00 AM
constexpr uint64_t epochJanFirst2001 = 978318000; // Monday, January 1, 2001 12:00 AM

static chip::app::AttributePathParams MkPath(chip::EndpointId ep)
{
    chip::app::AttributePathParams p{}; // zero-init
    p.mEndpointId  = ep;
    p.mClusterId   = chip::ClusterId(0x00000006);   // OnOff
    p.mAttributeId = chip::AttributeId(0x00000000); // OnOff::OnOff
    p.mListIndex   = chip::kInvalidListIndex;       // IMPORTANT
    return p;
}

class AutoCommissionerTest : public ::testing::Test
{
protected:
    AutoCommissioner mCommissioner{};
    CommissioningParameters mParams{};
    AutoCommissionerTestAccess mAcc{ &mCommissioner };
};

TEST_F(AutoCommissionerTest, DetectsThreadOperationalDatasetExceedsBuffer)
{
    auto buf = Bytes(CommissioningParameters::kMaxThreadDatasetLen + 1, 0x00);
    mParams.SetThreadOperationalDataset(ByteSpan{ buf.data(), buf.size() });
    ExpectSetErr(mCommissioner, mParams, CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, DetectsWifiCredentialsExceedBuffer)
{
    auto ssid  = Bytes(CommissioningParameters::kMaxSsidLen + 1, 0x31);
    auto creds = Bytes(CommissioningParameters::kMaxCredentialsLen + 1, 0x32);

    mParams.SetWiFiCredentials(WiFiCredentials{ ByteSpan{ ssid.data(), ssid.size() }, ByteSpan{ creds.data(), creds.size() } });

    ExpectSetErr(mCommissioner, mParams, CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, DetectsCountryCodeExceedsBuffer)
{
    mParams.SetCountryCode("012"_span);
    ExpectSetErr(mCommissioner, mParams, CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, DetectsAttestationNonceExceedsBuffer)
{
    auto bad = Bytes(kAttestationNonceLength + 1, 0xAB);
    mParams.SetAttestationNonce(ByteSpan{ bad.data(), bad.size() });
    ExpectSetErr(mCommissioner, mParams, CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, DetectsCSRNonceExceedsBuffer)
{
    auto bad = Bytes(kCSRNonceLength + 1, 0xCD);
    mParams.SetCSRNonce(ByteSpan{ bad.data(), bad.size() });
    ExpectSetErr(mCommissioner, mParams, CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, FeaturesPassedDSTOffsetsValue)
{
    DST sDSTBuf;
    sDSTBuf.offset        = int32_t{ 10 };
    sDSTBuf.validStarting = epochJanFirst2000;
    sDSTBuf.validUntil    = epochJanFirst2001;

    app::DataModel::List<DST> list(&sDSTBuf, 1);
    mParams.SetDSTOffsets(list);

    ExpectSetOk(mCommissioner, mParams);
    auto commissioning_params = mCommissioner.GetCommissioningParameters();

    ASSERT_TRUE(commissioning_params.GetDSTOffsets().HasValue());
    ASSERT_EQ(commissioning_params.GetDSTOffsets().Value().size(), size_t{ 1 });
    EXPECT_EQ(commissioning_params.GetDSTOffsets().Value()[0].offset, 10);
    EXPECT_EQ(commissioning_params.GetDSTOffsets().Value()[0].validStarting, epochJanFirst2000);
    EXPECT_EQ(commissioning_params.GetDSTOffsets().Value()[0].validUntil, epochJanFirst2001);
}

TEST_F(AutoCommissionerTest, FeaturesPassedTimeZoneValue)
{
    TZ sTimeZoneBuf;

    constexpr CharSpan countryName = "ARG"_span;

    sTimeZoneBuf.offset  = int32_t{ 10 };
    sTimeZoneBuf.validAt = epochJanFirst2000;
    sTimeZoneBuf.name.SetValue(chip::CharSpan{ countryName });

    app::DataModel::List<TZ> list(&sTimeZoneBuf, 1);
    mParams.SetTimeZone(list);

    ExpectSetOk(mCommissioner, mParams);
    auto commissioning_params = mCommissioner.GetCommissioningParameters();

    ASSERT_TRUE(commissioning_params.GetTimeZone().HasValue());
    ASSERT_EQ(commissioning_params.GetTimeZone().Value().size(), size_t{ 1 });
    EXPECT_EQ(commissioning_params.GetTimeZone().Value()[0].offset, 10);
    EXPECT_EQ(commissioning_params.GetTimeZone().Value()[0].validAt, epochJanFirst2000);
    ASSERT_TRUE(commissioning_params.GetTimeZone().Value()[0].name.HasValue());
    EXPECT_TRUE(commissioning_params.GetTimeZone().Value()[0].name.Value().data_equal("ARG"_span));
}

TEST_F(AutoCommissionerTest, FeaturesPassedNTPValue)
{
    constexpr CharSpan defaultNTPBuffer = "default"_span;

    mParams.SetDefaultNTP(chip::app::DataModel::MakeNullable(defaultNTPBuffer));

    ExpectSetOk(mCommissioner, mParams);
    auto commissioning_params = mCommissioner.GetCommissioningParameters();

    ASSERT_TRUE(commissioning_params.GetDefaultNTP().HasValue());
    ASSERT_TRUE(commissioning_params.GetDefaultNTP().Value().Value().data_equal("default"_span));
}

TEST_F(AutoCommissionerTest, FeaturesPassedICDRegistrationKey)
{
    mParams.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);

    uint8_t symmetric_key_buffer[Crypto::kAES_CCM128_Key_Length] = {};
    mParams.SetICDSymmetricKey(ByteSpan{ symmetric_key_buffer, Crypto::kAES_CCM128_Key_Length });
    mParams.SetICDCheckInNodeId(NodeId{ 10000 });
    mParams.SetICDMonitoredSubject(uint64_t{ 9999 });
    mParams.SetICDClientType(app::Clusters::IcdManagement::ClientTypeEnum::kPermanent);

    ExpectSetOk(mCommissioner, mParams);
    auto commissioning_params = mCommissioner.GetCommissioningParameters();

    ASSERT_TRUE(commissioning_params.GetICDSymmetricKey().HasValue());
    EXPECT_EQ(commissioning_params.GetICDRegistrationStrategy(), ICDRegistrationStrategy::kBeforeComplete);
    EXPECT_EQ(commissioning_params.GetICDSymmetricKey().Value().size(), Crypto::kAES_CCM128_Key_Length);
    EXPECT_TRUE(commissioning_params.GetICDSymmetricKey().Value().data_equal(ByteSpan{ symmetric_key_buffer }));
    ASSERT_TRUE(commissioning_params.GetICDCheckInNodeId().HasValue());
    EXPECT_EQ(commissioning_params.GetICDCheckInNodeId().Value(), NodeId{ 10000 });
    ASSERT_TRUE(commissioning_params.GetICDMonitoredSubject().HasValue());
    EXPECT_EQ(commissioning_params.GetICDMonitoredSubject().Value(), uint64_t{ 9999 });
    ASSERT_TRUE(commissioning_params.GetICDClientType().HasValue());
    EXPECT_EQ(commissioning_params.GetICDClientType().Value(), app::Clusters::IcdManagement::ClientTypeEnum::kPermanent);
}

TEST_F(AutoCommissionerTest, FeaturesPassedExtraReadPaths)
{
    constexpr uint32_t endpointId  = 1;
    constexpr uint32_t clusterId   = 2;
    constexpr uint32_t attributeId = 3;

    chip::app::AttributePathParams attributes[1];
    attributes[0] = chip::app::AttributePathParams{ endpointId, clusterId, attributeId };

    mParams.SetExtraReadPaths(Span<const app::AttributePathParams>{ attributes, 1 });

    auto pathParams = mParams.GetExtraReadPaths();

    ASSERT_EQ(pathParams.size(), size_t{ 1 });
    EXPECT_EQ(pathParams[0].mEndpointId, endpointId);
    EXPECT_EQ(pathParams[0].mClusterId, clusterId);
    EXPECT_EQ(pathParams[0].mAttributeId, attributeId);
}

// kStages are enumerators from enum type name CommissioningStage
struct StageTransition
{
    CommissioningStage currentStage;
    CommissioningStage nextStage;
};

const std::vector<StageTransition> kStagePairs = {
    // Only linear transitions are tested here; branching cases are separate
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
    { static_cast<CommissioningStage>(250), kError }, // default case
};

TEST_F(AutoCommissionerTest, NextCommissioningStage)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    for (const auto & stagePair : kStagePairs)
    {
        CommissioningStage nextStage = mAcc.AccessGetNextCommissioningStageInternal(stagePair.currentStage, err);
        EXPECT_EQ(nextStage, stagePair.nextStage);
    }
}

TEST_F(AutoCommissionerTest, NextStageStopCommissioning)
{
    mCommissioner.StopCommissioning();
    CHIP_ERROR err           = CHIP_ERROR_INTERNAL;
    CommissioningStage stage = mAcc.AccessGetNextCommissioningStageInternal(kSecurePairing, err);
    EXPECT_EQ(stage, kCleanup);
}

TEST_F(AutoCommissionerTest, NextCommissioningStageAfterError)
{
    CHIP_ERROR err           = CHIP_ERROR_INTERNAL;
    CommissioningStage stage = mAcc.AccessGetNextCommissioningStageInternal(kSecurePairing, err);
    EXPECT_EQ(stage, kCleanup);
}

TEST_F(AutoCommissionerTest, NextStageReadCommissioningInfo)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    mAcc.SetBreadcrumb(0);
    CommissioningStage nextStage = mAcc.AccessGetNextCommissioningStageInternal(kReadCommissioningInfo, err);
    EXPECT_EQ(nextStage, kArmFailsafe);

    mAcc.SetBreadcrumb(1);
    CommissioningStage fromRead = mAcc.AccessGetNextCommissioningStageInternal(kReadCommissioningInfo, err);
    CommissioningStage fromSend = mAcc.AccessGetNextCommissioningStageInternal(kSendNOC, err);
    EXPECT_EQ(fromRead, fromSend);
}

TEST_F(AutoCommissionerTest, NextStageConfigureTCAcknowledgments)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    mAcc.SetUTCRequirements(true);
    CommissioningStage nextStage = mAcc.AccessGetNextCommissioningStageInternal(kConfigureTCAcknowledgments, err);
    EXPECT_EQ(nextStage, kConfigureUTCTime);

    mAcc.SetUTCRequirements(false);
    nextStage = mAcc.AccessGetNextCommissioningStageInternal(kConfigureTCAcknowledgments, err);
    EXPECT_EQ(nextStage, kSendPAICertificateRequest);
}
// ----- VerifyICD tests (cleaned) -----

TEST_F(AutoCommissionerTest, VerifyICD_FailsWhenKeyMissing)
{
    AutoCommissionerTestAccess acc(&mCommissioner);

    CommissioningParameters p{};
    p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete); // non-ignore
    EXPECT_EQ(acc.AccessVerifyICDRegistrationInfo(p), CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, VerifyICD_FailsWhenKeyWrongSize)
{
    AutoCommissionerTestAccess acc(&mCommissioner);

    CommissioningParameters p{};
    p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);

    uint8_t short_key[Crypto::kAES_CCM128_Key_Length - 1] = {};
    p.SetICDSymmetricKey(ByteSpan{ short_key, sizeof(short_key) });

    EXPECT_EQ(acc.AccessVerifyICDRegistrationInfo(p), CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, VerifyICD_FailsWhenCheckInNodeMissing)
{
    AutoCommissionerTestAccess acc(&mCommissioner);

    CommissioningParameters p{};
    p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);

    uint8_t key[Crypto::kAES_CCM128_Key_Length] = {};
    p.SetICDSymmetricKey(ByteSpan{ key, sizeof(key) });
    // Missing check-in node id
    EXPECT_EQ(acc.AccessVerifyICDRegistrationInfo(p), CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, VerifyICD_FailsWhenMonitoredSubjectOrClientTypeMissing)
{
    AutoCommissionerTestAccess acc(&mCommissioner);

    CommissioningParameters p{};
    p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);

    uint8_t key[Crypto::kAES_CCM128_Key_Length] = {};
    p.SetICDSymmetricKey(ByteSpan{ key, sizeof(key) });
    p.SetICDCheckInNodeId(NodeId{ 42 });

    // 1) Missing monitored subject
    EXPECT_EQ(acc.AccessVerifyICDRegistrationInfo(p), CHIP_ERROR_INVALID_ARGUMENT);

    // 2) Add subject but still missing client type
    p.SetICDMonitoredSubject(uint64_t{ 7 });
    EXPECT_EQ(acc.AccessVerifyICDRegistrationInfo(p), CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, VerifyICD_SucceedsWhenAllPresent)
{
    AutoCommissionerTestAccess acc(&mCommissioner);

    CommissioningParameters p{};
    p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);

    uint8_t key[Crypto::kAES_CCM128_Key_Length] = {};
    p.SetICDSymmetricKey(ByteSpan{ key, sizeof(key) });
    p.SetICDCheckInNodeId(NodeId{ 123 });
    p.SetICDMonitoredSubject(uint64_t{ 9 });
    p.SetICDClientType(app::Clusters::IcdManagement::ClientTypeEnum::kPermanent); // use a real enum

    EXPECT_EQ(acc.AccessVerifyICDRegistrationInfo(p), CHIP_NO_ERROR);
}

TEST_F(AutoCommissionerTest, DISABLED_ExtraReadPathsMemmoveAndRealloc)
{
    using ReadPath = chip::app::AttributePathParams;

    constexpr chip::ClusterId kCluster = chip::ClusterId(0x00000006);
    constexpr chip::AttributeId kAttr  = chip::AttributeId(0x00000000);

    auto mk = [&](chip::EndpointId ep) -> ReadPath { return ReadPath(ep, kCluster, kAttr); };

    // First call: allocate
    std::array<ReadPath, 2> a = { mk(1), mk(2) };
    CommissioningParameters p1{};
    p1.SetExtraReadPaths(chip::Span<const ReadPath>(a.data(), a.size()));
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(p1), CHIP_NO_ERROR);

    // Second call with same size -> memmove path
    std::array<ReadPath, 2> b = { mk(3), mk(4) };
    CommissioningParameters p2{};
    p2.SetExtraReadPaths(chip::Span<const ReadPath>(b.data(), b.size()));
    // ASSERT_EQ(mCommissioner.SetCommissioningParameters(p2), CHIP_NO_ERROR);

    // Third call with a different size -> reallocate path
    std::array<ReadPath, 3> c = { mk(5), mk(6), mk(7) };
    CommissioningParameters p3{};
    p3.SetExtraReadPaths(chip::Span<const ReadPath>(c.data(), c.size()));
    // ASSERT_EQ(mCommissioner.SetCommissioningParameters(p3), CHIP_NO_ERROR);
}

// ----- Protected-call fix -----

TEST_F(AutoCommissionerTest, NextStageCleanupWhenStoppedOrErr)
{
    AutoCommissionerTestAccess acc(&mCommissioner);
    CHIP_ERROR lastErr = CHIP_ERROR_INTERNAL;
    EXPECT_EQ(acc.AccessGetNextCommissioningStageInternal(CommissioningStage::kSecurePairing, lastErr),
              CommissioningStage::kCleanup);
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

TEST_F(AutoCommissionerTest, RejectsTooLongCountryCode)
{
    CommissioningParameters p{};
    // Make 3+ chars (e.g., "USA") to exceed the internal 2-char cap
    p.SetCountryCode(CharSpan::fromCharString("USA"));
    EXPECT_EQ(mCommissioner.SetCommissioningParameters(p), CHIP_ERROR_INVALID_ARGUMENT);
}
TEST_F(AutoCommissionerTest, RejectsWrongSizedNonces)
{
    CommissioningParameters p{};
    std::array<uint8_t, kAttestationNonceLength - 1> badAtt{};
    p.SetAttestationNonce(ByteSpan{ badAtt.data(), badAtt.size() });
    EXPECT_EQ(mCommissioner.SetCommissioningParameters(p), CHIP_ERROR_INVALID_ARGUMENT);

    std::array<uint8_t, kCSRNonceLength + 1> badCSR{};
    CommissioningParameters p2{};
    p2.SetCSRNonce(ByteSpan{ badCSR.data(), badCSR.size() });
    EXPECT_EQ(mCommissioner.SetCommissioningParameters(p2), CHIP_ERROR_INVALID_ARGUMENT);
}
TEST_F(AutoCommissionerTest, TimeZoneNameWithinLimitIsCopied)
{
    app::Clusters::TimeSynchronization::Structs::TimeZoneStruct::Type tz{};
    tz.offset         = 0;
    tz.validAt        = epochJanFirst2000;
    const char name[] = "Asia/Yerevan";
    tz.name.SetValue(CharSpan{ name, strlen(name) });
    app::DataModel::List<decltype(tz)> list(&tz, 1);
    mParams.SetTimeZone(list);
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(mParams), CHIP_NO_ERROR);
    auto out = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(out.GetTimeZone().HasValue());
    EXPECT_TRUE(out.GetTimeZone().Value()[0].name.HasValue());
    EXPECT_TRUE(out.GetTimeZone().Value()[0].name.Value().data_equal(CharSpan{ name, strlen(name) }));
}
TEST_F(AutoCommissionerTest, AcceptsReasonableDefaultNtp)
{
    CommissioningParameters p{};
    constexpr char kNtp[] = "pool.ntp.org";
    p.SetDefaultNTP(chip::app::DataModel::MakeNullable(CharSpan{ kNtp, strlen(kNtp) }));
    EXPECT_EQ(mCommissioner.SetCommissioningParameters(p), CHIP_NO_ERROR);
    auto out = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(out.GetDefaultNTP().HasValue());
    ASSERT_FALSE(out.GetDefaultNTP().Value().IsNull());
    EXPECT_TRUE(out.GetDefaultNTP().Value().Value().data_equal(CharSpan{ kNtp, strlen(kNtp) }));
}

// ----- VerifyICD tests -----

TEST_F(AutoCommissionerTest, VerifyICD_FailsWhenKeyMissing)
{
    CommissioningParameters p{};
    p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete); // non-ignore
    EXPECT_EQ(mAcc.AccessVerifyICDRegistrationInfo(p), CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, VerifyICD_FailsWhenKeyWrongSize)
{
    CommissioningParameters p{};
    p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);

    uint8_t short_key[Crypto::kAES_CCM128_Key_Length - 1] = {};
    p.SetICDSymmetricKey(ByteSpan{ short_key, sizeof(short_key) });

    EXPECT_EQ(mAcc.AccessVerifyICDRegistrationInfo(p), CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, VerifyICD_FailsWhenCheckInNodeMissing)
{
    CommissioningParameters p{};
    p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);

    uint8_t key[Crypto::kAES_CCM128_Key_Length] = {};
    p.SetICDSymmetricKey(ByteSpan{ key, sizeof(key) });

    EXPECT_EQ(mAcc.AccessVerifyICDRegistrationInfo(p), CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, VerifyICD_FailsWhenMonitoredSubjectOrClientTypeMissing)
{
    CommissioningParameters p{};
    p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);

    uint8_t key[Crypto::kAES_CCM128_Key_Length] = {};
    p.SetICDSymmetricKey(ByteSpan{ key, sizeof(key) });
    p.SetICDCheckInNodeId(NodeId{ 42 });

    EXPECT_EQ(mAcc.AccessVerifyICDRegistrationInfo(p), CHIP_ERROR_INVALID_ARGUMENT);

    p.SetICDMonitoredSubject(uint64_t{ 7 });
    EXPECT_EQ(mAcc.AccessVerifyICDRegistrationInfo(p), CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, VerifyICD_SucceedsWhenAllPresent)
{
    CommissioningParameters p{};
    p.SetICDRegistrationStrategy(ICDRegistrationStrategy::kBeforeComplete);

    uint8_t key[Crypto::kAES_CCM128_Key_Length] = {};
    p.SetICDSymmetricKey(ByteSpan{ key, sizeof(key) });
    p.SetICDCheckInNodeId(NodeId{ 123 });
    p.SetICDMonitoredSubject(uint64_t{ 9 });
    p.SetICDClientType(app::Clusters::IcdManagement::ClientTypeEnum::kPermanent);

    EXPECT_EQ(mAcc.AccessVerifyICDRegistrationInfo(p), CHIP_NO_ERROR);
}

TEST_F(AutoCommissionerTest, ExtraReadPathsMemmoveAndRealloc)
{
    using ReadPath = chip::app::AttributePathParams;

    // 1) allocate (size = 2)
    std::array<ReadPath, 2> a = { MkPath(1), MkPath(2) };
    CommissioningParameters p1{};
    p1.SetExtraReadPaths(chip::Span<const ReadPath>(a.data(), a.size()));
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(p1), CHIP_NO_ERROR);
    {
        auto out = mCommissioner.GetCommissioningParameters().GetExtraReadPaths();
        ASSERT_EQ(out.size(), size_t{ 2 });
        EXPECT_EQ(out[0].mEndpointId, 1);
        EXPECT_EQ(out[1].mEndpointId, 2);
    }
    // 2) different size -> hits reallocate+memcpy branch
    std::array<ReadPath, 3> c = { MkPath(5), MkPath(6), MkPath(7) };
    CommissioningParameters p3{};
    p3.SetExtraReadPaths(chip::Span<const ReadPath>(c.data(), c.size()));
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(p3), CHIP_NO_ERROR);
    {
        auto out = mCommissioner.GetCommissioningParameters().GetExtraReadPaths();
        ASSERT_EQ(out.size(), size_t{ 3 });
        EXPECT_EQ(out[0].mEndpointId, 5);
        EXPECT_EQ(out[1].mEndpointId, 6);
        EXPECT_EQ(out[2].mEndpointId, 7);
    }

    // 3) alias/subspan of the *old* internal buffer -> exercises the “stash old” path safely
    CommissioningParameters p4{};
    auto prev = mCommissioner.GetCommissioningParameters().GetExtraReadPaths(); // {5,6,7} buffer
    p4.SetExtraReadPaths(chip::Span<const ReadPath>(prev.data() + 1, 2));       // {6,7}
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(p4), CHIP_NO_ERROR);
    {
        auto out = mCommissioner.GetCommissioningParameters().GetExtraReadPaths();
        ASSERT_EQ(out.size(), size_t{ 2 });
        EXPECT_EQ(out[0].mEndpointId, 6);
        EXPECT_EQ(out[1].mEndpointId, 7);
    }
}
TEST_F(AutoCommissionerTest, ExtraReadPaths_ReallocDifferentSize)
{
    using ReadPath            = chip::app::AttributePathParams;
    std::array<ReadPath, 2> a = { MkPath(1), MkPath(2) };
    CommissioningParameters p1{};
    p1.SetExtraReadPaths(chip::Span<const ReadPath>(a.data(), a.size()));
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(p1), CHIP_NO_ERROR);

    // size change -> must take realloc+memcpy branch
    std::array<ReadPath, 3> c = { MkPath(5), MkPath(6), MkPath(7) };
    CommissioningParameters p2{};
    p2.SetExtraReadPaths(chip::Span<const ReadPath>(c.data(), c.size()));
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(p2), CHIP_NO_ERROR);

    auto out = mCommissioner.GetCommissioningParameters().GetExtraReadPaths();
    ASSERT_EQ(out.size(), size_t{ 3 });
    EXPECT_EQ(out[0].mEndpointId, 5);
    EXPECT_EQ(out[1].mEndpointId, 6);
    EXPECT_EQ(out[2].mEndpointId, 7);
}

TEST_F(AutoCommissionerTest, ExtraReadPaths_AliasSubspan)
{
    using ReadPath = chip::app::AttributePathParams;
    // seed with 3 so we have an internal buffer
    std::array<ReadPath, 3> c = { MkPath(5), MkPath(6), MkPath(7) };
    CommissioningParameters p1{};
    p1.SetExtraReadPaths(chip::Span<const ReadPath>(c.data(), c.size()));
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(p1), CHIP_NO_ERROR);

    // Now pass a subspan that aliases the old internal buffer (exercises the “preserve old then memcpy” logic)
    CommissioningParameters p2{};
    auto prev = mCommissioner.GetCommissioningParameters().GetExtraReadPaths(); // spans internal
    p2.SetExtraReadPaths(chip::Span<const ReadPath>(prev.data() + 1, 2));       // {6,7}
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(p2), CHIP_NO_ERROR);

    auto out = mCommissioner.GetCommissioningParameters().GetExtraReadPaths();
    ASSERT_EQ(out.size(), size_t{ 2 });
    EXPECT_EQ(out[0].mEndpointId, 6);
    EXPECT_EQ(out[1].mEndpointId, 7);
}

TEST_F(AutoCommissionerTest, SetCommissioningParametersIsNoOpWhenPassingOwnParams)
{
    mParams.SetCountryCode("US"_span);
    ExpectSetOk(mCommissioner, mParams);

    const CommissioningParameters & same = mCommissioner.GetCommissioningParameters();
    ExpectSetOk(mCommissioner, same);

    auto again = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(again.GetCountryCode().HasValue());
    EXPECT_TRUE(again.GetCountryCode().Value().data_equal("US"_span));
}

TEST_F(AutoCommissionerTest, CopiesValidThreadDataset)
{
    uint8_t ds[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    mParams.SetThreadOperationalDataset(ByteSpan{ ds, sizeof(ds) });
    ExpectSetOk(mCommissioner, mParams);

    auto p = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p.GetThreadOperationalDataset().HasValue());
    EXPECT_EQ(p.GetThreadOperationalDataset().Value().size(), sizeof(ds));
    EXPECT_TRUE(p.GetThreadOperationalDataset().Value().data_equal(ByteSpan{ ds, sizeof(ds) }));
}

TEST_F(AutoCommissionerTest, CopiesValidWifiCredentials)
{
    const std::array<uint8_t, 2> ssid = { 'A', 'P' };
    const std::array<uint8_t, 4> pass = { '1', '2', '3', '4' };
    mParams.SetWiFiCredentials(WiFiCredentials{ ByteSpan{ ssid }, ByteSpan{ pass } });

    ExpectSetOk(mCommissioner, mParams);
    auto p = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p.GetWiFiCredentials().HasValue());
    auto creds = p.GetWiFiCredentials().Value();
    EXPECT_TRUE(creds.ssid.data_equal(ByteSpan{ ssid }));
    EXPECT_TRUE(creds.credentials.data_equal(ByteSpan{ pass }));
}

TEST_F(AutoCommissionerTest, AcceptsTwoCharCountryCode)
{
    mParams.SetCountryCode("AM"_span);
    ExpectSetOk(mCommissioner, mParams);

    auto p = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p.GetCountryCode().HasValue());
    EXPECT_TRUE(p.GetCountryCode().Value().data_equal("AM"_span));
}

TEST_F(AutoCommissionerTest, UsesProvidedNoncesOrGeneratesRandomWhenMissing)
{
    // Provided nonces
    std::vector<uint8_t> att(kAttestationNonceLength, 0xAB);
    std::vector<uint8_t> csr(kCSRNonceLength, 0xCD);
    mParams.SetAttestationNonce(ByteSpan{ att.data(), att.size() });
    mParams.SetCSRNonce(ByteSpan{ csr.data(), csr.size() });

    ExpectSetOk(mCommissioner, mParams);
    auto p1 = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p1.GetAttestationNonce().HasValue());
    EXPECT_EQ(p1.GetAttestationNonce().Value().size(), kAttestationNonceLength);
    EXPECT_TRUE(p1.GetAttestationNonce().Value().data_equal(ByteSpan{ att.data(), att.size() }));

    ASSERT_TRUE(p1.GetCSRNonce().HasValue());
    EXPECT_EQ(p1.GetCSRNonce().Value().size(), kCSRNonceLength);
    EXPECT_TRUE(p1.GetCSRNonce().Value().data_equal(ByteSpan{ csr.data(), csr.size() }));

    // Missing nonces -> generated
    CommissioningParameters empty;
    ExpectSetOk(mCommissioner, empty);
    auto p2 = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p2.GetAttestationNonce().HasValue());
    EXPECT_EQ(p2.GetAttestationNonce().Value().size(), kAttestationNonceLength);
    ASSERT_TRUE(p2.GetCSRNonce().HasValue());
    EXPECT_EQ(p2.GetCSRNonce().Value().size(), kCSRNonceLength);
}

TEST_F(AutoCommissionerTest, TimeZoneNameTooLongIsCleared)
{
    TZ tz{};
    tz.offset  = 0;
    tz.validAt = epochJanFirst2000;

    std::vector<char> long_name(4096, 'X');
    tz.name.SetValue(CharSpan{ long_name.data(), long_name.size() });

    app::DataModel::List<TZ> list(&tz, 1);
    mParams.SetTimeZone(list);

    ExpectSetOk(mCommissioner, mParams);
    auto p = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(p.GetTimeZone().HasValue());
    ASSERT_EQ(p.GetTimeZone().Value().size(), size_t{ 1 });
    ASSERT_FALSE(p.GetTimeZone().Value()[0].name.HasValue());
}

TEST_F(AutoCommissionerTest, OversizedDefaultNtpIsIgnoredAndNotSet)
{
    std::vector<char> long_ntp(4096, 'n');
    mParams.SetDefaultNTP(chip::app::DataModel::MakeNullable(CharSpan{ long_ntp.data(), long_ntp.size() }));

    ExpectSetOk(mCommissioner, mParams);
    auto p = mCommissioner.GetCommissioningParameters();
    ASSERT_FALSE(p.GetDefaultNTP().HasValue());
}

TEST_F(AutoCommissionerTest, RejectsTooLongCountryCode)
{
    CommissioningParameters p{};
    p.SetCountryCode(CharSpan::fromCharString("USA"));
    ExpectSetErr(mCommissioner, p, CHIP_ERROR_INVALID_ARGUMENT);
}

TEST_F(AutoCommissionerTest, RejectsWrongSizedNonces)
{
    // Attestation too short
    {
        CommissioningParameters p{};
        auto bad = Bytes(kAttestationNonceLength - 1, 0xAA);
        p.SetAttestationNonce(ByteSpan{ bad.data(), bad.size() });
        ExpectSetErr(mCommissioner, p, CHIP_ERROR_INVALID_ARGUMENT);
    }
    // CSR too long
    {
        CommissioningParameters p{};
        auto bad = Bytes(kCSRNonceLength + 1, 0xBB);
        p.SetCSRNonce(ByteSpan{ bad.data(), bad.size() });
        ExpectSetErr(mCommissioner, p, CHIP_ERROR_INVALID_ARGUMENT);
    }
}

TEST_F(AutoCommissionerTest, TimeZoneNameWithinLimitIsCopied)
{
    TZ tz{};
    tz.offset         = 0;
    tz.validAt        = epochJanFirst2000;
    const char name[] = "Asia/Yerevan";
    tz.name.SetValue(CharSpan{ name, strlen(name) });

    app::DataModel::List<TZ> list(&tz, 1);
    mParams.SetTimeZone(list);

    ExpectSetOk(mCommissioner, mParams);
    auto out = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(out.GetTimeZone().HasValue());
    ASSERT_TRUE(out.GetTimeZone().Value()[0].name.HasValue());
    EXPECT_TRUE(out.GetTimeZone().Value()[0].name.Value().data_equal(CharSpan{ name, strlen(name) }));
}

TEST_F(AutoCommissionerTest, AcceptsReasonableDefaultNtp)
{
    CommissioningParameters p{};
    constexpr char kNtp[] = "pool.ntp.org";
    p.SetDefaultNTP(chip::app::DataModel::MakeNullable(CharSpan{ kNtp, strlen(kNtp) }));
    ExpectSetOk(mCommissioner, p);
    auto out = mCommissioner.GetCommissioningParameters();
    ASSERT_TRUE(out.GetDefaultNTP().HasValue());
    ASSERT_FALSE(out.GetDefaultNTP().Value().IsNull());
    EXPECT_TRUE(out.GetDefaultNTP().Value().Value().data_equal(CharSpan{ kNtp, strlen(kNtp) }));
}

} // namespace
