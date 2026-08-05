//
//  PIDVerificationTests.swift
//  CA_mdlTests
//

import Testing
import Foundation
import CryptoKit
import SwiftCBOR
@testable import CA_mdl

struct PIDVerificationTests {

    // MARK: - VPTokenHandler

    @Test func testFormatDetectionMsoMdoc() {
        // Bytes that are not valid UTF-8 (a bare continuation byte with no lead byte),
        // representative of raw CBOR that should never be mistaken for SD-JWT text.
        let cborLikeBytes = Data([0xA1, 0x82, 0xFF, 0xFE, 0x00])
        let format = VPTokenHandler.detectFormat(from: cborLikeBytes)
        guard case .msoMdoc = format else {
            Issue.record("Expected .msoMdoc, got \(format)")
            return
        }
    }

    @Test func testFormatDetectionSDJWT() {
        let sdJwtString = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig~disc1~disc2~"
        let data = Data(sdJwtString.utf8)
        let format = VPTokenHandler.detectFormat(from: data)
        guard case .sdJWT(let decoded) = format else {
            Issue.record("Expected .sdJWT, got \(format)")
            return
        }
        #expect(decoded == sdJwtString)
    }

    // MARK: - SD-JWT disclosure hashing / decoding

    @Test func testSDJWTDisclosureHashVerification() {
        let disclosure = "WyJhYmMxMjNzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ"
        let expectedHash = SHA256.hash(data: Data(disclosure.utf8))
        let expectedBase64URL = Data(expectedHash)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        let actual = SDJWTVerifier.disclosureDigest(disclosure)
        #expect(actual == expectedBase64URL)
    }

    @Test func testSDJWTDisclosureDecoding() throws {
        let json = #"["abc123salt","given_name","John"]"#
        let disclosure = Data(json.utf8)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        let decoded = try SDJWTVerifier.decodeDisclosure(disclosure)
        #expect(decoded.name == "given_name")
        #expect(decoded.value as? String == "John")
    }

    @Test func testSDJWTInjectionAttackRejected() {
        let json = #"["abc123salt","family_name","Evil"]"#
        let disclosure = Data(json.utf8)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        // sdArray deliberately does NOT contain this disclosure's hash.
        let sdArray = ["someUnrelatedHash", "anotherUnrelatedHash"]

        do {
            _ = try SDJWTVerifier.verifyAndDecodeDisclosure(disclosure, sdArray: sdArray)
            Issue.record("Expected PIDError.invalidSDJWT to be thrown")
        } catch PIDError.invalidSDJWT {
            // expected
        } catch {
            Issue.record("Expected PIDError.invalidSDJWT, got \(error)")
        }
    }

    // MARK: - JWT signature verification
    //
    // The real codebase's CoseVerifier never does DER conversion — CryptoKit verifies raw
    // r||s ECDSA signatures directly — so SDJWTVerifier follows the same approach and there
    // is no DER helper to test. This exercises the actual signature-verification path
    // (CryptoKit ES256) end to end instead, covering both the accept and reject cases.
    @Test func testJWTSignatureVerificationRoundTrip() throws {
        let privateKey = P256.Signing.PrivateKey()
        let signingInput = Data("header.payload".utf8)
        let signature = try privateKey.signature(for: signingInput)

        let valid = try SDJWTVerifier.verifyECDSASignature(
            alg: "ES256",
            signingInput: signingInput,
            signature: signature.rawRepresentation,
            publicKeyX963: privateKey.publicKey.x963Representation
        )
        #expect(valid)

        let tamperedInput = Data("header.payload!".utf8)
        let invalid = try SDJWTVerifier.verifyECDSASignature(
            alg: "ES256",
            signingInput: tamperedInput,
            signature: signature.rawRepresentation,
            publicKeyX963: privateKey.publicKey.x963Representation
        )
        #expect(!invalid)
    }

    // MARK: - TrustAnchorStore

    @Test func testTrustAnchorStoreLoadsFallback() async throws {
        let store = TrustAnchorStore()
        let testBundle = Bundle(for: TrustAnchorStoreFixtureMarker.self)
        try await store.loadBundledFallback(bundle: testBundle)
        // Succeeding without throwing is the assertion; the fixture's certs are placeholders
        // and are expected to be skipped rather than resolve to real trust anchors.
    }

    // MARK: - MsoMdocPIDVerifier

    @Test func testMsoMdocPIDVerifierRejectsWrongDocType() async {
        let doc: CBOR = .map([.utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL")])
        let response: CBOR = .map([.utf8String("documents"): .array([doc])])
        let cborData = Data(response.encode())

        let verifier = MsoMdocPIDVerifier()
        do {
            _ = try await verifier.verify(cborData: cborData, expectedNonce: "n", countryCode: "DE")
            Issue.record("Expected PIDError.unsupportedCredentialType to be thrown")
        } catch PIDError.unsupportedCredentialType {
            // expected
        } catch {
            Issue.record("Expected PIDError.unsupportedCredentialType, got \(error)")
        }
    }

    @Test func testExpiredPIDThrows() {
        let now = Date()
        let validFrom = now.addingTimeInterval(-7200)
        let validUntil = now.addingTimeInterval(-3600) // already expired

        do {
            try MsoMdocPIDVerifier.checkValidity(now: now, validFrom: validFrom, validUntil: validUntil)
            Issue.record("Expected PIDError.expiredDocument to be thrown")
        } catch PIDError.expiredDocument {
            // expected
        } catch {
            Issue.record("Expected PIDError.expiredDocument, got \(error)")
        }
    }

    @Test func testNonceMismatchThrows() {
        do {
            try MsoMdocPIDVerifier.checkNonce(presented: "wrong-nonce", expected: "expected-nonce")
            Issue.record("Expected PIDError.nonceMismatch to be thrown")
        } catch PIDError.nonceMismatch {
            // expected
        } catch {
            Issue.record("Expected PIDError.nonceMismatch, got \(error)")
        }
    }
}

private final class TrustAnchorStoreFixtureMarker {}
