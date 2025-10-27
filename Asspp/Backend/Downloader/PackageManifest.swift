//
//  PackageManifest.swift
//  Asspp
//
//  Created by 秋星桥 on 2024/7/13.
//

import AnyCodable // Moved to Request.swift

import ApplePackage
import Foundation

private let packagesDir = {
    let ret = documentsDirectory.appendingPathComponent("Packages")
    try? FileManager.default.createDirectory(at: ret, withIntermediateDirectories: true)
    return ret
}()

class PackageManifest: ObservableObject, Identifiable, Codable, Hashable, Equatable {
    private(set) var id: UUID = .init()

    private(set) var account: AppStore.UserAccount
    private(set) var package: AppStore.AppPackage

    private(set) var url: URL
    private(set) var signatures: [ApplePackage.Sinf]

    private(set) var creation: Date

    var state: PackageState = .init() {
        didSet {
            DispatchQueue.main.async {
                self.objectWillChange.send()
            }
            if state.status == .completed {
                refreshUpdateStatus(force: true)
            } else if updateStatus != .idle {
                updateStatus = .idle
            }
        }
    }

    var updateStatus: UpdateStatus = .idle {
        didSet {
            DispatchQueue.main.async {
                self.objectWillChange.send()
            }
        }
    }

    var targetLocation: URL {
        packagesDir
            .appendingPathComponent(package.software.bundleID)
            .appendingPathComponent(package.software.version)
            .appendingPathComponent("\(id.uuidString)")
            .appendingPathExtension("ipa")
    }

    var completed: Bool { state.status == .completed }

    init(account: AppStore.UserAccount, package: AppStore.AppPackage, downloadOutput: ApplePackage.DownloadOutput) {
        self.account = account
        self.package = package
        url = URL(string: downloadOutput.downloadURL)!
        signatures = downloadOutput.sinfs
        creation = .init()
    }

    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        account = try container.decode(AppStore.UserAccount.self, forKey: .account)
        package = try container.decode(AppStore.AppPackage.self, forKey: .package)
        url = try container.decode(URL.self, forKey: .url)
        signatures = try container.decode([ApplePackage.Sinf].self, forKey: .signatures)
        creation = try container.decode(Date.self, forKey: .creation)
        state = try container.decode(PackageState.self, forKey: .runtime)
        updateStatus = try container.decodeIfPresent(UpdateStatus.self, forKey: .updateStatus) ?? .idle
        if state.status == .completed {
            refreshUpdateStatus()
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(account, forKey: .account)
        try container.encode(package, forKey: .package)
        try container.encode(url, forKey: .url)
        try container.encode(signatures, forKey: .signatures)
        try container.encode(creation, forKey: .creation)
        try container.encode(state, forKey: .runtime)
        try container.encode(updateStatus, forKey: .updateStatus)
    }

    private enum CodingKeys: String, CodingKey {
        case id, account, package, url, md5, signatures, metadata, creation, runtime, updateStatus
    }

    static func == (lhs: PackageManifest, rhs: PackageManifest) -> Bool {
        lhs.hashValue == rhs.hashValue
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(account)
        hasher.combine(package)
        hasher.combine(url)
        hasher.combine(signatures)
        hasher.combine(creation)
        hasher.combine(state)
        hasher.combine(updateStatus)
    }
}

extension PackageManifest {
    func delete() {
        try? FileManager.default.removeItem(at: targetLocation)
        var cleanUpDir = targetLocation.deletingLastPathComponent()
        do {
            while FileManager.default.fileExists(atPath: cleanUpDir.path),
                  try FileManager.default.contentsOfDirectory(atPath: cleanUpDir.path).isEmpty,
                  cleanUpDir.path != packagesDir.path,
                  cleanUpDir.path.count > packagesDir.path.count,
                  cleanUpDir.path.contains(packagesDir.path)
            {
                try? FileManager.default.removeItem(at: cleanUpDir)
                cleanUpDir.deleteLastPathComponent()
            }
        } catch {}
    }
}

extension PackageManifest {
    func refreshUpdateStatus(force: Bool = false) {
        guard state.status == .completed else {
            if updateStatus != .idle {
                updateStatus = .idle
            }
            return
        }

        if updateStatus == .checking {
            return
        }

        if !force && !updateStatus.allowsRefresh {
            return
        }

        updateStatus = .checking

        guard let countryCode = ApplePackage.Configuration.countryCode(for: account.account.store) else {
            updateStatus = .failed(String(localized: "Unable to determine account region."))
            logger.warning("Skipping update check for \(package.software.bundleID); unsupported store identifier \(account.account.store)")
            return
        }

        Task.detached { [weak self] in
            guard let self else { return }
            do {
                logger.debug("Checking updates for \(self.package.software.bundleID)")
                let lookup = try await ApplePackage.Lookup.lookup(
                    bundleID: self.package.software.bundleID,
                    countryCode: countryCode
                )
                let latestVersion = lookup.version
                let comparison = latestVersion.compare(self.package.software.version, options: .numeric)
                let status: UpdateStatus = comparison == .orderedDescending
                    ? .updateAvailable(latest: latestVersion)
                    : .upToDate(latest: latestVersion)
                await MainActor.run {
                    self.updateStatus = status
                }
            } catch {
                logger.warning("Failed to check updates for \(self.package.software.bundleID): \(error.localizedDescription)")
                await MainActor.run {
                    self.updateStatus = .failed(String(localized: "Update check failed."))
                }
            }
        }
    }
}

extension PackageManifest {
    enum UpdateStatus: Equatable, Hashable {
        case idle
        case checking
        case upToDate(latest: String)
        case updateAvailable(latest: String)
        case failed(String)

        var allowsRefresh: Bool {
            switch self {
            case .idle, .failed:
                return true
            case .checking, .upToDate, .updateAvailable:
                return false
            }
        }
    }
}

extension PackageManifest.UpdateStatus: Codable {
    private enum CodingKeys: String, CodingKey {
        case caseName
        case version
        case message
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .idle:
            try container.encode("idle", forKey: .caseName)
        case .checking:
            try container.encode("checking", forKey: .caseName)
        case let .upToDate(latest):
            try container.encode("upToDate", forKey: .caseName)
            try container.encode(latest, forKey: .version)
        case let .updateAvailable(latest):
            try container.encode("updateAvailable", forKey: .caseName)
            try container.encode(latest, forKey: .version)
        case let .failed(message):
            try container.encode("failed", forKey: .caseName)
            try container.encode(message, forKey: .message)
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let caseName = try container.decode(String.self, forKey: .caseName)
        switch caseName {
        case "idle":
            self = .idle
        case "checking":
            self = .checking
        case "upToDate":
            let version = try container.decode(String.self, forKey: .version)
            self = .upToDate(latest: version)
        case "updateAvailable":
            let version = try container.decode(String.self, forKey: .version)
            self = .updateAvailable(latest: version)
        case "failed":
            let message = try container.decode(String.self, forKey: .message)
            self = .failed(message)
        default:
            self = .idle
        }
    }
}
