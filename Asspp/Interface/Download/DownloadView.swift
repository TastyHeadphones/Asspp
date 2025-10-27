//
//  DownloadView.swift
//  Asspp
//
//  Created by 秋星桥 on 2024/7/11.
//

import SwiftUI

struct DownloadView: View {
    @StateObject var vm = Downloads.this

    var body: some View {
        #if os(iOS)
            NavigationView {
                content
                    .navigationTitle("Downloads")
            }
            .navigationViewStyle(.stack)
        #else
            NavigationStack {
                content
                    .navigationTitle("Downloads")
            }
        #endif
    }

    var content: some View {
        FormOnTahoeList {
            if vm.manifests.isEmpty {
                Text("No downloads yet.")
            } else {
                packageList
            }
        }
        .toolbar {
            NavigationLink(destination: AddDownloadView()) {
                Image(systemName: "plus")
            }
        }
    }

    var packageList: some View {
        ForEach(vm.manifests, id: \.id) { req in
            NavigationLink(destination: PackageView(pkg: req)) {
                VStack(spacing: 8) {
                    ArchivePreviewView(archive: req.package)
                    SimpleProgress(progress: req.state.percent)
                        .animation(.interactiveSpring, value: req.state.percent)
                    HStack {
                        Text(req.hint)
                            .foregroundStyle(req.hintColor)
                        Spacer()
                        Text(req.creation.formatted())
                            .foregroundStyle(.secondary)
                    }
                    .font(.system(.footnote, design: .rounded))
                }
            }
            .task {
                req.refreshUpdateStatus()
            }
            .contextMenu {
                let actions = vm.getAvailableActions(for: req)
                ForEach(actions, id: \.self) { action in
                    let label = vm.getActionLabel(for: action)
                    Button(role: label.isDestructive ? .destructive : .none) {
                        Task { vm.performDownloadAction(for: req, action: action) }
                    } label: {
                        Label(label.title, systemImage: label.systemImage)
                    }
                }
            }
        }
    }
}

extension PackageManifest {
    var hint: String {
        if let error = state.error {
            return error
        }
        return switch state.status {
        case .pending:
            String(localized: "Pending...")
        case .downloading:
            [
                String(Int(state.percent * 100)) + "%",
                state.speed.isEmpty ? "" : state.speed + "/s",
            ]
            .compactMap(\.self)
            .joined(separator: " ")
        case .paused:
            String(localized: "Paused")
        case .completed:
            completionHint
        case .failed:
            String(localized: "Failed")
        }
    }

    private var completionHint: String {
        switch updateStatus {
        case .idle:
            return String(localized: "Completed")
        case .checking:
            return String(localized: "Checking for updates...")
        case let .upToDate(latest):
            let prefix = String(localized: "Up to date")
            return "\(prefix) (\(latest))"
        case let .updateAvailable(latest):
            let prefix = String(localized: "Update available")
            return "\(prefix): \(latest)"
        case .failed:
            return String(localized: "Update check failed")
        }
    }

    var hintColor: Color {
        if state.error != nil {
            return .red
        }
        switch updateStatus {
        case .updateAvailable:
            return .orange
        case .failed:
            return .secondary
        case .checking:
            return .secondary
        case .idle, .upToDate:
            return .secondary
        }
    }
}
