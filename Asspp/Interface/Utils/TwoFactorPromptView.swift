//
//  TwoFactorPromptView.swift
//  Asspp
//
//  Created by Codex on 2026/2/14.
//

import SwiftUI

struct TwoFactorPromptView: View {
    let message: String
    @Binding var code: String
    let onCancel: () -> Void
    let onContinue: () -> Void

    @FocusState private var isFocused: Bool

    var body: some View {
        NavigationStack {
            FormOnTahoeList {
                Section {
                    Text(message)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)

                    TextField("2FA Code", text: $code)
                        #if os(iOS)
                            .keyboardType(.numberPad)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled(true)
                        #endif
                        .font(.system(.body, design: .monospaced))
                        .focused($isFocused)
                } header: {
                    Text("Verification Code")
                } footer: {
                    Text("Apple may require a one-time verification code to continue.")
                }
            }
            .navigationTitle("2FA Required")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { onCancel() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue") { onContinue() }
                        .disabled(code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
        .onAppear { isFocused = true }
    }
}

