//
// MIT License
//
// Copyright (c) 2018-2019 Radix DLT ( https://radixdlt.com )
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

import Foundation
import SwiftUI
import Combine

import RadixSDK


struct ConfirmMnemonicScreen {
    @EnvironmentObject private var viewModel: ViewModel
}

// MARK: - View
extension ConfirmMnemonicScreen: Screen {
    var body: some View {
        VStack {
            Text("Tap on the words in the correct order").font(.roboto(size: 18))

            MnemonicGridView(cellViewModels: viewModel.selectedWords) { self.viewModel.removeWordFromSelected(word: $0) }

            MnemonicGridView(cellViewModels: viewModel.availableWords) { self.viewModel.addWordToSelected(word: $0) }

            Button("Restart") {
                self.viewModel.unselectAll()
            }.buttonStyleSaphire()

//            NavigationLink(destination: BarScreen()) {
//                Text("Confirm").buttonStyleEmerald(enabled: viewModel.hasOrderedMnemonicWordsCorrectly)
//            } .enabled(viewModel.hasOrderedMnemonicWordsCorrectly)

            Button("Confirm") { self.viewModel.done() }.buttonStyleEmerald(enabled: viewModel.hasOrderedMnemonicWordsCorrectly)
        }
            .padding([.leading, .trailing], 20)
            .onAppear { self.viewModel.unselectAll() }
            .navigationBarTitle("Confirm order")
    }
}

// MARK: - ViewModel
typealias ConfirmMnemonicViewModel = ConfirmMnemonicScreen.ViewModel

typealias Done = () -> Void

extension ConfirmMnemonicScreen {

    final class ViewModel: ObservableObject {

        let objectWillChange = PassthroughSubject<Void, Never>()

        @Published private var mnemonicWordsToConfirm: [MnemonicWordCellViewModel]

        private let _hasOrderedMnemonicWordsCorrectly: ([String]) -> Bool
        private let keychainStore: SecurePersistence

        private let dismissClosure: Done

        init(keychainStore: SecurePersistence, dismiss: @escaping Done) {

            self.keychainStore = keychainStore
            self.dismissClosure = dismiss

            guard let mnemonic = keychainStore.mnemonic else {
                   incorrectImplementation("Should have mnemonic")
               }

            let mnemonicWords = mnemonic.words.map { $0.value }

            self.mnemonicWordsToConfirm = mnemonicWords.enumerated().map {
                MnemonicWordCellViewModel(word: $0.element, correctPosition: $0.offset)
            }
            #if DEBUG
            // do not shuffle for debug builds
            #else
            .shuffled()
            #endif

            _hasOrderedMnemonicWordsCorrectly = { $0 == mnemonicWords }
        }
    }
}

private extension ConfirmMnemonicScreen.ViewModel {
    var hasOrderedMnemonicWordsCorrectly: Bool {
        return _hasOrderedMnemonicWordsCorrectly(selectedWords.map { $0.word })
    }

    var selectedWords: [MnemonicWordCellViewModel] {
        return mnemonicWordsToConfirm
            .filter { $0.selectedIndex != nil }
            // we have already filtered out elements having a `selectedIndex`, so force unwrap ok!
            .map { (viewModel: $0, index: $0.selectedIndex!) }
            .sorted(by: \.index)
            .map { $0.viewModel }

    }

    var availableWords: [MnemonicWordCellViewModel] { mnemonicWordsToConfirm.filter { $0.selectedIndex == nil } }

    func addWordToSelected(word selectedWord: MnemonicWordCellViewModel) {
        selectedWord.selectedIndex = selectedWords.count
        objectWillChange.send()
    }

    func removeWordFromSelected(word selectedWord: MnemonicWordCellViewModel) {

        let indexOfWordToDeselect = selectedWord.selectedIndex!
        for wordToUpdate in selectedWords where wordToUpdate.selectedIndex! >= indexOfWordToDeselect {
            wordToUpdate.selectedIndex = wordToUpdate.selectedIndex! - 1
        }
        selectedWord.selectedIndex = nil

        objectWillChange.send()
    }

    func unselectAll() {
        selectedWords.forEach { $0.selectedIndex = nil }
        objectWillChange.send()
    }

    func done() {
        keychainStore.mnemonic = nil
        dismissClosure()
    }
}

// MARK: - MnemonicGridView
import QGrid
struct MnemonicGridView {
    let cellViewModels: [MnemonicWordCellViewModel]
    let selection: (MnemonicWordCellViewModel) -> Void

    init(cellViewModels: [MnemonicWordCellViewModel], selection: @escaping (MnemonicWordCellViewModel) -> Void) {
        self.cellViewModels = cellViewModels
        self.selection = selection
    }
}

extension MnemonicGridView: View {
    var body: some View {
        QGrid(cellViewModels, columns: 3, vSpacing: 8, hSpacing: 8, vPadding: 8, hPadding: 8) { selectedCellViewModel in
            MnemonicGridCell(word: selectedCellViewModel) { self.selection(selectedCellViewModel) }
        }
    }
}

// MARK: MnemonicGridCell
struct MnemonicGridCell {
    let word: MnemonicWordCellViewModel
    let selection: () -> Void

    init(word: MnemonicWordCellViewModel, selection: @escaping () -> Void) {
        self.word = word
        self.selection = selection
    }
}

extension MnemonicGridCell: View {
    var body: some View {
        Button(displayedText, action: selection)
    }

    private var displayedText: String {


        var string: String = [
            String?.none,
            word.word
        ].compactMap { $0 }.joined(separator: ". ")


        #if DEBUG
        string = "\(string) [\(word.correctPosition + 1)]"
        #endif

        return string
    }
}

// MARK: - MnemonicWordCellViewModel
final class MnemonicWordCellViewModel: CustomStringConvertible {
    let correctPosition: Int
    let word: String

    var selectedIndex: Int?

    init(word: String, correctPosition: Int) {
        self.word = word
        self.correctPosition = correctPosition
    }
}

extension MnemonicWordCellViewModel: Swift.Identifiable {
    var id: Int { selectedIndex ?? correctPosition }
}

extension MnemonicWordCellViewModel {
    var description: String {
        // Omitted for security reasons
        return "<>"
    }
}

#if DEBUG
extension MnemonicWordCellViewModel: CustomDebugStringConvertible {
    var debugDescription: String {
        var selectedString = ""
        if let selectedIndex = selectedIndex {
            selectedString = ", 📍: \(selectedIndex)"
        }
        return """
            \(word)<✅: \(correctPosition)\(selectedString)>
        """
    }
}
#endif
