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

import SwiftUI

import RadixSDK

struct AddressView: Equatable {

    private let address: Address

    @State private var isPresentingCopiedAddressAlert = false

    init(address: Address) {
        self.address = address
    }
}

extension AddressView {
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.address == rhs.address
    }
}

extension AddressView: View {
    var body: some View {
        Text(addressString)
            .lineLimit(nil)
            .contextMenu {
                copyAddressButton
            }
    }
}

private extension AddressView {
    var copyAddressButton: some View {
        Button("Copy address") {
            UIPasteboard.general.string = self.addressString
            self.isPresentingCopiedAddressAlert = true
        }.buttonStyleEmerald()
            .alert(isPresented: $isPresentingCopiedAddressAlert) {
                Alert(title: Text("Copied"), message: nil, dismissButton: nil)
        }
    }

    var addressString: String {
        address.stringValue
    }
}

