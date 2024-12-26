require 'spec_helper'

describe Bitcoin::Master do
  let(:test_vectors) do
    [
      {
        # Test vector from BIP39 spec
        entropy: "00000401003008014030070100240500b0180340700f020044090130280540b0",
        mnemonic: "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress blanket",
        seed: "4b94d8ad0b6f4cf1715522411695201584beb2a77d3d0ad4a6b9e143c084eb2f04d76633623d8bdd770faee336a11faee5ad055b09961e256d89ac723ac203a3",
        private_key: "5c4ffc8f27cec820e6d58fb37438b04543bebb388c282c7135ed30c8c27722d4",
        m_0_0: {
          private_key: "L58ZAa6YxmQEvwL7fJTabt8A5uz137TEuuoZnkRSpmCfNPchpQK9",
          public_key: "037e03d5741f8a212798096379efdf5e8efeab7a076263792555dc7be87ef0b7a2",
          address: "1DZG5ER2eBiDZnqKLpQjwSvbLr6wkPePcD"
        },
        m_0_1: {
          private_key: "KxEdXU5pK5EhKtWCdPSdjYCrPeKNdi8GAgn35ahxwb31vP5VCMEm",
          public_key: "0281c6418944b0ab643b7b24d2200c3b009bcada84a3bd48592441235fbe997e4e",
          address: "1CUwWrerTrmZw3N4ja7APggVYVWWRhT1HD"
        },
        m_0_0_: {
          private_key: "KykVHtUQAVKujr8uvcA2tazizkaNuZKNAZsFrcd7XvhjnuEDYQVK",
          public_key: "02d31edd816bad7bb741cf5cf9dd5c983dff58dd28f19749a83fa7a2103bf9dce3",
          address: "1HptK6XhcKg3A7eCqRRuNLS3Xz3BQHfaR7"
        }
      },
      {
        entropy: "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262",
        mnemonic: "trumpet delay fury misery march there unit enough journey book tiny trigger farm another science regular busy album fly weapon crisp face sister edit",
        seed: "473103ac1e8c51f4dcd2b1102717e434f7b9b339b332da7de55d2313d2fa1584965367b7e0cd8c4542c033f7f1af50087aa804019be0e87a8531ceceff9715d1",
        private_key: "dbb4cf97a2e1b651e4efb22e282675e7fff84c63435f93722f029958efb1068d",
        m_0_0: {
          private_key: "L3JasvVnQdWGF7opkF17CKwYDQ53L7xB8hRpgDqhcdZJcAmCNj8q",
          public_key: "02ba80f88bd962fdf1e0f0e1b34655f444244e1ad58a105d3bfc6663cf61f2a5e7",
          address: "1GtucbgL8v9JnzqTCyBhvwhQBg5hhKTFqv"
        },
        m_0_1: {
          private_key: "L58dDzJxbrWqf5iTjSS2agvJcNwSEcP5qsk9vVmZaGwCiAKZY4Zb",
          public_key: "02bd95e61a0f04915b998fb65a512f6cb45d9fe4739df0cd3a227be4a78de44345",
          address: "1JCDUVLzWAHNg9nQ9KnsQmBgGrgpxRvb84"
        },
        m_0_0_: {
          private_key: "L2snVxnzM6XGT56HeH91WAN4iQLg9UjuXYbo5u9zCPxs7UnWxnvz",
          public_key: "035e2db9fa04eed973a674ff541b4bd42fb48649d5b31987f85039da88dca7de69",
          address: "1Cn5Dcf3M32roEdteo3S6zEetVDSdJCyhu"
        }
      }
    ]
  end

  describe ".generate" do
    it "generates valid master node" do
      master = described_class.generate
      expect(master.mnemonic.split.length).to eq(24)
      expect(master.seed).to_not be_nil
      expect(master.key).to be_a(Bitcoin::Key)
    end

    it "uses words from wordlist" do
      master = described_class.generate
      master.mnemonic.split.each do |word|
        expect(described_class::WORDLIST).to include(word)
      end
    end

    it 'signs and verifies messages' do
      original_master = described_class.generate
      mnemonic = original_master.mnemonic
      msg = "Hello, world!"
      signature = original_master.key.sign_message(msg)
      expect(original_master.key.verify_message(signature, msg)).to be true

      recovered_master = described_class.from_mnemonic(mnemonic)
      expect(recovered_master.key.verify_message(signature, msg)).to be true
      expect(recovered_master.seed).to eq(original_master.seed)
    end
  end

  describe ".from_mnemonic" do
    it "recovers the correct keys from test vectors" do
      test_vectors.each do |vector|
        master = described_class.from_mnemonic(vector[:mnemonic])
        expect(master.seed).to eq(vector[:seed])
        expect(master.key.priv).to eq(vector[:private_key])

        # Test hardened derivation
        expect(master.node_for_path("m/0/0").to_base58).to eq(vector[:m_0_0][:private_key])
        expect(master.node_for_path("m/0/0").addr).to eq(vector[:m_0_0][:address])
        expect(master.node_for_path("m/0/0").pub).to eq(vector[:m_0_0][:public_key])

        expect(master.node_for_path("m/0/1").to_base58).to eq(vector[:m_0_1][:private_key])
        expect(master.node_for_path("m/0/1").addr).to eq(vector[:m_0_1][:address])
        expect(master.node_for_path("m/0/1").pub).to eq(vector[:m_0_1][:public_key])

        # Test non-hardened derivation
        expect(master.node_for_path("m/0/0'").to_base58).to eq(vector[:m_0_0_][:private_key])
        expect(master.node_for_path("m/0/0'").addr).to eq(vector[:m_0_0_][:address])
        expect(master.node_for_path("m/0/0'").pub).to eq(vector[:m_0_0_][:public_key])
      end
    end

    it "raises error for invalid mnemonic length" do
      invalid_mnemonic = "abandon " * 23  # 23 words instead of 24
      expect {
        described_class.from_mnemonic(invalid_mnemonic)
      }.to raise_error("Invalid mnemonic length")
    end

    it "raises error for invalid words" do
      invalid_mnemonic = "invalid " * 24  # Invalid words
      expect {
        described_class.from_mnemonic(invalid_mnemonic)
      }.to raise_error(/Invalid word in mnemonic: invalid/)
    end

    it "raises error for invalid checksum" do
      # Modify last word to create invalid checksum
      mnemonic = test_vectors.first[:mnemonic].sub(/blanket$/, 'abandon')
      expect {
        described_class.from_mnemonic(mnemonic)
      }.to raise_error("Invalid checksum")
    end
  end

  describe "from_entropy" do
    it "generates correct mnemonic from entropy" do
      test_vectors.each do |vector|
        master = described_class.from_entropy(vector[:entropy])
        expect(master.mnemonic).to eq(vector[:mnemonic])
        expect(master.seed).to eq(vector[:seed])
        expect(master.key.priv).to eq(vector[:private_key])
      end
    end
  end

  describe "compatibility" do
    it "generates compressed public keys by default" do
      master = described_class.from_mnemonic(test_vectors.first[:mnemonic])
      expect(master.key.compressed).to be true
    end

    it "generates valid bitcoin addresses" do
      master = described_class.from_mnemonic(test_vectors.first[:mnemonic])
      expect(master.key.addr).to match(/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/)
    end

    it "supports passphrase" do
      mnemonic = test_vectors.first[:mnemonic]
      master1 = described_class.from_mnemonic(mnemonic)
      master2 = described_class.from_mnemonic(mnemonic, passphrase: "TREZOR")

      # Different passphrases should produce different seeds
      expect(master2.seed).not_to eq(master1.seed)
      expect(master2.key.priv).not_to eq(master1.key.priv)
    end

    it 'signs and verifies messages' do
      master = described_class.from_mnemonic(test_vectors.first[:mnemonic])
      msg = "Hello, world!"
      signature = master.key.sign_message(msg)
      expect(master.key.verify_message(signature, msg)).to be true
    end
  end

  describe "BIP32/BIP44 derivation" do
    context "additional test vectors" do
      let(:test_vectors) do
        [
          {
            # New test vector with specific derivation path and expected outputs
            mnemonic: "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress blanket",
            path: "m/44'/0'/0'/0/0",
            address: "1Gq9GxfUAenFVBEWthLSCg5cnXpwkcQfcQ",
            public_key: "02453d00e7c1b3098a9851619e4105301e0285f1eea1986e4d1b1b125666a27eff",
            private_key: "L1kkvNK8ciXEQqqokUzPwCBFpnd9eQRJZ5F8HkV6nfmunM35KnyN"
          },
          {
            # New test vector with specific derivation path and expected outputs
            mnemonic: "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress blanket",
            path: "m/44'/0'/0'/0/0'",
            address: "142FbLTYeAH3chiRid2GSgvUbtPNbWU9Xm",
            public_key: "02b7d491281db71308f5ae4e673b3d2b1b7a363654cb68fe378abf3b0b79351327",
            private_key: "Kyd9u7p3we6fLQ2VxThra41XZpewe456JuSwuvobAChbytv1rViF"
          }
        ]
      end

      it "correctly derives keys for specific test vector" do
        test_vectors.each do |vector|
          master = described_class.from_mnemonic(vector[:mnemonic])
          derived_key = master.node_for_path(vector[:path])

          expect(derived_key.addr).to eq(vector[:address])
          expect(derived_key.pub).to eq(vector[:public_key])
          expect(derived_key.to_base58).to eq(vector[:private_key])
        end
      end

      it "verifies signatures with derived keys" do
        vector = test_vectors.last
        master = described_class.from_mnemonic(vector[:mnemonic])
        derived_key = master.node_for_path(vector[:path])

        message = "Test message"
        signature = derived_key.sign_message(message)

        expect(derived_key.verify_message(signature, message)).to be true
      end
    end
  end
end