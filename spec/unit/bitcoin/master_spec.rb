require 'spec_helper'

describe Bitcoin::Master do
  let(:test_vectors) do
    [
      {
        # Test vector from BIP39 spec
        entropy: "00000401003008014030070100240500b0180340700f020044090130280540b0",
        mnemonic: "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress blanket",
        seed: "4b94d8ad0b6f4cf1715522411695201584beb2a77d3d0ad4a6b9e143c084eb2f04d76633623d8bdd770faee336a11faee5ad055b09961e256d89ac723ac203a3",
        private_key: "5c4ffc8f27cec820e6d58fb37438b04543bebb388c282c7135ed30c8c27722d4"
      },
      {
        entropy: "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262",
        mnemonic: "trumpet delay fury misery march there unit enough journey book tiny trigger farm another science regular busy album fly weapon crisp face sister edit",
        seed: "473103ac1e8c51f4dcd2b1102717e434f7b9b339b332da7de55d2313d2fa1584965367b7e0cd8c4542c033f7f1af50087aa804019be0e87a8531ceceff9715d1",
        private_key: "dbb4cf97a2e1b651e4efb22e282675e7fff84c63435f93722f029958efb1068d"
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
      expect(recovered_master.key.priv).to eq(original_master.key.priv)
    end
  end

  describe ".from_mnemonic" do
    it "recovers the correct keys from test vectors" do
      test_vectors.each do |vector|
        master = described_class.from_mnemonic(vector[:mnemonic])
        expect(master.seed).to eq(vector[:seed])
        expect(master.key.priv).to eq(vector[:private_key])
        expect(master.mnemonic).to eq(vector[:mnemonic])
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

  describe "entropy conversion" do
    it "generates correct mnemonic from entropy" do
      test_vectors.each do |vector|
        mnemonic = described_class.send(:entropy_to_mnemonic, vector[:entropy])
        expect(mnemonic).to eq(vector[:mnemonic])
      end
    end

    it "preserves entropy through mnemonic conversion" do
      vector = test_vectors.first

      # Convert entropy to mnemonic
      mnemonic = described_class.send(:entropy_to_mnemonic, vector[:entropy])

      # Create master node from mnemonic
      master = described_class.from_mnemonic(mnemonic)

      # Should match test vector
      expect(master.key.priv).to eq(vector[:private_key])
      expect(master.seed).to eq(vector[:seed])
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
end