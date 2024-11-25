# Implementation of BIP39 HD wallet functionality
# @see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
#
# The correct flow is:
# Entropy -> Mnemonic -> Seed -> Private Key -> Public Key
# Note: It's NOT possible to go from Private Key -> Mnemonic
module Bitcoin
  # Master class handles BIP39 mnemonic generation and HD wallet creation
  class Master
    # @return [String] hex-encoded seed used for key generation
    attr_reader :seed

    # @return [String] space-separated 24-word mnemonic phrase
    attr_reader :mnemonic

    # @return [Bitcoin::Key] the generated Bitcoin key
    attr_reader :key

    # Number of rounds for PBKDF2
    PBKDF2_ROUNDS = 2048

    # Size of seed in bytes (512 bits)
    SEED_BYTES = 64

    # Size of entropy in bytes (256 bits)
    ENTROPY_BYTES = 32

    # BIP39 English wordlist containing exactly 2048 words
    # @raise [RuntimeError] if wordlist is invalid
    WORDLIST = File.read(File.join(File.dirname(__FILE__), 'wordlist', 'english.txt')).split("\n")
    raise "Invalid wordlist" unless WORDLIST.length == 2048

    # Initialize a new master node
    # @param private_key [String] hex-encoded private key
    # @param mnemonic [String] space-separated 24-word mnemonic
    # @param seed [String] hex-encoded seed
    # @param entropy [String] hex-encoded entropy
    def initialize(private_key, mnemonic:, seed:, entropy:)
      @key = Bitcoin::Key.new(private_key, nil, compressed: true)
      @mnemonic = mnemonic
      @seed = seed
      @entropy = entropy
    end

    # Generate a new random HD wallet
    # @return [Master] new master node with random mnemonic
    def self.generate
      entropy_bytes = SecureRandom.random_bytes(ENTROPY_BYTES)
      entropy = entropy_bytes.unpack('H*')[0]

      # Validate entropy length
      raise "Invalid entropy length" unless entropy.length == ENTROPY_BYTES * 2

      mnemonic = entropy_to_mnemonic(entropy)
      from_mnemonic(mnemonic)
    end

    # Create master node from existing mnemonic
    # @param mnemonic [String] space-separated 24-word mnemonic
    # @param passphrase [String] optional passphrase for extra security
    # @return [Master] master node restored from mnemonic
    # @raise [RuntimeError] if mnemonic is invalid
    def self.from_mnemonic(mnemonic, passphrase: "")
      entropy = mnemonic_to_entropy(mnemonic)
      create_master_node(mnemonic: mnemonic, entropy: entropy, passphrase: passphrase)
    end

    def self.from_entropy(entropy)
      # Validate entropy input
      raise "Invalid entropy length" unless entropy.length == ENTROPY_BYTES * 2
      raise "Invalid entropy format" unless entropy =~ /\A[0-9a-f]{#{ENTROPY_BYTES * 2}}\z/i

      # Generate mnemonic
      mnemonic = entropy_to_mnemonic(entropy)

      # Create master node
      create_master_node(mnemonic: mnemonic, entropy: entropy)
    end

    # Get the BIP39 wordlist
    # @return [Array<String>] array of 2048 words
    def self.word_list
      @words ||= File.read(File.join(File.dirname(__FILE__), 'wordlist', 'english.txt')).split("\n")
    end

    private

    # Convert mnemonic phrase back to entropy
    # @param mnemonic [String] space-separated 24-word mnemonic
    # @return [String] hex-encoded entropy
    # @raise [RuntimeError] if mnemonic is invalid
    def self.mnemonic_to_entropy(mnemonic)
      words = mnemonic.split(' ')
      raise "Invalid mnemonic length" unless words.length == 24

      bits = words.map do |word|
        index = word_list.index(word)
        raise "Invalid word in mnemonic: #{word}" unless index
        index.to_s(2).rjust(11, '0')
      end.join

      entropy_bits = bits[0...-8]    # First 256 bits
      checksum_bits = bits[-8..]     # Last 8 bits

      entropy_bytes = [entropy_bits].pack('B*')
      expected_checksum = Digest::SHA256.digest(entropy_bytes).unpack('B*')[0][0...8]
      raise "Invalid checksum" unless checksum_bits == expected_checksum

      entropy_bytes.unpack('H*')[0]
    end

    # Convert entropy to mnemonic phrase
    # @param entropy [String] hex-encoded entropy
    # @return [String] space-separated 24-word mnemonic
    def self.entropy_to_mnemonic(entropy)
      # Validate entropy input
      raise "Invalid entropy length" unless entropy.length == ENTROPY_BYTES * 2
      raise "Invalid entropy format" unless entropy =~ /\A[0-9a-f]{#{ENTROPY_BYTES * 2}}\z/i

      entropy_bits = [entropy].pack('H*').unpack('B*')[0]
      checksum = Digest::SHA256.digest([entropy].pack('H*')).unpack('B*')[0][0...8]
      combined_bits = entropy_bits + checksum

      words = combined_bits.scan(/.{11}/).map do |bits|
        WORDLIST[bits.to_i(2)]
      end

      words.join(' ')
    end

    # Validate mnemonic format and words
    # @param mnemonic [String] space-separated 24-word mnemonic
    # @raise [RuntimeError] if mnemonic is invalid
    def self.validate_mnemonic!(mnemonic)
      words = mnemonic.split(' ')
      raise "Invalid mnemonic length" unless words.length == 24

      words.each do |word|
        raise "Invalid word in mnemonic: #{word}" unless WORDLIST.include?(word)
      end
    end

    # Create master node with seed and key generation
    # @param mnemonic [String] space-separated 24-word mnemonic
    # @param entropy [String] hex-encoded entropy
    # @param passphrase [String] optional passphrase (default: "")
    # @return [Master] new master node
    def self.create_master_node(mnemonic:, entropy:, passphrase: "")
      # Generate seed
      salt = "mnemonic" + passphrase
      seed = OpenSSL::PKCS5.pbkdf2_hmac(
        mnemonic,
        salt,
        PBKDF2_ROUNDS,
        SEED_BYTES,
        OpenSSL::Digest::SHA512.new
      ).unpack('H*')[0]

      # Generate master key
      hmac = OpenSSL::HMAC.digest(
        OpenSSL::Digest::SHA512.new,
        "Bitcoin seed",
        [seed].pack('H*')
      )
      private_key = hmac[0...32].unpack('H*')[0]

      new(private_key, mnemonic: mnemonic, seed: seed, entropy: entropy)
    end
  end
end