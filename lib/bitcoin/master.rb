module Bitcoin
  class Master
    attr_reader :seed, :mnemonic, :key

    PBKDF2_ROUNDS = 2048
    SEED_BYTES = 64    # 512 bits
    ENTROPY_BYTES = 32 # 256 bits

    # Load BIP39 wordlist
    WORDLIST = File.read(File.join(File.dirname(__FILE__), 'wordlist', 'english.txt')).split("\n")
    raise "Invalid wordlist" unless WORDLIST.length == 2048


    def initialize(private_key, mnemonic:, seed:, entropy:)
      @key = Bitcoin::Key.new(private_key, nil, compressed: true)
      @mnemonic = mnemonic
      @seed = seed
      @entropy = entropy
    end

    def self.generate
      # Generate random entropy (32 bytes = 256 bits)
      entropy = SecureRandom.hex(ENTROPY_BYTES)

      # Generate mnemonic from entropy
      mnemonic = entropy_to_mnemonic(entropy)

      # Create master node from mnemonic
      from_mnemonic(mnemonic)
    end

    def self.from_mnemonic(mnemonic, passphrase: "")
      # 1. Get entropy (with validation)
      entropy = mnemonic_to_entropy(mnemonic)

      # 2. Generate seed
      salt = "mnemonic" + passphrase
      seed = OpenSSL::PKCS5.pbkdf2_hmac(
        mnemonic,
        salt,
        2048,
        64,
        OpenSSL::Digest::SHA512.new
      ).unpack('H*')[0]

      # 3. Generate private key
      hmac = OpenSSL::HMAC.digest(
        OpenSSL::Digest::SHA512.new,
        "Bitcoin seed",
        [seed].pack('H*')
      )
      private_key = hmac[0...32].unpack('H*')[0]

      # 4. Create Master key
      new(private_key, mnemonic:, seed:, entropy:)
    end

    def self.word_list
      @words ||= File.read(File.join(File.dirname(__FILE__), 'wordlist', 'english.txt')).split("\n")
    end

    private

    def self.mnemonic_to_entropy(mnemonic)
      # 1. Split into words and validate length
      words = mnemonic.split(' ')
      raise "Invalid mnemonic length" unless words.length == 24

      # 2. Convert words to bits, validating each word
      bits = words.map do |word|
        index = word_list.index(word)
        raise "Invalid word in mnemonic: #{word}" unless index
        index.to_s(2).rjust(11, '0')
      end.join

      # 3. Split entropy and checksum
      entropy_bits = bits[0...-8]    # First 256 bits
      checksum_bits = bits[-8..]     # Last 8 bits

      # 4. Validate checksum
      entropy_bytes = [entropy_bits].pack('B*')
      expected_checksum = Digest::SHA256.digest(entropy_bytes).unpack('B*')[0][0...8]
      raise "Invalid checksum" unless checksum_bits == expected_checksum

      # 5. Convert entropy bits to hex
      entropy_bytes.unpack('H*')[0]
    end

    def self.entropy_to_mnemonic(entropy)
      # Convert entropy to bits and add checksum
      entropy_bits = [entropy].pack('H*').unpack('B*')[0]
      checksum = Digest::SHA256.digest([entropy].pack('H*')).unpack('B*')[0][0...8]
      combined_bits = entropy_bits + checksum

      # Convert to words
      words = combined_bits.scan(/.{11}/).map do |bits|
        WORDLIST[bits.to_i(2)]  # Now using WORDLIST from Master class
      end

      words.join(' ')
    end

    def self.validate_mnemonic!(mnemonic)
      words = mnemonic.split(' ')
      raise "Invalid mnemonic length" unless words.length == 24

      words.each do |word|
        raise "Invalid word in mnemonic: #{word}" unless WORDLIST.include?(word)
      end

      # ... rest of validation ...
    end

    # ... rest of private methods ...
  end
end