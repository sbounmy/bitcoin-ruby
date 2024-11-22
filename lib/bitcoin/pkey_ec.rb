module Bitcoin
  class PKeyEC

    CURVE = 'secp256k1'

    attr_reader :private_key, :group

    attr_accessor :public_key, :private_key

    def private_key_hex; private_key.to_hex.rjust(64, '0'); end
    def public_key_hex;  public_key.to_hex.rjust(130, '0'); end

    def initialize
      @group = OpenSSL::PKey::EC::Group.new(CURVE)
    end

    def self.generate_key
      OpenSSL::PKey::EC.generate(CURVE)
    end

    def private_key
      @public_key = restore_public_key(@private_key)

      private_key_bn   = OpenSSL::BN.new(@private_key, 16)
      public_key_bn    = OpenSSL::BN.new(@public_key, 16)
      public_key_point = OpenSSL::PKey::EC::Point.new(@group, public_key_bn)

      asn1 = OpenSSL::ASN1::Sequence(
        [
          OpenSSL::ASN1::Integer.new(1),
          OpenSSL::ASN1::OctetString(private_key_bn.to_s(2)),
          OpenSSL::ASN1::ObjectId(CURVE, 0, :EXPLICIT),
          OpenSSL::ASN1::BitString(public_key_point.to_octet_string(:uncompressed), 1, :EXPLICIT)
        ]
      )

      OpenSSL::PKey::EC.new(asn1.to_der).private_key
    end

    def public_key
      return nil unless @private_key
      @public_key = restore_public_key(@private_key)
      public_key_bn    = OpenSSL::BN.new(@public_key, 16)
      public_key_point = OpenSSL::PKey::EC::Point.new(@group, public_key_bn)

      asn1 = OpenSSL::ASN1::Sequence.new(
        [
          OpenSSL::ASN1::Sequence.new([
                                        OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'),
                                        OpenSSL::ASN1::ObjectId.new(@group.curve_name)
                                      ]),
          OpenSSL::ASN1::BitString.new(public_key_point.to_octet_string(:uncompressed))
        ]
      )
      OpenSSL::PKey::EC.new(asn1.to_der).public_key
    end

    private

    def restore_public_key(private_key)
      private_bn = OpenSSL::BN.new private_key, 16
      group = OpenSSL::PKey::EC::Group.new CURVE
      public_bn = group.generator.mul(private_bn).to_bn
      public_bn = OpenSSL::PKey::EC::Point.new(group, public_bn).to_bn

      public_bn.to_s(16).downcase
    end
  end
end