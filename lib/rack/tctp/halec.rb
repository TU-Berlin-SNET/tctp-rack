require 'openssl'
require 'socket'

# HTTP application layer encryption channel. Used for the Trusted Cloud Transfer Protocol (TCTP)
class HALEC
  # The URL of this HALEC
  attr_reader :url

  # The plaintext socket
  attr_reader :socket_here

  # The SSL socket
  attr_reader :ssl_socket

  # The encrypted socket
  attr_reader :socket_there

  # The private key for a certificate (if any)
  attr_reader :private_key

  # A server or client certificate (if any)
  attr_reader :certificate

  # The TLS context
  attr_reader :ctx

  def initialize(options = {})
    @url = options[:url] || ''
    @ctx = options[:ssl_context] || OpenSSL::SSL::SSLContext.new()

    @ctx.ssl_version = :TLSv1

    @socket_here, @socket_there = socket_pair
    [@socket_here, @socket_there].each do |socket|
      socket.set_encoding(Encoding::BINARY)
    end
  end

  private
    def socket_pair
      Socket.pair(:UNIX, :STREAM, 0) # Linux
    rescue Errno::EAFNOSUPPORT
      Socket.pair(:INET, :STREAM, 0) # Windows
    end
end

# The Client end of an HALEC
class ClientHALEC < HALEC
  def initialize(options = {})
    super(options)

    @ssl_socket = OpenSSL::SSL::SSLSocket.new(@socket_here, @ctx)
  end
end

# The Server end of an HALEC
class ServerHALEC < HALEC
  def initialize(options = {})
    super(options)

    if(options[:private_key] && options[:certificate])
      @private_key = options[:private_key]
      @certificate = options[:certificate]
    else
      @private_key = ServerHALEC.default_key
      @certificate = ServerHALEC.default_self_signed_certificate
    end

    @ctx.cert = @certificate
    @ctx.key = @private_key

    @ssl_socket = OpenSSL::SSL::SSLSocket.new(@socket_here, @ctx)
    Thread.new {
      begin
        s = @ssl_socket.accept
      rescue Exception => e
        puts e
      end
    }
  end

  class << self
    @default_key
    @default_self_signed_certificate

    def initialize
      default_key
      default_self_signed_certificate

      self
    end

    def default_key
      @default_key ||= OpenSSL::PKey::RSA.new 2048
    end

    def default_self_signed_certificate
      @default_self_signed_certificate ||= generate_self_signed_certificate
    end

    def generate_self_signed_certificate
      name = OpenSSL::X509::Name.parse 'CN=tctp-server/DC=tctp'

      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 0
      cert.not_before = Time.now
      cert.not_after = Time.now + 3600

      cert.public_key = @default_key.public_key
      cert.subject = name

      cert
    end
  end
end
