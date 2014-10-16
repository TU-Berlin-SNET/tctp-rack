require 'openssl'
require 'socket'
require 'radix'

require 'rack/tctp/engine'

# HTTP application layer encryption channel. Used for the Trusted Cloud Transfer Protocol (TCTP)
class Rack::TCTP::HALEC
  # The SSL engine
  attr_reader :engine

  # The URL of this HALEC
  attr_accessor :url

  # The private key for a certificate (if any)
  attr_reader :private_key

  # A server or client certificate (if any)
  attr_reader :certificate

  # The thread for encrypting and decrypting data of this HALEC
  attr_reader :async_thread

  # The queue for encrypting and decrypting data
  # @return [Queue] The async queue
  # @!attr [r] async_queue
  def async_queue
    unless @async_queue
      @async_queue = Queue.new

      @async_thread = Thread.new do
        begin
          while true
            item = @async_queue.pop

            case item[0]
              when :encrypt
                item[2].call encrypt_data(item[1])
              when :decrypt
                item[2].call decrypt_data(item[1])
              when :call
                item[2].call
            end
          end
        rescue Exception => e
          #TODO Handle HALEC encryption thread shutdown
          #TODO Handle OpenSSL error
          unless item[0] == :call
            item[2].call e
          end
        end
      end
    end

    @async_queue
  end

  def initialize(options = {})
    @url = options[:url] || nil
  end

  # Encrypts +plaintext+ data and either returns the encrypted data or calls a block with it.
  # @param [String] plaintext The plaintext
  # @return [String] The encrypted data
  # @yield Gives the encrypted data to the block
  # @yieldparam [String] The encrypted data
  def encrypt_data(plaintext, &encrypted)
    written = @engine.write plaintext

    if written < plaintext.length
      exit -1
    end

    read_data = []

    while(read_chunk = @engine.extract)
      read_data << read_chunk
    end

    if block_given?
      read_data.each do |data|
        encrypted.call data
      end
    else
      read_data.join
    end
  end

  # Encrypts +plaintext+ data asynchronously, yielding data to the block when done.
  # @param [String] plaintext The plaintext
  # @yield Gives the encrypted data to the block
  # @yieldparam [String|Exception] The encrypted data or an exception
  def encrypt_data_async(plaintext, &encrypted)
    async_queue.push [:encrypt, plaintext, encrypted]
  end

  # Decrypts +encrypted+ data and either returns the plaintext or calls a block with it.
  # @param [String] encrypted The encrypted data
  # @return [String] The plaintext
  # @yield Gives the plaintext to the block
  # @yieldparam [String] The plaintext
  def decrypt_data(encrypted, &decrypted)
    injected = @engine.inject encrypted

    unless injected
      exit -1
    end

    read_data = []

    begin
      while(read_chunk = @engine.read)
        read_data << read_chunk
      end
    rescue Exception => e
      unless @engine.state == 'SSLOK '
        raise e
      end
    end

    if block_given? then
      read_data.each do |data|
        decrypted.call data
      end
    else
      read_data.join
    end
  end

  # Decrypts +encrypted+ data asynchronously, yielding data to the block when done.
  # @param [String] encrypted The encrypted data
  # @yield Gives the decrypted data to the block
  # @yieldparam [String|Exception] the decrypted data or an exception
  def decrypt_data_async(encrypted, &decrypted)
    async_queue.push [:decrypt, encrypted, decrypted]
  end

  # Calls a given block asynchronously, considering the order of all calls to async methods.
  def call_async(&block)
    async_queue.push [:call, nil, block]
  end
end

# The Client end of an HALEC
class Rack::TCTP::ClientHALEC < Rack::TCTP::HALEC
  def initialize(options = {})
    super(options)

    @engine = Rack::TCTP::Engine.client
  end
end

# The Server end of an HALEC
class Rack::TCTP::ServerHALEC < Rack::TCTP::HALEC
  def initialize(options = {})
    super(options)

    if(options[:private_key] && options[:certificate])
      @private_key = options[:private_key]
      @certificate = options[:certificate]
    else
      @private_key = self.class.default_key
      @certificate = self.class.default_self_signed_certificate
    end

    @private_key_file = Tempfile.new('rack_tctp_pk')
    @private_key_file.write @private_key.to_s
    @private_key_file.close

    @certificate_file = Tempfile.new('rack_tctp_cert')
    @certificate_file.write @certificate.to_s
    @certificate_file.close

    @engine = Rack::TCTP::Engine.server(@private_key_file.path, @certificate_file.path)
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

    # The slug URI can contain any HTTP compatible characters
    def slug_base
      Radix::Base.new(Radix::BASE::B62 + ['-', '_'])
    end

    # Generate a new random slug (2^64 possibilities)
    def new_slug
      slug_base.convert(rand(2**64), 10)
    end
  end
end