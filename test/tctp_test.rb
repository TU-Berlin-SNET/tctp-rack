require 'test/unit'
require 'rack/test'
require 'rack-tctp'
require 'faker'

TCTP_APP = Rack::Builder.app do
  use Rack::TCTP
  run Proc.new { |env|
    [200, {'Content-Type' => 'text/plain'}, [env['REQUEST_METHOD'].eql?('GET') ? 'OK' : env['rack.input'].string]]
  }
end

# This test class demonstrates TCTP functionality by testing the TCTP middleware
class TCTPTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    TCTP_APP
  end

  # Tests the discovery, i.e., that TCTP discovery information are sent after they are requested by an HTTP OPTIONS
  # request
  def test_discovery
    options '*', {}, {'HTTP_ACCEPT' => Rack::TCTP::TCTP_DISCOVERY_MEDIA_TYPE}
    assert last_response.ok?
    assert_equal last_response.body, Rack::TCTP::DEFAULT_TCTP_DISCOVERY_INFORMATION
  end

  # Tests the whole TCTP encryption:
  # * Creating an HALEC
  # * Performing a TCTP handshake
  # * Posting encrypted data
  # * Receiving encrypted data
  def test_tctp_encryption
    client_halec = Rack::TCTP::ClientHALEC.new()

    # Receive the TLS client_hello
    client_halec.engine.read
    client_hello = client_halec.engine.extract

    # Post the client_hello to the HALEC creation URI, starting the handshake
    post '/halecs', {}, {input: client_hello}

    assert last_response.successful?

    # The HALEC URL is returned as Location header
    halec_url = last_response.headers['Location']

    # Feed the handshake response (server_hello, certificate, etc.) from the entity-body to the client HALEC
    client_halec.engine.inject(last_response.body)

    # Read the TLS client response (client_key_exchange, change_cipher_spec, finished)
    client_halec.engine.read
    client_response = client_halec.engine.extract

    # Post the TLS client response to the HALEC url
    post halec_url, {}, {input: client_response}

    # Feed the handshake response (change_cipher_spec, finished) to the client HALEC
    client_halec.engine.inject last_response.body

    # The handshake is now complete!

    # Mock Accept-Encoding 'encrypted'
    Rack::MockRequest::DEFAULT_ENV['HTTP_ACCEPT_ENCODING'] = 'encrypted'
    get '/', {}
    Rack::MockRequest::DEFAULT_ENV.delete 'HTTP_ACCEPT_ENCODING'

    # The TCTP encrypted HTTP entity-body
    body_stream = StringIO.new(last_response.body)

    # Read first line (the Halec URL ... we know it already)
    url = body_stream.readline

    # Write the rest of the stream to the client HALEC
    client_halec.engine.inject body_stream.read

    # Read the decrypted body
    decrypted_body = client_halec.engine.read

    puts decrypted_body

    # Creates a POST body
    post_body = StringIO.new
    post_body.set_encoding('BINARY')
    post_body.write("#{halec_url}\n")

    # Creates the lorem to be posted
    lorem_ipsum = Faker::Lorem.paragraphs.join("\n")

    # Encrypts lorem_ipsum
    client_halec.engine.write lorem_ipsum
    encrypted_lorem = client_halec.engine.extract
    post_body.write(encrypted_lorem)

    # Rewind the StringIO as it is passed as-is to the TCTP middleware and otherwise reading would result in EOF
    post_body.rewind

    # Mock Accept-Encoding 'encrypted'
    Rack::MockRequest::DEFAULT_ENV['HTTP_ACCEPT_ENCODING'] = 'encrypted'
    Rack::MockRequest::DEFAULT_ENV['HTTP_CONTENT_ENCODING'] = 'encrypted'
    post '/', {}, {:input => post_body}
    Rack::MockRequest::DEFAULT_ENV.delete 'HTTP_ACCEPT_ENCODING'
    Rack::MockRequest::DEFAULT_ENV.delete 'HTTP_CONTENT_ENCODING'

    # Create a stream from the response body
    body_stream = StringIO.new(last_response.body)

    # Read first line (the Halec URL ... we know it already)
    url = body_stream.readline

    # Write the rest of the stream to the client HALEC
    client_halec.engine.inject body_stream.read

    # Read the decrypted body
    decrypted_body = client_halec.engine.read

    # Compares the response
    assert_equal lorem_ipsum, decrypted_body

    # Thats it, we've successfully posted an encrypted TCTP body and received and decrypted a TCTP-secured entity-body

    # And it was the same.

    # How cool is that?
  end
end