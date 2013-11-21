require 'radix'
require 'ruby-prof'

require_relative 'tctp/halec'

module Rack
  # This middleware enables Rack to make use of the Trusted Cloud Transfer Protocol (TCTP) for HTTP end-to-end
  # body confidentiality and integrity.
  class TCTP
    DEFAULT_TCTP_DISCOVERY_INFORMATION = '/.*:/halecs'
    TCTP_DISCOVERY_MEDIA_TYPE = 'text/prs.tctp-discovery'

    # The slug URI can contain any HTTP compatible characters
    def self.slug_base
      Radix::Base.new(Radix::BASE::B62 + ['-', '_'])
    end

    # Generate a new random slug (2^64 possibilities)
    def self.new_slug
      slug_base.convert(rand(2**64), 10)
    end

    # The TCTP sessions
    attr_reader :sessions

    # Initializes TCTP middleware
    def initialize(app)
      @app = app
      @sessions = {}
    end

    # Middleware call. Supports all TCTP use cases:
    # * TCTP discovery
    # * HALEC creation
    # * HALEC handshake
    # * Decrypting TCTP secured entity-bodies
    # * Encrypting entity-bodies using TCTP
    def call(env)
      begin
        req = Rack::Request.new(env)

        # Switch through TCTP use cases
        case
          when is_tctp_discovery?(req)
            # TCTP discovery
            # TODO Parameterize discovery information
            [200, {"Content-Type" => TCTP_DISCOVERY_MEDIA_TYPE, "Content-Length" => DEFAULT_TCTP_DISCOVERY_INFORMATION.length.to_s}, DEFAULT_TCTP_DISCOVERY_INFORMATION]
          when is_halec_creation?(req)
            # HALEC creation
            halec = ServerHALEC.new(url: '/halecs/' + TCTP::new_slug)

            # TODO Allow creation using predefined cookie
            session = TCTPSession.new

            # Send client_hello to server HALEC and read handshake_response
            client_hello = req.body.read
            halec.socket_there.write(client_hello)
            handshake_response = [halec.socket_there.recv(2048)]

            # Set location header and content-length
            header = {'Location' => halec.url, 'Content-Length' => handshake_response[0].length.to_s}

            # Set the TCTP session cookie header
            Rack::Utils.set_cookie_header!(header, "tctp_session_cookie", {:value => session.session_id, :path => '/', :expires => Time.now+24*60*60})

            # Persist session and HALEC
            session.halecs[halec.url] = halec
            sessions[session.session_id] = session

            [201, header, handshake_response]
          when is_halec_handshake?(req)
            # Get persisted server HALEC
            halec = @sessions[req.cookies['tctp_session_cookie']].halecs[req.path_info]

            # Write handshake message to server HALEC
            halec.socket_there.write(req.body.read)

            # Receive handshake response
            handshake_response = halec.socket_there.recv(2048)

            # Send back server HALEC response
            [200, {'Content-Length' => handshake_response.length.to_s}, [handshake_response]]
          else
            # Decrypt TCTP secured bodies
            if is_tctp_encrypted_body?(req) then
              decrypted_body = StringIO.new

              halec_url = req.body.readline.chomp

              # Gets the HALEC
              halec = @sessions[req.cookies['tctp_session_cookie']].halecs[halec_url]

              halec.socket_there.write(req.body.read)
              decrypted_body.write(halec.ssl_socket.readpartial(2 ** 26 - 1))

              req.body.string = decrypted_body.string
            end

            status, headers, body = @app.call(env)

            if is_tctp_response_requested?(req)
              # Gets the first free server HALEC for encryption
              # TODO Send error if cookie is missing
              halec = @sessions[req.cookies['tctp_session_cookie']].free_halec

              # The length of the content body
              content_body_length = 0

              # The first line
              first_line = halec.url + "\r\n"
              content_body_length += first_line.length

              # Encrypt the body. The first line of the response specifies the used HALEC
              encrypted_body = []
              encrypted_body << first_line

              # Encrypt each body fragment
              body.each do |fragment|
                bodyio = StringIO.new(fragment)

                until bodyio.eof? do
                  chunk = bodyio.read(16 * 1024)
                  halec.ssl_socket.write(chunk)
                  encrypted_chunk = halec.socket_there.readpartial(32 * 1024)
                  encrypted_body << encrypted_chunk
                  content_body_length += encrypted_chunk.length
                end
              end

              # Sets the content length and encoding
              headers['Content-Length'] = content_body_length.to_s
              headers['Content-Encoding'] = 'encrypted'

              [status, headers, encrypted_body]
            else
              [status, headers, body]
            end
        end
      rescue Exception => e
        puts e
      end
    end

    private
      def is_tctp_discovery?(req)
        req.options? && !req.env['HTTP_ACCEPT'].nil? && req.env['HTTP_ACCEPT'].eql?(TCTP_DISCOVERY_MEDIA_TYPE)
      end

      def is_halec_creation?(req)
        req.post? && req.path_info.eql?('/halecs')
      end

      def is_halec_handshake?(req)
        req.post? &&
            !req.cookies.nil? &&
            req.cookies.has_key?('tctp_session_cookie') &&
            sessions.has_key?(req.cookies['tctp_session_cookie']) &&
            sessions[req.cookies['tctp_session_cookie']].halecs.has_key?(req.path_info)
      end

      def is_tctp_response_requested? (req)
        req.env['HTTP_ACCEPT_ENCODING'].eql?('encrypted')
      end

      def is_tctp_encrypted_body? (req)
        req.env['HTTP_CONTENT_ENCODING'].eql?('encrypted')
      end
  end

  class TCTPSession
    attr_reader :session_id

    attr_reader :halecs

    def initialize(session_id = TCTP::new_slug)
      @session_id = session_id
      @halecs = {}
    end

    def free_halec
      # TODO free HALEC handling
      @halecs.first[1]
    end
  end
end