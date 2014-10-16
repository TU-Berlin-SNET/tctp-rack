require 'radix'
require 'logger'

require_relative 'tctp/halec'

module Rack
  # This middleware enables Rack to make use of the Trusted Cloud Transfer Protocol (TCTP) for HTTP end-to-end
  # body confidentiality and integrity.
  class TCTP
    DEFAULT_TCTP_DISCOVERY_INFORMATION = '/.*:/halecs'
    TCTP_DISCOVERY_MEDIA_TYPE = 'text/prs.tctp-discovery'
    TCTP_MEDIA_TYPE = 'binary/prs.tctp'

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
    def initialize(app, logger = nil)
      unless logger
        @logger = ::Logger.new(STDOUT)
        @logger.level = ::Logger::FATAL
      else
        @logger = logger
      end

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
      status, headers, body = nil, nil, nil

      begin
        req = Rack::Request.new(env)

        case
          when is_tctp_discovery?(req)
            # TCTP discovery
            # TODO Parameterize discovery information
            [200, {"Content-Type" => TCTP_DISCOVERY_MEDIA_TYPE, "Content-Length" => DEFAULT_TCTP_DISCOVERY_INFORMATION.length.to_s}, [DEFAULT_TCTP_DISCOVERY_INFORMATION]]
          when is_halec_creation?(req)
            # HALEC creation
            halec = ServerHALEC.new(url: halec_uri(req.env, "/halecs/#{TCTP::new_slug}"))

            session = sessions[req.cookies['tctp_session_cookie']] || TCTPSession.new

            # Send client_hello to server HALEC and read handshake_response
            client_hello = req.body.read
            halec.engine.inject client_hello
            halec.engine.read
            handshake_response = [halec.engine.extract]

            # Set location header and content-length
            header = {
                'Location' => halec.url.to_s,
                'Content-Length' => handshake_response[0].length.to_s,
                'Content-Type' => TCTP_MEDIA_TYPE
            }

            # Set the TCTP session cookie header
            Rack::Utils.set_cookie_header!(header, "tctp_session_cookie", {:value => session.session_id, :path => '/', :expires => Time.now+24*60*60})

            # Persist session and HALEC
            session.push_halec(halec)
            sessions[session.session_id] = session

            [201, header, handshake_response]
          when is_halec_handshake?(req)
            # Get persisted server HALEC
            halec = @sessions[req.cookies['tctp_session_cookie']].halecs[halec_uri(req.env, req.path_info)]

            # Write handshake message to server HALEC
            halec.engine.inject req.body.read

            # Receive handshake response
            halec.engine.read
            handshake_response = halec.engine.extract

            # Send back server HALEC response
            [200, {
                'Content-Length' => handshake_response.length.to_s,
                'Content-Type' => TCTP_MEDIA_TYPE
            }, [handshake_response]]
          else
            # Decrypt TCTP secured bodies
            if is_tctp_encrypted_body?(req) then
              decrypted_body = StringIO.new

              halec_url = req.body.gets.chomp

              # Gets the HALEC
              halec = @sessions[req.cookies['tctp_session_cookie']].halecs[URI(halec_url)]

              read_body = req.body.read

              begin
                decrypted_body.write halec.decrypt_data(read_body)
              rescue Exception => e
                error(e.message + e.backtrace.join("<br/>\n"))
              end

              decrypted_body.rewind

              env['rack.input'] = decrypted_body
            end

            status, headers, body = @app.call(env)

            if is_tctp_response_requested?(req) && status >= 200 && ![204, 205, 304].include?(status)
              # Gets the first free server HALEC for encryption
              # TODO Send error if cookie is missing
              session = @sessions[req.cookies['tctp_session_cookie']]

              unless session
                return no_usable_halec_error
              end

              halec = session.pop_halec

              unless halec
                return no_usable_halec_error
              end

              # The length of the content body
              content_body_length = 0

              # The first line
              first_line = halec.url.to_s + "\r\n"
              content_body_length += first_line.length

              # Encrypt the body. The first line of the response specifies the used HALEC
              encrypted_body = []
              encrypted_body << first_line

              # Encrypt each body fragment
              body.each do |fragment|
                encrypted_fragment = halec.encrypt_data fragment
                encrypted_body << encrypted_fragment
                content_body_length += encrypted_fragment.length
              end

              encrypted_body.define_singleton_method :close do
                session.push_halec halec

                super() if self.class.superclass.respond_to? :close
              end

              # Finding this bug took waaaay too long ...
              body.close if body.respond_to?(:close)

              # Sets the content length and encoding
              headers['Content-Length'] = content_body_length.to_s
              headers['Content-Encoding'] = 'encrypted'

              [status, headers, encrypted_body]
            else
              [status, headers, body]
            end
        end
      rescue Exception => e
        # TODO Handle SSL Error
        @logger.fatal e

        error "Error in TCTP middleware. #{e} #{e.backtrace.inspect}"
      end
    end

    private
      def log_key
        'TCTP Middleware'
      end

      def no_usable_halec_error
        error 'No useable HALEC for encryption. Please perform Handshake.'
      end

      def error(message)
        [500, {'Content-Type' => 'text/plain', 'Content-Length' => message.length.to_s}, [message]]
      end

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
            sessions[req.cookies['tctp_session_cookie']].halecs.has_key?(halec_uri(req.env, req.path_info))
      end

      def is_tctp_response_requested? (req)
        req.env['HTTP_ACCEPT_ENCODING'].eql?('encrypted')
      end

      def is_tctp_encrypted_body? (req)
        req.env['HTTP_CONTENT_ENCODING'].eql?('encrypted')
      end

      # Builds an URI object to be used as a HALEC +uri+
      # @param [Hash] env A Rack environment hash
      # @param [String] path A path
      # @return [URI] An HALEC +uri+
      def halec_uri(env, path)
        if(env['HTTP_HOST'])
          URI("#{env['rack.url_scheme']}://#{env['HTTP_HOST']}#{path}")
        else
          URI("#{env['rack.url_scheme']}://#{env['SERVER_NAME']}:#{env['SERVER_PORT']}#{path}")
        end
      end
  end

  class TCTPSession
    attr_reader :session_id

    attr_reader :halecs

    attr_reader :halecs_mutex

    def initialize(session_id = TCTP::new_slug)
      @session_id = session_id
      @halecs = {}
      @halecs_mutex = Mutex.new
    end

    def pop_halec
      free_halec = nil

      @halecs_mutex.synchronize do
        free_halec = @halecs.first {|url, halec| halec.engine.state.eql? 'SSLOK '}

        @halecs.delete free_halec[0] if free_halec
      end
      return free_halec[1]
    end

    def push_halec(halec)
      @halecs_mutex.synchronize do
        @halecs[halec.url] = halec
      end
    end
  end
end