Rack TCTP middleware
====================

This gem contains Rack middleware for enabling end-to-end security using the Trusted Cloud Transfer Protocol (TCTP).

What is the Trusted Cloud Transfer Protocol (TCTP)?
---------------------------------------------------

TCTP is an approach to end-to-end encryption, where HTTP bodies are encrypted using TLS before sending them over HTTPS.

This enables you to trust the cloud again, as the body encryption happens within the application. This is in contrast to
regular HTTPS traffic, which is normally handled by the provider infrastructure.

How to use
----------

Add 'rack-tctp' to your Gemfile and add the following to your config.ru:

    require 'rack-tctp'

    use Rack::TCTP

How does the middleware work?
-----------------------------

Currently, the best way to understand it, is to look at the fully documented test/tctp_test.rb file, which details the
middleware functionality.

Who's behind the Trusted Cloud Transfer Protocol (TCTP)?
--------------------------------------------------------

TCTP was devised and implemented by Mathias Slawik of Service-centric Networking, a chair of TU Berlin and Deutsche
Telekom Laboratories. It was funded within the TRESOR research project of the Trusted Cloud project by the Federal
Ministry of Economy on the basis of a resolution passed by the German Bundestag.